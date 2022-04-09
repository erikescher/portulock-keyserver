/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::fmt::Debug;

use async_trait::async_trait;
use sequoia_openpgp::cert::amalgamation::UserIDAmalgamation;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::{Cert, Fingerprint};
use shared::filtering::applier::KeyFilterApplier;
use shared::filtering::filters::{KeyFilterUIDsMatchingEmails, KeyFilterUIDsMatchingNames};

use crate::db_new::DBWrapper;
use crate::key_storage::openpgp_ca_lib::OpenPGPCALib;

pub mod multi_keystore;
pub mod openpgp_ca_lib;

#[tracing::instrument]
pub async fn filter_cert_by_approved_uids(submitter_db: &DBWrapper<'_>, cert: Cert) -> Result<Cert, anyhow::Error> {
    let approved_names = submitter_db.get_approved_names(&cert.fingerprint()).await?;
    let approved_emails = submitter_db.get_approved_emails(&cert.fingerprint()).await?;
    println!(
        "Filtering Cert by approved UIDs: names={:?} emails={:?}",
        approved_names, approved_emails
    );
    let approved_cert: Cert = KeyFilterApplier::from(cert.clone())
        .apply(KeyFilterUIDsMatchingNames::new(approved_names))
        .apply(KeyFilterUIDsMatchingEmails::new(approved_emails))
        .into();
    Ok(approved_cert)
}

#[tracing::instrument]
pub async fn certify_and_publish_approved_cert(
    keystore: &(impl KeyStore + ?Sized),
    approved_cert: Cert,
) -> Result<(), anyhow::Error> {
    println!("Certifying and Publishing approved cert: {}", approved_cert);
    let result = keystore.store(&approved_cert).await;
    result
}

#[async_trait]
pub trait KeyStore: Debug + Send + Sync {
    async fn store(&self, cert: &Cert) -> Result<(), anyhow::Error>;
    async fn list_by_email(&self, email: &str) -> Result<Vec<Cert>, anyhow::Error>;
    async fn get_by_fpr(&self, fpr: &Fingerprint) -> Result<Option<Cert>, anyhow::Error>;
    async fn stop_recertification(&self, fpr: &Fingerprint) -> Result<(), anyhow::Error>;
    async fn delete(&self, fpr: &Fingerprint) -> Result<(), anyhow::Error>;
    fn can_store_revocations_without_publishing(&self) -> bool;
    async fn store_revocations_without_publishing(
        &self,
        cert: &Cert,
        revocations: Vec<Signature>,
    ) -> Result<(), anyhow::Error>;
    async fn get_stored_revocations(&self, fpr: &Fingerprint) -> Result<Vec<Signature>, anyhow::Error>;
}

#[async_trait]
pub trait LookupSource {
    async fn by_fpr(&self, fpr: &Fingerprint) -> Result<Option<Cert>, anyhow::Error>;
    async fn by_email(&self, email: &str) -> Result<Vec<Cert>, anyhow::Error>;
}

#[async_trait]
impl LookupSource for OpenPGPCALib {
    async fn by_fpr(&self, fpr: &Fingerprint) -> Result<Option<Cert>, anyhow::Error> {
        self.get_by_fpr(fpr).await
    }

    async fn by_email(&self, email: &str) -> Result<Vec<Cert>, anyhow::Error> {
        self.list_by_email(email).await
    }
}

pub fn emails_from_cert(cert: &Cert) -> Vec<String> {
    cert.userids()
        .into_iter()
        .filter_map(|uida: UserIDAmalgamation| uida.email_normalized().unwrap_or(None))
        .collect()
}
