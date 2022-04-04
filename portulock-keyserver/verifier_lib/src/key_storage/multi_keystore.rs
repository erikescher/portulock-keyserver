/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;

use anyhow::anyhow;
use async_trait::async_trait;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::{Cert, Fingerprint};
use shared::types::Email;
use shared::utils::merge_certs;

use crate::certs::CertWithSingleUID;
use crate::key_storage::openpgp_ca_lib::OpenPGPCALib;
use crate::key_storage::KeyStore;

#[derive(Clone, Debug)]
pub struct MultiOpenPGPCALib {
    keystores: HashMap<String, OpenPGPCALib>,
}

impl MultiOpenPGPCALib {
    pub fn new(keystores: HashMap<String, OpenPGPCALib>) -> Self {
        Self { keystores }
    }

    #[tracing::instrument]
    fn get_keystore_for_domain(&self, domain: &str) -> Result<&OpenPGPCALib, anyhow::Error> {
        self.keystores
            .get(domain)
            .ok_or_else(|| anyhow!("No keystore found for this domain!"))
    }

    #[tracing::instrument]
    fn get_all_keystores(&self) -> Vec<&OpenPGPCALib> {
        self.keystores.values().collect()
    }

    #[tracing::instrument]
    pub fn perform_maintenance(&self) -> Result<(), anyhow::Error> {
        for keystore in self.get_all_keystores() {
            keystore.perform_maintenance()?;
        }
        Ok(())
    }
}

#[async_trait]
impl KeyStore for &MultiOpenPGPCALib {
    #[tracing::instrument]
    async fn store(&self, cert: &Cert) -> Result<(), anyhow::Error> {
        for (domain, cert) in split_cert_by_domain(cert) {
            self.get_keystore_for_domain(domain.as_str())?.store(&cert).await?;
        }
        Ok(())
    }

    #[tracing::instrument]
    async fn list_by_email(&self, email: &str) -> Result<Vec<Cert>, anyhow::Error> {
        let parsed_email = Email::parse(email)?;
        let keystore = self.get_keystore_for_domain(parsed_email.get_domain())?;

        keystore.list_by_email(email).await
    }

    #[tracing::instrument]
    async fn get_by_fpr(&self, fpr: &Fingerprint) -> Result<Option<Cert>, anyhow::Error> {
        let mut certs = vec![];
        for keystore in self.get_all_keystores() {
            match keystore.get_by_fpr(fpr).await? {
                None => {}
                Some(c) => certs.push(c),
            }
        }
        let certs = merge_certs(certs);
        Ok(certs.first().cloned())
    }

    #[tracing::instrument]
    async fn stop_recertification(&self, fpr: &Fingerprint) -> Result<(), anyhow::Error> {
        let mut at_least_one_stopped = false;
        for keystore in self.get_all_keystores() {
            if keystore.stop_recertification(fpr).await.is_ok() {
                at_least_one_stopped = true;
            }
        }
        if at_least_one_stopped {
            Ok(())
        } else {
            Err(anyhow!("Could not find stop recertification in any CA!"))
        }
    }

    #[tracing::instrument]
    async fn delete(&self, fpr: &Fingerprint) -> Result<(), anyhow::Error> {
        for keystore in self.get_all_keystores() {
            keystore.delete(fpr).await.unwrap_or(());
        }
        Ok(())
    }

    fn can_store_revocations_without_publishing(&self) -> bool {
        true
    }

    #[tracing::instrument]
    async fn store_revocations_without_publishing(
        &self,
        cert: &Cert,
        revocations: Vec<Signature>,
    ) -> Result<(), anyhow::Error> {
        for (domain, cert) in split_cert_by_domain(cert) {
            self.get_keystore_for_domain(domain.as_str())?
                .store_revocations_without_publishing(&cert, revocations.clone())
                .await?;
        }
        Ok(())
    }

    #[tracing::instrument]
    async fn get_stored_revocations(&self, fpr: &Fingerprint) -> Result<Vec<Signature>, anyhow::Error> {
        let mut stored_revocations = vec![];
        for keystore in self.get_all_keystores() {
            let mut revocations = keystore.get_stored_revocations(fpr).await.unwrap_or_default();
            stored_revocations.append(&mut revocations);
        }
        #[allow(clippy::mutable_key_type)]
        let hashset: HashSet<Signature, RandomState> = HashSet::from_iter(stored_revocations.into_iter());
        Ok(hashset.into_iter().collect())
    }
}

#[tracing::instrument]
fn split_cert_by_domain(cert: &Cert) -> HashMap<String, Cert> {
    let mut map: HashMap<String, Vec<Cert>> = HashMap::new();
    for cert_with_single_uid in CertWithSingleUID::iterate_over_cert(cert) {
        if let Ok(Some(email)) = cert_with_single_uid.userid().email_normalized() {
            if let Ok(email) = Email::parse(email.as_str()) {
                let domain = email.get_domain();
                match map.get_mut(domain) {
                    None => {
                        map.insert(domain.to_string(), vec![cert_with_single_uid.into()]);
                    }
                    Some(mut_vec) => mut_vec.push(cert_with_single_uid.into()),
                }
            }
        }
    }
    let iter = map.into_iter().map(|(k, v)| {
        (
            k,
            merge_certs(v)
                .first()
                .cloned()
                .expect("Contains at least one cert by design!"),
        )
    });
    HashMap::from_iter(iter)
}
