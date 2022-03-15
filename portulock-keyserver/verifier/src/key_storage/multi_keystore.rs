/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;

use async_trait::async_trait;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::{Cert, Fingerprint};
use shared::errors::CustomError;
use shared::types::Email;

use crate::certs::CertWithSingleUID;
use crate::key_storage::openpgp_ca_lib::OpenPGPCALib;
use crate::key_storage::KeyStore;
use crate::utils::merge_certs;

#[derive(Clone, Debug)]
pub struct MultiOpenPGPCALib {
    keystores: HashMap<String, OpenPGPCALib>,
}

impl MultiOpenPGPCALib {
    pub fn new(keystores: HashMap<String, OpenPGPCALib>) -> Self {
        Self { keystores }
    }

    fn get_keystore_for_domain(&self, domain: &str) -> Result<&OpenPGPCALib, CustomError> {
        self.keystores
            .get(domain)
            .ok_or_else(|| "No keystore found for this domain!".into())
    }

    fn get_all_keystores(&self) -> Vec<&OpenPGPCALib> {
        self.keystores.values().collect()
    }

    pub fn perform_maintenance(&self) -> Result<(), CustomError> {
        for keystore in self.get_all_keystores() {
            keystore.perform_maintenance()?;
        }
        Ok(())
    }
}

#[async_trait]
impl KeyStore for &MultiOpenPGPCALib {
    async fn store(&self, cert: &Cert) -> Result<(), CustomError> {
        for (domain, cert) in split_cert_by_domain(cert) {
            self.get_keystore_for_domain(domain.as_str())?.store(&cert).await?;
        }
        Ok(())
    }

    async fn list_by_email(&self, email: &str) -> Result<Vec<Cert>, CustomError> {
        let parsed_email = Email::parse(email)?;
        let keystore = self.get_keystore_for_domain(parsed_email.get_domain())?;

        keystore.list_by_email(email).await
    }

    async fn get_by_fpr(&self, fpr: &Fingerprint) -> Result<Option<Cert>, CustomError> {
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

    async fn stop_recertification(&self, fpr: &Fingerprint) -> Result<(), CustomError> {
        let mut at_least_one_stopped = false;
        for keystore in self.get_all_keystores() {
            if keystore.stop_recertification(fpr).await.is_ok() {
                at_least_one_stopped = true;
            }
        }
        if at_least_one_stopped {
            Ok(())
        } else {
            Err("Could not find stop recertification in any CA!".into())
        }
    }

    async fn delete(&self, fpr: &Fingerprint) -> Result<(), CustomError> {
        for keystore in self.get_all_keystores() {
            keystore.delete(fpr).await.unwrap_or(());
        }
        Ok(())
    }

    fn can_store_revocations_without_publishing(&self) -> bool {
        true
    }

    async fn store_revocations_without_publishing(
        &self,
        cert: &Cert,
        revocations: Vec<Signature>,
    ) -> Result<(), CustomError> {
        for (domain, cert) in split_cert_by_domain(cert) {
            self.get_keystore_for_domain(domain.as_str())?
                .store_revocations_without_publishing(&cert, revocations.clone())
                .await?;
        }
        Ok(())
    }

    async fn get_stored_revocations(&self, fpr: &Fingerprint) -> Result<Vec<Signature>, CustomError> {
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
