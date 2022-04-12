/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::fs;
use std::fs::{remove_dir_all, remove_file};
use std::path::Path;

use anyhow::anyhow;
use async_trait::async_trait;
use openpgp_ca_lib::ca::OpenpgpCa as BackendCA;
use openpgp_ca_lib::db::models::Cert as BackendCert;
use sequoia_net::wkd::{Url, Variant};
use sequoia_openpgp::cert::CertParser;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::Serialize;
use sequoia_openpgp::{Cert, Fingerprint};
use shared::types::Email;
use shared::utils::armor::certificate_from_str;
use shared::utils::armor::{armor_signature, export_armored_cert};

use crate::certs::CertWithSingleUID;
use crate::key_storage::emails_from_cert;
use crate::key_storage::KeyStore;
use crate::management::revocations_from_string;

#[derive(Clone, Debug)]
pub struct OpenPGPCALib {
    db_url: String,
    domain: String,
    duration: u64,
    threshold: u64,
    path: String,
}

impl OpenPGPCALib {
    #[tracing::instrument]
    pub fn new(domain: &str, certification_duration: u64, certification_threshold: u64) -> Result<Self, anyhow::Error> {
        let domain = domain.to_string();
        let db_url = format!("./state/ca-{}.sqlite", domain);
        let new_instance = Self {
            db_url,
            domain,
            duration: certification_duration,
            threshold: certification_threshold,
            path: "./wkd".to_string(),
        };

        let new_ca = new_instance.get_ca()?;
        match new_ca.ca_get_cert_pub() {
            Ok(_) => (),
            Err(_) => {
                new_ca.ca_init(new_instance.domain.as_str(), None)?;
                new_ca.export_wkd(new_instance.domain.as_str(), new_instance.get_wkd_path())?;
            }
        }
        new_instance.perform_maintenance()?;
        Ok(new_instance)
    }
}

fn ca_cert_model_to_parsed_cert(cert: BackendCert) -> Cert {
    certificate_from_str(cert.pub_cert.as_str())
}

fn ca_cert_model_vec_to_parsed_cert_vec(certs: Vec<BackendCert>) -> Vec<Cert> {
    certs.into_iter().map(ca_cert_model_to_parsed_cert).collect()
}

struct CertEntryForDeletion {
    cert_id: usize,
    user_id: usize,
}

impl OpenPGPCALib {
    fn get_db_url(&self) -> &str {
        self.db_url.as_str()
    }

    fn get_wkd_path(&self) -> &Path {
        Path::new(self.path.as_str())
    }

    fn get_ca(&self) -> Result<BackendCA, anyhow::Error> {
        BackendCA::new(Some(self.get_db_url()))
    }

    #[tracing::instrument]
    fn delete_cert_from_wkd(&self, delisted_cert: &Cert) -> Result<(), anyhow::Error> {
        for uida in delisted_cert.userids() {
            if let Ok(Some(string)) = uida.userid().email_normalized() {
                if let Ok(e) = Email::parse(string.as_str()) {
                    if e.get_domain() == self.domain.as_str() {
                        if let Ok(url) = Url::from(e.get_email()) {
                            if let Ok(path) = url.to_file_path(None) {
                                if path.is_file() {
                                    let existing_certs: Vec<Cert> = CertParser::from_file(&path)?
                                        .filter_map(|c| c.ok())
                                        .filter(|existing_cert| {
                                            existing_cert.fingerprint() != delisted_cert.fingerprint()
                                        })
                                        .collect();

                                    if !existing_certs.is_empty() {
                                        let mut file = fs::File::create(&path)?;
                                        for c in existing_certs {
                                            c.export(&mut file)?;
                                        }
                                    } else {
                                        remove_file(path)?;
                                    }
                                }
                            }
                        }
                    }
                }
            };
        }
        Ok(())
    }

    #[tracing::instrument]
    fn update_wkd_for_cert(&self, cert: &Cert) -> Result<(), anyhow::Error> {
        for cert in CertWithSingleUID::iterate_over_cert(cert) {
            sequoia_net::wkd::insert(
                self.get_wkd_path(),
                self.domain.as_str(),
                Variant::Advanced,
                &cert.into(),
            )?
        }
        Ok(())
    }

    #[tracing::instrument]
    fn delete_delisted_certs(&self) -> Result<(), anyhow::Error> {
        let mut connection = rusqlite::Connection::open(self.get_db_url())?;
        connection.execute("PRAGMA foreign_keys=on", [])?;
        let transaction = connection.transaction()?;
        let mut query =
            transaction.prepare("SELECT id, user_id FROM certs WHERE user_id NOT NULL AND delisted = 1;")?;
        let entries = query
            .query_map([], |row| {
                Ok(CertEntryForDeletion {
                    cert_id: row.get(0)?,
                    user_id: row.get(1)?,
                })
            })?
            .filter_map(|r| match r {
                Ok(e) => Some(e),
                Err(_) => None,
            });
        for entry in entries {
            transaction.execute("DELETE FROM users        WHERE user_id=?1;", [entry.user_id])?;
            transaction.execute("DELETE FROM certs        WHERE cert_id=?1;", [entry.cert_id])?;
            transaction.execute("DELETE FROM certs_emails WHERE cert_id=?1;", [entry.cert_id])?;
        }

        drop(query);
        transaction.commit()?;
        Ok(())
    }

    #[tracing::instrument]
    pub fn perform_maintenance(&self) -> Result<(), anyhow::Error> {
        let ca = self.get_ca()?;
        ca.certs_refresh_ca_certifications(self.threshold, self.duration)?;
        self.delete_delisted_certs()
    }

    #[tracing::instrument]
    pub fn regenerate_wkd(&self) -> Result<(), anyhow::Error> {
        let ca = self.get_ca()?;
        let path = self.path.clone() + ".well-known/openpgpkey/" + self.domain.as_str() + "/hu/";
        let path = Path::new(&path);
        if path.is_dir() {
            remove_dir_all(path)?;
        }
        ca.export_wkd(self.domain.as_str(), self.get_wkd_path())?;
        Ok(())
    }
}

#[async_trait]
impl KeyStore for &OpenPGPCALib {
    #[tracing::instrument]
    async fn store(&self, cert: &Cert) -> Result<(), anyhow::Error> {
        let emails = emails_from_cert(cert);
        let emails: Vec<&str> = emails.iter().map(|s| s.as_str()).collect();
        let armored_cert = export_armored_cert(cert);
        let ca = self.get_ca()?;
        match ca.cert_import_update(armored_cert.as_str()) {
            Ok(_) => (),
            Err(_) => {
                ca.cert_import_new(
                    armored_cert.as_str(),
                    vec![],
                    None,
                    emails.as_slice(),
                    Some(self.duration),
                )?;
            }
        };
        self.update_wkd_for_cert(cert)
    }

    #[tracing::instrument]
    async fn list_by_email(&self, email: &str) -> Result<Vec<Cert>, anyhow::Error> {
        self.get_ca()?
            .certs_by_email(email)
            .map(ca_cert_model_vec_to_parsed_cert_vec)
    }

    #[tracing::instrument]
    async fn get_by_fpr(&self, fpr: &Fingerprint) -> Result<Option<Cert>, anyhow::Error> {
        Ok(self
            .get_ca()?
            .cert_get_by_fingerprint(fpr.to_hex().as_str())?
            .map(ca_cert_model_to_parsed_cert))
    }

    #[tracing::instrument]
    async fn stop_recertification(&self, fpr: &Fingerprint) -> Result<(), anyhow::Error> {
        let ca = self.get_ca()?;
        let mut cert = ca
            .cert_get_by_fingerprint(fpr.to_hex().as_str())?
            .ok_or_else(|| anyhow!("No certificate found to deactivate!"))?;

        cert.inactive = true;

        Ok(ca.db().cert_update(&cert)?)
    }

    #[tracing::instrument]
    async fn delete(&self, fpr: &Fingerprint) -> Result<(), anyhow::Error> {
        let ca = self.get_ca()?;
        let mut cert = ca
            .cert_get_by_fingerprint(fpr.to_hex().as_str())?
            .ok_or_else(|| anyhow!("No certificate found to delete!"))?;

        cert.delisted = true;

        ca.db().cert_update(&cert)?;

        self.delete_delisted_certs().unwrap_or(());
        self.delete_cert_from_wkd(&ca_cert_model_to_parsed_cert(cert))
    }

    fn can_store_revocations_without_publishing(&self) -> bool {
        true
    }

    #[tracing::instrument]
    async fn store_revocations_without_publishing(
        &self,
        _cert: &Cert,
        revocations: Vec<Signature>,
    ) -> Result<(), anyhow::Error> {
        for revocation in revocations {
            self.get_ca()?.revocation_add(armor_signature(revocation)?.as_str())?;
        }
        Ok(())
    }

    #[tracing::instrument]
    async fn get_stored_revocations(&self, fpr: &Fingerprint) -> Result<Vec<Signature>, anyhow::Error> {
        let ca = self.get_ca()?;
        let cert = ca
            .cert_get_by_fingerprint(fpr.to_hex().as_str())?
            .ok_or_else(|| anyhow!("No certificate found!"))?;
        Ok(self
            .get_ca()?
            .revocations_get(&cert)?
            .into_iter()
            .filter_map(|rev| revocations_from_string(rev.revocation).ok())
            .flatten()
            .collect())
    }
}
