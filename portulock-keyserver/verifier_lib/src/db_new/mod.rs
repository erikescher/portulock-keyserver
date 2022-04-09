// TODO maybe define specific Errors?

use std::fmt::{Debug, Formatter};

use async_trait::async_trait;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::{Cert, Fingerprint};
use shared::filtering::applier::KeyFilterApplier;
use shared::filtering::filters::KeyFilterStrippingUserids;
use shared::types::Email;

use crate::certs::CertWithSingleUID;

#[async_trait]
pub trait DB: Send + Sync {
    async fn migrate(&self) -> Result<(), anyhow::Error>;
    async fn maintain(&self) -> Result<(), anyhow::Error>;

    async fn get_approved_names(&self, fpr: Fingerprint) -> Result<Vec<String>, anyhow::Error>;
    async fn get_approved_emails(&self, fpr: Fingerprint) -> Result<Vec<String>, anyhow::Error>;
    async fn get_pending_cert_by_fpr(&self, fpr: Fingerprint) -> Result<Option<Cert>, anyhow::Error>;
    async fn get_pending_cert_by_email(&self, email: Email) -> Result<Vec<Cert>, anyhow::Error>;
    async fn get_stored_revocations(&self, fpr: Fingerprint) -> Result<Vec<Signature>, anyhow::Error>;

    async fn store_approved_name(&self, name: String, fpr: Fingerprint, expiration: u64) -> Result<(), anyhow::Error>;
    async fn store_approved_email(&self, email: Email, fpr: Fingerprint, expiration: u64) -> Result<(), anyhow::Error>;
    async fn store_pending_revocation(
        &self,
        revocation: Signature,
        fpr: Fingerprint,
        expiration: u64,
    ) -> Result<(), anyhow::Error>;
    async fn store_pending_key(&self, cert: Cert, expiration: u64) -> Result<(), anyhow::Error>;
    async fn store_pending_uid(&self, cert: CertWithSingleUID, expiration: u64) -> Result<(), anyhow::Error>;

    async fn delete_data_for_fpr(&self, fpr: Fingerprint) -> Result<(), anyhow::Error>;
}

pub struct DBWrapper<'a> {
    pub db: &'a dyn DB,
}

impl Debug for DBWrapper<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "DBWrapper: {{db: <DEBUG_NOT_IMPLEMENTED>}}")
    }
}

// TODO handle signature verification here or in the DB implementations?
//  or implement them as Wrappers?
impl DBWrapper<'_> {
    #[tracing::instrument]
    pub async fn get_approved_names(&self, fpr: &Fingerprint) -> Result<Vec<String>, anyhow::Error> {
        self.db.get_approved_names(fpr.clone()).await.map(|mut v| {
            v.sort_unstable();
            v.dedup();
            v
        })
    }

    #[tracing::instrument]
    pub async fn get_approved_emails(&self, fpr: &Fingerprint) -> Result<Vec<String>, anyhow::Error> {
        self.db.get_approved_emails(fpr.clone()).await.map(|mut v| {
            v.sort_unstable();
            v.dedup();
            v
        })
    }

    #[tracing::instrument]
    pub async fn get_pending_cert_by_fpr(&self, fpr: &Fingerprint) -> Result<Option<Cert>, anyhow::Error> {
        self.db.get_pending_cert_by_fpr(fpr.clone()).await
    }

    #[tracing::instrument]
    pub async fn get_pending_cert_by_email(&self, email: &Email) -> Result<Vec<Cert>, anyhow::Error> {
        self.db.get_pending_cert_by_email(email.clone()).await
    }

    #[tracing::instrument]
    pub async fn get_stored_revocations(&self, fpr: &Fingerprint) -> Result<Vec<Signature>, anyhow::Error> {
        self.db.get_stored_revocations(fpr.clone()).await
    }

    #[tracing::instrument]
    pub async fn store_approved_name(
        &self,
        name: &str,
        fpr: &Fingerprint,
        expiration: u64,
    ) -> Result<(), anyhow::Error> {
        self.db
            .store_approved_name(name.to_string(), fpr.clone(), expiration)
            .await
    }

    #[tracing::instrument]
    pub async fn store_approved_email(
        &self,
        email: &Email,
        fpr: &Fingerprint,
        expiration: u64,
    ) -> Result<(), anyhow::Error> {
        // TODO accept typed expiration instead
        self.db
            .store_approved_email(email.clone(), fpr.clone(), expiration)
            .await
    }

    #[tracing::instrument]
    pub async fn store_pending_key(&self, pending_key: &Cert, expiration: u64) -> Result<(), anyhow::Error> {
        let key_without_uids = KeyFilterApplier::from(pending_key.clone())
            .apply(KeyFilterStrippingUserids {})
            .into();
        self.db.store_pending_key(key_without_uids, expiration).await?;
        for key_with_single_uid in CertWithSingleUID::iterate_over_cert(pending_key) {
            self.db.store_pending_uid(key_with_single_uid, expiration).await?;
        }
        Ok(())
    }

    #[tracing::instrument]
    pub async fn store_pending_revocation(
        &self,
        revocation: &Signature,
        fpr: &Fingerprint,
        expiration: u64,
    ) -> Result<(), anyhow::Error> {
        self.db
            .store_pending_revocation(revocation.clone(), fpr.clone(), expiration)
            .await
    }

    #[tracing::instrument]
    pub async fn delete_data_for_fpr(&self, fpr: &Fingerprint) -> Result<(), anyhow::Error> {
        self.db.delete_data_for_fpr(fpr.clone()).await
    }

    #[tracing::instrument]
    pub async fn maintain(&self) -> Result<(), anyhow::Error> {
        self.db.maintain().await
    }

    #[tracing::instrument]
    pub async fn migrate(&self) -> Result<(), anyhow::Error> {
        self.db.migrate().await
    }
}
