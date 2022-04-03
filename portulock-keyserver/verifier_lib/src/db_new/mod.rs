// TODO maybe define specific Errors?

use std::fmt::{Debug, Formatter};

use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::{Cert, Fingerprint};
use shared::filtering::applier::KeyFilterApplier;
use shared::filtering::filters::KeyFilterStrippingUserids;
use shared::types::Email;

use crate::certs::CertWithSingleUID;

pub trait DB {
    fn migrate(&self) -> Result<(), anyhow::Error>;
    fn maintain(&self) -> Result<(), anyhow::Error>;

    fn get_approved_names(&self, fpr: &Fingerprint) -> Result<Vec<String>, anyhow::Error>;
    fn get_approved_emails(&self, fpr: &Fingerprint) -> Result<Vec<String>, anyhow::Error>;
    fn get_pending_cert_by_fpr(&self, fpr: &Fingerprint) -> Result<Option<Cert>, anyhow::Error>;
    fn get_pending_cert_by_email(&self, email: &Email) -> Result<Vec<Cert>, anyhow::Error>;
    fn get_stored_revocations(&self, fpr: &Fingerprint) -> Result<Vec<Signature>, anyhow::Error>;

    fn store_approved_name(&self, name: &str, fpr: &Fingerprint, expiration: u64) -> Result<(), anyhow::Error>;
    fn store_approved_email(&self, email: &Email, fpr: &Fingerprint, expiration: u64) -> Result<(), anyhow::Error>;
    fn store_pending_revocation(
        &self,
        revocation: &Signature,
        fpr: &Fingerprint,
        expiration: u64,
    ) -> Result<(), anyhow::Error>;
    fn store_pending_key(&self, cert: &Cert, expiration: u64) -> Result<(), anyhow::Error>;
    fn store_pending_uid(&self, cert: &CertWithSingleUID, expiration: u64) -> Result<(), anyhow::Error>;

    fn delete_data_for_fpr(&self, fpr: &Fingerprint) -> Result<(), anyhow::Error>;
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
        self.db.get_approved_names(fpr).map(|mut v| {
            v.sort_unstable();
            v.dedup();
            v
        })
    }

    #[tracing::instrument]
    pub async fn get_approved_emails(&self, fpr: &Fingerprint) -> Result<Vec<String>, anyhow::Error> {
        self.db.get_approved_emails(fpr).map(|mut v| {
            v.sort_unstable();
            v.dedup();
            v
        })
    }

    #[tracing::instrument]
    pub async fn get_pending_cert_by_fpr(&self, fpr: &Fingerprint) -> Result<Option<Cert>, anyhow::Error> {
        self.db.get_pending_cert_by_fpr(fpr)
    }

    #[tracing::instrument]
    pub async fn get_pending_cert_by_email(&self, email: &Email) -> Result<Vec<Cert>, anyhow::Error> {
        self.db.get_pending_cert_by_email(email)
    }

    #[tracing::instrument]
    pub async fn get_stored_revocations(&self, fpr: &Fingerprint) -> Result<Vec<Signature>, anyhow::Error> {
        self.db.get_stored_revocations(fpr)
    }

    #[tracing::instrument]
    pub async fn store_approved_name(
        &self,
        name: &str,
        fpr: &Fingerprint,
        expiration: u64,
    ) -> Result<(), anyhow::Error> {
        self.db.store_approved_name(name, fpr, expiration)
    }

    #[tracing::instrument]
    pub async fn store_approved_email(
        &self,
        email: &Email,
        fpr: &Fingerprint,
        expiration: u64,
    ) -> Result<(), anyhow::Error> {
        // TODO accept typed expiration instead
        self.db.store_approved_email(email, fpr, expiration)
    }

    #[tracing::instrument]
    pub async fn store_pending_key(&self, pending_key: &Cert, expiration: u64) -> Result<(), anyhow::Error> {
        let key_without_uids = KeyFilterApplier::from(pending_key.clone())
            .apply(KeyFilterStrippingUserids {})
            .into();
        self.db.store_pending_key(&key_without_uids, expiration)?;
        for key_with_single_uid in CertWithSingleUID::iterate_over_cert(pending_key) {
            self.db.store_pending_uid(&key_with_single_uid, expiration)?;
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
        self.db.store_pending_revocation(revocation, fpr, expiration)
    }

    #[tracing::instrument]
    pub async fn delete_data_for_fpr(&self, fpr: &Fingerprint) -> Result<(), anyhow::Error> {
        self.db.delete_data_for_fpr(fpr)
    }

    #[tracing::instrument]
    pub async fn maintain(&self) -> Result<(), anyhow::Error> {
        self.db.maintain()
    }

    #[tracing::instrument]
    pub fn migrate(&self) -> Result<(), anyhow::Error> {
        self.db.migrate()
    }
}
