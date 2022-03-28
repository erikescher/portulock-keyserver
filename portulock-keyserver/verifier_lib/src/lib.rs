#[macro_use]
extern crate diesel;
#[macro_use]
extern crate diesel_migrations;
#[macro_use]
extern crate rocket_contrib;

use std::fmt::{Debug, Formatter};

use crate::errors::VerifierError;
use crate::verification::tokens::oidc_verification::OidcVerifier;
use crate::verification::VerificationConfig;

pub mod certs;
pub mod db;
pub mod errors;
pub mod key_storage;
pub mod management;
pub mod submission;
pub mod utils_verifier;
pub mod verification;

#[database("sqlite")]
pub struct SubmitterDBConn(diesel::SqliteConnection);

impl Debug for SubmitterDBConn {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("SubmitterDBConn") // TODO add SQLite url
    }
}

#[derive(Debug)]
pub enum DeletionConfig {
    Always(),
    Never(),
}

pub async fn create_verifier(verification_config: &VerificationConfig) -> Result<OidcVerifier, VerifierError> {
    let config_entry = &verification_config.oidc_config.entry;
    OidcVerifier::new(
        config_entry.issuer_url.as_str(),
        config_entry.client_id.as_str(),
        config_entry.client_secret.as_deref(),
        config_entry.endpoint_url.as_str(),
    )
    .await
}
