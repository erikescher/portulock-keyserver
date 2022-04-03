use std::fmt::Debug;

use crate::errors::VerifierError;
use crate::verification::sso::oidc_verification::OidcVerifier;
use crate::verification::sso::saml_verification::SamlVerifier;
use crate::verification::sso::AuthSystem;
use crate::verification::SSOConfigEntry;

pub mod certs;
pub mod db;
pub mod db_new;
pub mod errors;
pub mod key_storage;
pub mod management;
pub mod submission;
pub mod utils_verifier;
pub mod verification;

#[derive(Debug)]
pub enum DeletionConfig {
    Always(),
    Never(),
}

pub async fn create_auth_system(config_entry: &SSOConfigEntry) -> Result<AuthSystem, VerifierError> {
    Ok(match config_entry {
        SSOConfigEntry::Oidc(oidc) => AuthSystem::Oidc(
            OidcVerifier::new(
                oidc.issuer_url.as_str(),
                oidc.client_id.as_str(),
                oidc.client_secret.as_deref(),
                oidc.endpoint_url.as_str(),
            )
            .await?,
        ),
        SSOConfigEntry::Saml(saml) => AuthSystem::Saml(
            SamlVerifier::new(
                saml.idp_url.as_str(),
                saml.idp_metadata_url.as_str(),
                saml.endpoint_url.as_str(),
                saml.sp_entity_id.as_str(),
                saml.sp_certificate_pem.as_str(),
                saml.sp_private_key_pem.as_str(),
                saml.attribute_selectors_name.clone(),
                saml.attribute_selectors_email.clone(),
            )
            .await?,
        ),
    })
}
