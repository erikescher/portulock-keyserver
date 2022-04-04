use std::collections::HashMap;
use std::fmt::Debug;

use anyhow::anyhow;
use reqwest::Url;

use crate::verification::sso::oidc_verification::OidcVerifier;
use crate::verification::sso::saml_verification::SamlVerifier;

pub mod oidc_verification;
pub mod saml_verification;

pub(crate) type AuthChallengeData = HashMap<String, String>;

#[derive(Debug)]
pub enum AuthSystem {
    Saml(SamlVerifier),
    Oidc(OidcVerifier),
}

impl AuthSystem {
    pub fn get_auth_url(&self) -> Result<(Url, AuthChallengeData), anyhow::Error> {
        match self {
            AuthSystem::Saml(saml) => saml.get_auth_url(),
            AuthSystem::Oidc(oidc) => oidc.get_auth_url(),
        }
    }
    pub async fn verify_and_extract_claims(
        &self,
        auth_challenge: AuthChallengeData,
        auth_response: &str,
        auth_state: Option<String>,
    ) -> Result<VerifiedSSOClaims, anyhow::Error> {
        match self {
            AuthSystem::Saml(saml) => saml.verify_and_extract_claims(auth_challenge, auth_response).await,
            AuthSystem::Oidc(oidc) => match auth_state {
                None => Err(anyhow!("OIDC requires AuthState!")),
                Some(auth_state) => {
                    oidc.verify_and_extract_claims(auth_challenge, auth_response, auth_state.as_str())
                        .await
                }
            },
        }
    }
}

#[derive(Debug)]
pub struct VerifiedSSOClaims {
    pub names: Vec<String>,
    pub emails: Vec<String>,
}
