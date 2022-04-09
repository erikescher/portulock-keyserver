/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use base64::DecodeError;
use challenges::EmailVerificationChallenge;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use sequoia_openpgp::Fingerprint;
use serde::de::{Error, Unexpected};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use shared::types::Email;
use tracing::info;

use crate::db_new::DBWrapper;
use crate::key_storage::{certify_and_publish_approved_cert, filter_cert_by_approved_uids, KeyStore};
use crate::submission::mailer::Mailer;
use crate::utils_verifier::expiration::ExpirationConfig;
use crate::verification::sso::{AuthChallengeData, AuthSystem, VerifiedSSOClaims};
use crate::verification::tokens::{
    EmailVerificationToken, NameVerificationToken, SignedEmailVerificationToken, SignedNameVerificationToken,
};

#[tracing::instrument]
pub async fn verify_email_request(
    fpr: &Fingerprint,
    email: &Email,
    token_key: &TokenKey,
    expiration_config: &ExpirationConfig,
    mailer: &dyn Mailer,
) -> Result<(), anyhow::Error> {
    let challenge = EmailVerificationChallenge::new(fpr, email);
    let challenge = EmailVerificationToken::from(&challenge, expiration_config).sign(token_key);
    mailer.send_signed_email_challenge(&challenge, email).await
}

#[tracing::instrument]
pub async fn verify_email(
    email_token: SignedEmailVerificationToken,
    submitter_db: &DBWrapper<'_>,
    token_key: &TokenKey,
    keystore: &(impl KeyStore + ?Sized),
) -> Result<(), anyhow::Error> {
    let email_token = email_token.verify(token_key)?;
    let fpr = email_token.fpr.as_str();
    submitter_db
        .store_approved_email(
            &Email::parse(email_token.email.as_str())?,
            &Fingerprint::from_hex(fpr)?,
            email_token.exp,
        )
        .await?;
    trigger_certification_and_publishing(fpr, submitter_db, keystore).await
}

#[tracing::instrument]
pub async fn verify_name(
    name_token: SignedNameVerificationToken,
    submitter_db: &DBWrapper<'_>,
    token_key: &TokenKey,
    keystore: &(impl KeyStore + ?Sized),
) -> Result<(), anyhow::Error> {
    let name_token = name_token.verify(token_key)?;
    let fpr = name_token.fpr.as_str();

    submitter_db
        .store_approved_name(name_token.name.as_str(), &Fingerprint::from_hex(fpr)?, name_token.exp)
        .await?;

    trigger_certification_and_publishing(fpr, submitter_db, keystore).await
}

pub async fn trigger_certification_and_publishing(
    fpr: &str,
    submitter_db: &DBWrapper<'_>,
    keystore: &(impl KeyStore + ?Sized),
) -> Result<(), anyhow::Error> {
    info!("Triggering Certification and Publishing: fpr={}", fpr);
    let fpr = Fingerprint::from_hex(fpr)?;
    let pending_cert = submitter_db.get_pending_cert_by_fpr(&fpr).await?;
    match pending_cert {
        None => {
            info!("No pending Cert found!")
        }
        Some(pending_cert) => {
            info!("Pending Cert found: {:?}", pending_cert);
            let approved_cert = filter_cert_by_approved_uids(submitter_db, pending_cert).await?;
            info!("Found {} approved userids.", approved_cert.userids().len());
            if approved_cert.userids().len() > 0 {
                certify_and_publish_approved_cert(keystore, approved_cert.clone()).await?;

                if keystore.can_store_revocations_without_publishing() {
                    let stored_revocations = submitter_db
                        .get_stored_revocations(&approved_cert.fingerprint())
                        .await?;
                    keystore
                        .store_revocations_without_publishing(&approved_cert, stored_revocations)
                        .await?;
                }
            }
        }
    };
    Ok(())
}

pub mod challenges;
pub mod sso;
pub mod tokens;

#[derive(Debug)]
// TODO implement Debug manually or switch to secret type to not log the TokenKey
pub struct TokenKey {
    secret: Vec<u8>,
}

impl<'de> Deserialize<'de> for TokenKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string: String = Deserialize::deserialize(deserializer)?;
        let bytes = base64::decode(&string)
            .map_err(|_| D::Error::invalid_value(Unexpected::Str(&string), &"base64 encoded bytes"))?;
        Ok(Self { secret: bytes })
    }
}

#[derive(Debug)]
pub struct Base64(Vec<u8>);
impl Serialize for Base64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&base64::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Base64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let string: String = Deserialize::deserialize(deserializer)?;
        let bytes = base64::decode(&string)
            .map_err(|_| D::Error::invalid_value(Unexpected::Str(&string), &"base64 encoded bytes"))?;
        Ok(Self(bytes))
    }
}

impl TokenKey {
    pub fn new(secret: &str) -> Result<Self, DecodeError> {
        let secret = base64::decode(secret)?;
        Ok(Self { secret })
    }

    pub fn decoding_key(&self) -> DecodingKey {
        DecodingKey::from_secret(self.secret.as_slice())
    }

    pub fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_secret(self.secret.as_slice())
    }

    pub fn algorithm(&self) -> Algorithm {
        Algorithm::HS512
    }
}

#[derive(Deserialize, Debug)]
pub struct VerificationConfig {
    #[serde(flatten)]
    pub sso_config: SSOConfig,
}

#[derive(Deserialize, Debug)]
pub struct SSOConfig {
    #[serde(flatten)]
    pub entry: SSOConfigEntry,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
#[serde(tag = "sso_type")] // TODO switch to externally tagged?
pub enum SSOConfigEntry {
    Oidc(OpenIDConnectConfigEntry),
    Saml(SAMLConfigEntry),
}

#[derive(Deserialize, Debug)]
pub struct OpenIDConnectConfigEntry {
    #[serde(alias = "oidc_issuer_url")]
    pub issuer_url: String,
    #[serde(alias = "oidc_client_id")]
    pub client_id: String,
    #[serde(alias = "oidc_client_secret")]
    pub client_secret: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct SAMLConfigEntry {
    #[serde(alias = "saml_idp_url")]
    pub idp_url: String,
    #[serde(alias = "saml_idp_metadata_url")]
    pub idp_metadata_url: String,
    #[serde(alias = "saml_sp_entity_id")]
    pub sp_entity_id: String, // can make this optional, which will use the sp_metadata_url
    #[serde(alias = "saml_sp_certificate_pem")]
    pub sp_certificate_pem: String,
    #[serde(alias = "saml_sp_private_key_pem")]
    pub sp_private_key_pem: String,
    #[serde(alias = "saml_attribute_selectors_name")]
    pub attribute_selectors_name: Vec<String>,
    #[serde(alias = "saml_attribute_selectors_email")]
    pub attribute_selectors_email: Vec<String>,
}

#[tracing::instrument]
pub async fn verify_name_start(
    fpr: Fingerprint,
    auth_system: &AuthSystem,
) -> Result<(String, AuthChallengeCookie), anyhow::Error> {
    let (auth_url, auth_challenge) = auth_system.get_auth_url()?;

    let cookie_data = AuthChallengeCookie {
        auth_challenge,
        fpr: fpr.to_string(),
    };
    Ok((auth_url.to_string(), cookie_data))
}

#[tracing::instrument]
fn claims_to_tokens(
    claims: VerifiedSSOClaims,
    expiration_config: &ExpirationConfig,
    fpr: &str,
    token_key: &TokenKey,
) -> (Vec<SignedNameVerificationToken>, Vec<SignedEmailVerificationToken>) {
    let name_tokens = claims
        .names
        .iter()
        .map(|name| {
            NameVerificationToken {
                name: name.to_string(),
                fpr: fpr.to_string(),
                exp: expiration_config.expiration_u64(),
                iat: ExpirationConfig::current_time_u64(),
                nbf: ExpirationConfig::current_time_u64() - 1,
            }
            .sign(token_key)
        })
        .collect();
    let email_tokens = claims
        .emails
        .iter()
        .map(|email| {
            EmailVerificationToken {
                email: email.to_string(),
                fpr: fpr.to_string(),
                exp: expiration_config.expiration_u64(),
                iat: ExpirationConfig::current_time_u64(),
                nbf: ExpirationConfig::current_time_u64() - 1,
            }
            .sign(token_key)
        })
        .collect();

    (name_tokens, email_tokens)
}

#[tracing::instrument]
pub async fn verify_name_auth_system(
    auth_state: Option<&String>,
    auth_response: &str,
    auth_challenge_cookie: AuthChallengeCookie,
    auth_system: &AuthSystem,
    token_key: &TokenKey,
    expiration_config: &ExpirationConfig,
) -> Result<(Vec<SignedNameVerificationToken>, Vec<SignedEmailVerificationToken>), anyhow::Error> {
    let auth_challenge = auth_challenge_cookie.auth_challenge;
    let fpr = auth_challenge_cookie.fpr;
    let claims = auth_system
        .verify_and_extract_claims(auth_challenge, auth_response, auth_state)
        .await?;

    Ok(claims_to_tokens(claims, expiration_config, &fpr, token_key))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthChallengeCookie {
    auth_challenge: AuthChallengeData,
    pub fpr: String,
}
