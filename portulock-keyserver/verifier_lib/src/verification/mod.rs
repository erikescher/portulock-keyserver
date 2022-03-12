/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use base64::DecodeError;
use chrono::NaiveDateTime;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use sequoia_openpgp::Fingerprint;
use serde::{Deserialize, Serialize};
use shared::errors::CustomError;
use shared::types::Email;
use tracing::info;

use crate::db::{
    get_pending_cert, get_stored_revocations, store_verified_email, store_verified_name, EmailVerificationChallenge,
};
use crate::errors::VerifierError;
use crate::key_storage::{certify_and_publish_approved_cert, filter_cert_by_approved_uids, KeyStore};
use crate::submission::mailer::Mailer;
use crate::utils_verifier::expiration::ExpirationConfig;
use crate::verification::sso::{AuthChallengeData, AuthSystem, VerifiedSSOClaims};
use crate::verification::tokens::{
    EmailVerificationToken, NameVerificationToken, SignedEmailVerificationToken, SignedNameVerificationToken,
};
use crate::SubmitterDBConn;

#[tracing::instrument]
pub async fn verify_email_request(
    fpr: &Fingerprint,
    email: &Email,
    token_key: &TokenKey,
    expiration_config: &ExpirationConfig,
    mailer: &dyn Mailer,
) -> Result<(), VerifierError> {
    let challenge = EmailVerificationChallenge::new(fpr, email);
    let challenge = EmailVerificationToken::from(&challenge, expiration_config).sign(token_key);
    mailer.send_signed_email_challenge(&challenge, email).await
}

#[tracing::instrument]
pub async fn verify_email(
    email_token: SignedEmailVerificationToken,
    submitter_db: &SubmitterDBConn,
    token_key: &TokenKey,
    keystore: &(impl KeyStore + ?Sized),
) -> Result<(), VerifierError> {
    let email_token = email_token.verify(token_key)?;
    let fpr = email_token.fpr.as_str();
    store_verified_email(
        submitter_db,
        fpr,
        email_token.email.as_str(),
        NaiveDateTime::from_timestamp(email_token.exp as i64, 0),
    )
    .await?;
    trigger_certification_and_publishing(fpr, submitter_db, keystore).await
}

#[tracing::instrument]
pub async fn verify_name(
    name_token: SignedNameVerificationToken,
    submitter_db: &SubmitterDBConn,
    token_key: &TokenKey,
    keystore: &(impl KeyStore + ?Sized),
) -> Result<(), VerifierError> {
    let name_token = name_token.verify(token_key)?;
    let fpr = name_token.fpr.as_str();

    store_verified_name(
        submitter_db,
        fpr,
        name_token.name.as_str(),
        NaiveDateTime::from_timestamp(name_token.exp as i64, 0),
    )
    .await?;

    trigger_certification_and_publishing(fpr, submitter_db, keystore).await
}

pub async fn trigger_certification_and_publishing(
    fpr: &str,
    submitter_db: &SubmitterDBConn,
    keystore: &(impl KeyStore + ?Sized),
) -> Result<(), VerifierError> {
    info!("Triggering Certification and Publishing: fpr={}", fpr);
    let fpr = Fingerprint::from_hex(fpr).map_err(CustomError::from)?;
    let pending_cert = get_pending_cert(submitter_db, &fpr).await?;
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
                    let stored_revocations = get_stored_revocations(submitter_db, &approved_cert.fingerprint()).await?;
                    keystore
                        .store_revocations_without_publishing(&approved_cert, stored_revocations)
                        .await?;
                }
            }
        }
    };
    Ok(())
}

pub mod sso;
pub mod tokens;

#[derive(Debug)]
// TODO implement Debug manually or switch to secret type to not log the TokenKey
pub struct TokenKey {
    secret: Vec<u8>,
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

pub struct VerificationConfig {
    pub sso_config: SSOConfig,
}

pub struct SSOConfig {
    pub entry: SSOConfigEntry,
}

pub enum SSOConfigEntry {
    Oidc(OpenIDConnectConfigEntry),
    Saml(SAMLConfigEntry),
}

pub struct OpenIDConnectConfigEntry {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub endpoint_url: String,
}

pub struct SAMLConfigEntry {
    pub idp_url: String,
    pub idp_metadata_url: String, // can likely make this optional and derive from idp_url
    pub endpoint_url: String,
    pub sp_entity_id: String, // can make this optional, which will use the sp_metadata_url
    pub sp_certificate_pem: String,
    pub sp_private_key_pem: String,
    pub attribute_selectors_name: Vec<String>,
    pub attribute_selectors_email: Vec<String>,
}

#[tracing::instrument]
pub async fn verify_name_start(
    fpr: Fingerprint,
    auth_system: &AuthSystem,
) -> Result<(String, AuthChallengeCookie), CustomError> {
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
    auth_state: Option<String>,
    auth_response: &str,
    auth_challenge_cookie: AuthChallengeCookie,
    auth_system: &AuthSystem,
    token_key: &TokenKey,
    expiration_config: &ExpirationConfig,
) -> Result<(Vec<SignedNameVerificationToken>, Vec<SignedEmailVerificationToken>), CustomError> {
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