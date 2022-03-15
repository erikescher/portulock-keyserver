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

use crate::db::{
    get_pending_cert, get_stored_revocations, store_verified_email, store_verified_name, EmailVerificationChallenge,
};
use crate::errors::VerifierError;
use crate::key_storage::{certify_and_publish_approved_cert, filter_cert_by_approved_uids, KeyStore};
use crate::submission::Mailer;
use crate::types::Email;
use crate::utils_verifier::expiration::ExpirationConfig;
use crate::verification::tokens::oidc_verification::{OIDCAuthChallenge, OidcVerifier};
use crate::verification::tokens::{
    EmailVerificationToken, NameVerificationToken, SignedEmailVerificationToken, SignedNameVerificationToken,
};
use crate::SubmitterDBConn;

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

pub async fn trigger_certification_and_publishing(
    fpr: &str,
    submitter_db: &SubmitterDBConn,
    keystore: &(impl KeyStore + ?Sized),
) -> Result<(), VerifierError> {
    println!("Triggering Certification and Publishing: fpr={}", fpr);
    let fpr = Fingerprint::from_hex(fpr).map_err(CustomError::from)?;
    let pending_cert = get_pending_cert(submitter_db, &fpr).await?;
    match pending_cert {
        None => {
            println!("No pending Cert found!")
        }
        Some(pending_cert) => {
            println!("Pending Cert found: {:?}", pending_cert);
            let approved_cert = filter_cert_by_approved_uids(submitter_db, pending_cert).await?;
            println!("Found {} approved userids.", approved_cert.userids().len());
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
    pub oidc_config: OpenIDConnectConfig,
}

pub struct OpenIDConnectConfig {
    pub entry: OpenIDConnectConfigEntry,
}

pub struct OpenIDConnectConfigEntry {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub endpoint_url: String,
}

#[tracing::instrument]
pub async fn verify_name_start(
    fpr: Fingerprint,
    oidc_verifier: &OidcVerifier,
) -> Result<(String, AuthChallengeCookie), CustomError> {
    let (auth_url, auth_challenge) = oidc_verifier.get_auth_url();

    let cookie_data = AuthChallengeCookie {
        auth_challenge,
        fpr: fpr.to_string(),
    };
    Ok((auth_url.to_string(), cookie_data))
}

#[tracing::instrument]
pub async fn verify_name_code(
    state: String,
    code: String,
    oidc_verifier: &OidcVerifier,
    auth_challenge_cookie: AuthChallengeCookie,
    token_key: &TokenKey,
    expiration_config: &ExpirationConfig,
) -> Result<(SignedNameVerificationToken, Option<SignedEmailVerificationToken>), CustomError> {
    let auth_challenge: OIDCAuthChallenge = auth_challenge_cookie.auth_challenge;
    let fpr = auth_challenge_cookie.fpr;

    if auth_challenge.get_state() != state.as_str() {
        return Err(CustomError::String(
            "Failed to validate OAuth State parameter!".to_string(),
        ));
    }

    let claims = oidc_verifier
        .verify_token_and_extract_claims(auth_challenge, code.as_str())
        .await?;
    println!("CLAIMS: {:#?}\nFingerprint: {}", claims, fpr);

    let name_token = NameVerificationToken {
        name: claims.name,
        fpr: fpr.clone(),
        exp: expiration_config.expiration_u64(),
        iat: ExpirationConfig::current_time_u64(),
        nbf: ExpirationConfig::current_time_u64() - 1,
    };
    let token = name_token.sign(token_key);
    let email_token = match claims.verified_email {
        None => None,
        Some(email) => {
            let email_token = EmailVerificationToken {
                email,
                fpr,
                exp: expiration_config.expiration_u64(),
                iat: ExpirationConfig::current_time_u64(),
                nbf: ExpirationConfig::current_time_u64() - 1,
            };
            Some(email_token.sign(token_key))
        }
    };

    Ok((token, email_token))
}

#[tracing::instrument]
pub async fn verify_name_confirm(
    name_token: SignedNameVerificationToken,
    email_token: Option<SignedEmailVerificationToken>,
    token_key: &TokenKey,
    submitter_db: &SubmitterDBConn,
    keystore: &(impl KeyStore + ?Sized),
) -> Result<(), VerifierError> {
    let name_token = name_token.verify(token_key)?;

    if let Some(email_token) = email_token {
        let email_token = email_token.verify(token_key)?;
        store_verified_email(
            submitter_db,
            email_token.fpr.as_str(),
            email_token.email.as_str(),
            NaiveDateTime::from_timestamp(email_token.exp as i64, 0),
        )
        .await?;
        if name_token.fpr != email_token.fpr {
            trigger_certification_and_publishing(email_token.fpr.as_str(), submitter_db, keystore).await?;
        }
    }

    store_verified_name(
        submitter_db,
        name_token.fpr.as_str(),
        name_token.name.as_str(),
        NaiveDateTime::from_timestamp(name_token.exp as i64, 0),
    )
    .await?;

    trigger_certification_and_publishing(name_token.fpr.as_str(), submitter_db, keystore).await
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthChallengeCookie {
    auth_challenge: OIDCAuthChallenge,
    fpr: String,
}
