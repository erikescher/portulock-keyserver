/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::marker::PhantomData;

use jsonwebtoken::{Header, Validation};
use serde::{Deserialize, Serialize};
use shared::errors::CustomError;

use crate::db::EmailVerificationChallenge;
use crate::utils_verifier::expiration::ExpirationConfig;
use crate::verification::TokenKey;

pub mod oidc_verification;

#[derive(Debug)]
pub struct SignedEmailVerificationToken {
    data: String,
}

impl SignedEmailVerificationToken {
    pub fn verify(&self, token_key: &TokenKey) -> Result<EmailVerificationToken, CustomError> {
        let validation = Validation {
            validate_nbf: true,
            algorithms: vec![token_key.algorithm()],
            ..Validation::default()
        };
        Ok(jsonwebtoken::decode(self.data.as_str(), &token_key.decoding_key(), &validation)?.claims)
    }

    pub fn get_data(&self) -> &str {
        self.data.as_str()
    }
}

impl From<String> for SignedEmailVerificationToken {
    fn from(s: String) -> Self {
        SignedEmailVerificationToken { data: s }
    }
}

#[derive(Debug)]
pub struct SignedNameVerificationToken {
    data: String,
}

impl SignedNameVerificationToken {
    pub fn verify(&self, token_key: &TokenKey) -> Result<NameVerificationToken, CustomError> {
        let validation = Validation {
            validate_nbf: true,
            algorithms: vec![token_key.algorithm()],
            ..Validation::default()
        };
        Ok(jsonwebtoken::decode(self.data.as_str(), &token_key.decoding_key(), &validation)?.claims)
    }

    pub fn get_data(&self) -> &str {
        self.data.as_str()
    }
}

impl From<String> for SignedNameVerificationToken {
    fn from(s: String) -> Self {
        SignedNameVerificationToken { data: s }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EmailVerificationToken {
    pub email: String,
    pub fpr: String,
    pub exp: u64,
    pub iat: u64,
    pub nbf: u64,
}

impl EmailVerificationToken {
    pub fn from(challenge: &EmailVerificationChallenge, expiration_config: &ExpirationConfig) -> Self {
        EmailVerificationToken {
            email: challenge.email().to_string(),
            fpr: challenge.fpr().to_string(),
            exp: expiration_config.expiration_u64(),
            iat: ExpirationConfig::current_time_u64(),
            nbf: ExpirationConfig::current_time_u64(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NameVerificationToken {
    pub(crate) name: String,
    pub(crate) fpr: String,
    pub exp: u64,
    pub iat: u64,
    pub nbf: u64,
}

impl NameVerificationToken {
    pub fn sign(&self, token_key: &TokenKey) -> SignedNameVerificationToken {
        SignedNameVerificationToken {
            data: generic_sign(token_key, &self),
        }
    }
}

impl EmailVerificationToken {
    pub fn sign(&self, token_key: &TokenKey) -> SignedEmailVerificationToken {
        SignedEmailVerificationToken {
            data: generic_sign(token_key, &self),
        }
    }
}

pub fn generic_sign<C: Serialize>(token_key: &TokenKey, claim: &C) -> String {
    jsonwebtoken::encode(
        &Header {
            alg: token_key.algorithm(),
            kid: None,
            typ: None,
            cty: None,
            jku: None,
            x5u: None,
            x5t: None,
        },
        claim,
        &token_key.encoding_key(),
    )
    .expect("Token signing should not fail.")
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(transparent)]
pub struct SignedToken<'a, T>
where
    T: Serialize + Deserialize<'a>,
{
    data: String,
    #[serde(skip)]
    payload_type: PhantomData<&'a T>,
}

impl<'a, T> From<String> for SignedToken<'a, T>
where
    T: Serialize + Deserialize<'a>,
{
    fn from(value: String) -> Self {
        SignedToken {
            data: value,
            payload_type: PhantomData,
        }
    }
}

impl<'a, T> SignedToken<'a, T>
where
    T: Serialize + for<'d> Deserialize<'d>,
{
    pub fn verify(&self, token_key: &TokenKey) -> Result<T, CustomError> {
        let validation = Validation {
            validate_nbf: true,
            algorithms: vec![token_key.algorithm()],
            ..Validation::default()
        };
        Ok(jsonwebtoken::decode(self.data.as_str(), &token_key.decoding_key(), &validation)?.claims)
    }

    pub fn get_data(&self) -> &str {
        self.data.as_str()
    }

    pub fn sign(payload: T, token_key: &'a TokenKey) -> SignedToken<T> {
        SignedToken {
            data: generic_sign(token_key, &payload),
            payload_type: PhantomData,
        }
    }
}
