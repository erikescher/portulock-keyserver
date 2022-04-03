/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::fmt::{Display, Formatter};

use anyhow::anyhow;
use openssl::error::ErrorStack;
use reqwest::Error;
use samael::metadata::de::DeError;
use shared::errors::CustomError;
use tracing::error;

#[derive(Debug)]
pub enum VerifierError {
    CustomError(CustomError),
    String(String),
}

impl VerifierError {
    fn anyhow(error: anyhow::Error) -> Self {
        let string = format!("{:?}", error);
        error!("Created VerifierError from anyhow::Error: \n{}", string);
        Self::String(string)
    }
    fn str(string: &str) -> Self {
        error!("Created VerifierError from String: \n{}", string);
        Self::String(string.to_string())
    }
    fn custom(error: CustomError) -> Self {
        error!("Created VerifierError from CustomError: \n{}", error);
        Self::CustomError(error)
    }
}

impl Display for VerifierError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifierError::String(s) => write!(f, "{}", s.as_str()),
            VerifierError::CustomError(c) => c.fmt(f),
        }
    }
}

impl From<&str> for VerifierError {
    fn from(s: &str) -> Self {
        VerifierError::str(s)
    }
}

impl From<String> for VerifierError {
    fn from(s: String) -> Self {
        VerifierError::str(s.as_str())
    }
}

impl From<CustomError> for VerifierError {
    fn from(c: CustomError) -> Self {
        VerifierError::custom(c)
    }
}

impl From<VerifierError> for CustomError {
    fn from(v: VerifierError) -> Self {
        match v {
            VerifierError::CustomError(e) => e,
            VerifierError::String(s) => CustomError::str(s.as_str()),
        }
    }
}

impl From<Box<dyn std::error::Error>> for VerifierError {
    fn from(e: Box<dyn serde::de::StdError>) -> Self {
        Self::str(format!("std::error::Error: {:?}", e.as_ref()).as_str())
    }
}

impl From<reqwest::Error> for VerifierError {
    fn from(e: Error) -> Self {
        VerifierError::anyhow(anyhow!(e))
    }
}

impl From<DeError> for VerifierError {
    fn from(e: DeError) -> Self {
        VerifierError::anyhow(anyhow!(e))
    }
}

impl From<ErrorStack> for VerifierError {
    fn from(e: ErrorStack) -> Self {
        VerifierError::anyhow(anyhow!(e))
    }
}

impl From<samael::service_provider::ServiceProviderBuilderError> for VerifierError {
    fn from(e: samael::service_provider::ServiceProviderBuilderError) -> Self {
        VerifierError::anyhow(anyhow!(e))
    }
}

impl From<lettre::transport::smtp::Error> for VerifierError {
    fn from(e: lettre::transport::smtp::Error) -> Self {
        VerifierError::anyhow(anyhow!(e))
    }
}

impl From<lettre::error::Error> for VerifierError {
    fn from(e: lettre::error::Error) -> Self {
        VerifierError::anyhow(anyhow!(e))
    }
}

impl From<lettre::address::AddressError> for VerifierError {
    fn from(e: lettre::address::AddressError) -> Self {
        VerifierError::anyhow(anyhow!(e))
    }
}

impl From<openidconnect::url::ParseError> for VerifierError {
    fn from(e: openidconnect::url::ParseError) -> Self {
        VerifierError::anyhow(anyhow!(e))
    }
}

impl From<anyhow::Error> for VerifierError {
    fn from(e: anyhow::Error) -> Self {
        VerifierError::anyhow(e)
    }
}
