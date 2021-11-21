/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::fmt::{Display, Formatter};

use shared::errors::CustomError;

#[derive(Debug)]
pub enum VerifierError {
    CustomError(CustomError),
    String(String),
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
        Self::String(s.to_string())
    }
}

impl From<String> for VerifierError {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<CustomError> for VerifierError {
    fn from(c: CustomError) -> Self {
        Self::CustomError(c)
    }
}

impl From<VerifierError> for CustomError {
    fn from(v: VerifierError) -> Self {
        CustomError::String(v.to_string())
    }
}

impl From<lettre::transport::smtp::Error> for VerifierError {
    fn from(e: lettre::transport::smtp::Error) -> Self {
        Self::String(e.to_string())
    }
}

impl From<lettre::error::Error> for VerifierError {
    fn from(e: lettre::error::Error) -> Self {
        Self::String(e.to_string())
    }
}

impl From<lettre::address::AddressError> for VerifierError {
    fn from(e: lettre::address::AddressError) -> Self {
        Self::String(e.to_string())
    }
}

impl From<diesel::result::Error> for VerifierError {
    fn from(e: diesel::result::Error) -> Self {
        Self::String(e.to_string())
    }
}

impl From<rocket::http::uri::Error<'_>> for VerifierError {
    fn from(e: rocket::http::uri::Error) -> Self {
        Self::String(e.to_string())
    }
}

impl From<openidconnect::url::ParseError> for VerifierError {
    fn from(e: openidconnect::url::ParseError) -> Self {
        Self::String(e.to_string())
    }
}
