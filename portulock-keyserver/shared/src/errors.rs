/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::fmt::{Display, Formatter};

use anyhow::anyhow;
use diesel;
use tracing::{error, info};

#[derive(Debug, Clone)]
pub enum CustomError {
    String(String),
}

impl CustomError {
    pub fn anyhow(error: anyhow::Error) -> Self {
        let string = format!("{:?}", error);
        error!("Created CustomError from anyhow::Error: \n{}", string);
        Self::String(string)
    }
    pub fn str(string: &str) -> Self {
        error!("Created CustomError from String: \n{}", string);
        Self::String(string.to_string())
    }
}

impl Display for CustomError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CustomError::String(s) => {
                write!(f, "{}", s.as_str())
            }
        }
    }
}

impl From<rusqlite::Error> for CustomError {
    fn from(e: rusqlite::Error) -> Self {
        CustomError::anyhow(anyhow!(e))
    }
}

impl From<diesel::result::Error> for CustomError {
    fn from(e: diesel::result::Error) -> Self {
        CustomError::anyhow(anyhow!(e))
    }
}

impl From<serde_json::Error> for CustomError {
    fn from(e: serde_json::Error) -> Self {
        CustomError::anyhow(anyhow!(e))
    }
}

impl From<reqwest::Error> for CustomError {
    fn from(e: reqwest::Error) -> Self {
        CustomError::anyhow(anyhow!(e))
    }
}

impl From<anyhow::Error> for CustomError {
    fn from(e: anyhow::Error) -> Self {
        CustomError::anyhow(anyhow!(e))
    }
}

impl From<&str> for CustomError {
    fn from(e: &str) -> Self {
        CustomError::str(e)
    }
}

impl From<jsonwebtoken::errors::Error> for CustomError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        CustomError::anyhow(anyhow!(e))
    }
}

impl From<std::io::Error> for CustomError {
    fn from(e: std::io::Error) -> Self {
        CustomError::anyhow(anyhow!(e))
    }
}

impl From<std::string::FromUtf8Error> for CustomError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        CustomError::anyhow(anyhow!(e))
    }
}

const INTERNAL_SERVER_ERROR: rocket::http::Status = rocket::http::Status {
    code: 500,
    reason: "Unknown client or server error!",
};

impl<'r> rocket::response::Responder<'r> for CustomError {
    fn respond_to(self, request: &rocket::request::Request) -> Result<rocket::Response<'r>, rocket::http::Status> {
        info!("ERROR_RESPONSE: {}", self);
        let responder = match self {
            //CustomError::String(message) => BadRequest(Some(message)),
            CustomError::String(message) => {
                Some(rocket::response::status::Custom(INTERNAL_SERVER_ERROR, Some(message)))
            }
        };
        match responder {
            Some(r) => Ok(r.respond_to(request).unwrap()),
            None => Err(INTERNAL_SERVER_ERROR),
        }
    }
}
