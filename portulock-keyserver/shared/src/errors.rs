/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::fmt::{Display, Formatter};

use diesel;

#[derive(Debug, Clone)]
pub enum CustomError {
    String(String),
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
        Self::String(e.to_string())
    }
}

impl From<diesel::result::Error> for CustomError {
    fn from(e: diesel::result::Error) -> Self {
        Self::String(e.to_string())
    }
}

impl From<serde_json::Error> for CustomError {
    fn from(e: serde_json::Error) -> Self {
        Self::String(e.to_string())
    }
}

impl From<reqwest::Error> for CustomError {
    fn from(e: reqwest::Error) -> Self {
        Self::String(e.to_string())
    }
}

impl From<anyhow::Error> for CustomError {
    fn from(e: anyhow::Error) -> Self {
        Self::String(e.to_string())
    }
}

impl From<&str> for CustomError {
    fn from(e: &str) -> Self {
        Self::String(e.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for CustomError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        Self::String(e.to_string())
    }
}

impl From<std::io::Error> for CustomError {
    fn from(e: std::io::Error) -> Self {
        Self::String(e.to_string())
    }
}

impl From<std::string::FromUtf8Error> for CustomError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Self::String(e.to_string())
    }
}

const INTERNAL_SERVER_ERROR: rocket::http::Status = rocket::http::Status {
    code: 500,
    reason: "Unknown client or server error!",
};

impl<'r> rocket::response::Responder<'r> for CustomError {
    fn respond_to(self, request: &rocket::request::Request) -> Result<rocket::Response<'r>, rocket::http::Status> {
        println!("ERROR_RESPONSE: {}", self);
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
