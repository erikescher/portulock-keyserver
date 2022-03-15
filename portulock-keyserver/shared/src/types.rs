/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::fmt::Display;

use sequoia_openpgp::packet::UserID;

use crate::errors::CustomError;

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct Email {
    localpart: String,
    domain: String,
}

impl Email {
    pub fn new(localpart: &str, domain: &str) -> Self {
        Self {
            localpart: localpart.to_string(),
            domain: domain.to_string(),
        }
    }

    pub fn parse(email: &str) -> Result<Self, CustomError> {
        let mut parts = email.split('@');
        let localpart = parts.next().ok_or("Invalid Email Address!")?;
        let domain = parts.next().ok_or("Invalid Email Address!")?;
        match parts.next() {
            Some(_) => Err("Invalid Email Address!".into()),
            None => Ok(Self::new(localpart, domain)),
        }
    }

    pub fn parse_option(email: &str) -> Option<Email> {
        match Self::parse(email) {
            Ok(e) => Some(e),
            Err(_) => None,
        }
    }

    pub fn get_domain(&self) -> &str {
        &self.domain
    }

    pub fn get_email(&self) -> String {
        self.localpart.clone() + "@" + self.get_domain()
    }
}

impl From<Email> for String {
    fn from(e: Email) -> Self {
        e.to_string()
    }
}

impl Display for Email {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.get_email())
    }
}

impl From<&Email> for UserID {
    fn from(e: &Email) -> Self {
        UserID::from_address(None, None, e.to_string()).expect("Unchecked type conversion failed!")
    }
}
