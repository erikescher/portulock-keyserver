/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use sequoia_net::{KeyServer, Policy};
use sequoia_openpgp::{Cert, KeyHandle};

use crate::errors::CustomError;
use crate::types::Email;

#[derive(Clone, Eq, Debug)]
pub struct Keyserver {
    pub url: String,
}

impl Keyserver {
    pub async fn lookup_email(&self, email: &Email) -> Result<Vec<Cert>, CustomError> {
        self.get_keyserver()?.search(email).await.map_err(CustomError::from)
    }

    pub async fn lookup_locator(&self, handle: &KeyHandle) -> Result<Vec<Cert>, CustomError> {
        self.get_keyserver()?
            .get(handle.clone())
            .await
            .map_err(CustomError::from)
            .map(|c| vec![c])
    }

    fn get_keyserver(&self) -> Result<KeyServer, CustomError> {
        Ok(sequoia_net::KeyServer::new(Policy::Encrypted, self.url.as_str())?)
    }
}

impl PartialEq for Keyserver {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url
    }
}

impl std::hash::Hash for Keyserver {
    fn hash<H>(&self, state: &mut H)
    where
        H: std::hash::Hasher,
    {
        self.url.hash(state)
    }
}
