/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use sequoia_net::Policy;
use sequoia_openpgp::{Cert, KeyHandle};
use serde::Deserialize;
use shared::types::Email;

#[derive(Clone, Eq, Debug, Deserialize)]
#[serde(transparent)]
pub struct Keyserver {
    pub url: String,
}

impl Keyserver {
    pub async fn lookup_email(&self, email: &Email) -> Result<Vec<Cert>, anyhow::Error> {
        sequoia_net::KeyServer::new(Policy::Encrypted, self.url.as_str())?
            .search(email)
            .await
    }

    pub async fn lookup_locator(&self, handle: &KeyHandle) -> Result<Cert, anyhow::Error> {
        sequoia_net::KeyServer::new(Policy::Encrypted, self.url.as_str())?
            .get(handle.clone())
            .await
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
