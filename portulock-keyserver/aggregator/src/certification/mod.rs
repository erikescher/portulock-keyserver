/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use async_trait::async_trait;
use local::LocalCertifier;
use sequoia_openpgp::packet::UserID;
use sequoia_openpgp::Cert;
use serde::Deserialize;

#[async_trait]
pub trait Certifier {
    async fn certify(&self, cert: Cert, userid: &UserID) -> Cert;
}

#[derive(Clone, Debug, Deserialize)]
pub enum CertifierConfig {
    Local(LocalCertifier),
}

impl CertifierFactory for CertifierConfig {
    fn get_certifier(&self) -> &dyn Certifier {
        match self {
            CertifierConfig::Local(l) => l.get_certifier(),
        }
    }
}

#[async_trait]
pub trait CertifierFactory {
    fn get_certifier(&self) -> &dyn Certifier;
}

pub mod local;
