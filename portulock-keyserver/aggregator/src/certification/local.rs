/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::str::FromStr;

use async_trait::async_trait;
use sequoia_openpgp::crypto::KeyPair;
use sequoia_openpgp::packet::UserID;
use sequoia_openpgp::types::SignatureType;
use sequoia_openpgp::Cert;
use serde::de::{Error, Unexpected};
use serde::{Deserialize, Deserializer};

use crate::certification::{Certifier, CertifierFactory};

#[derive(Clone, Debug, Deserialize)]
pub struct LocalCertifier {
    #[serde(deserialize_with = "deserialize_cert")]
    certification_key: Cert,
}

impl LocalCertifier {
    fn get_keypair(&self) -> KeyPair {
        cert_to_keypair(self.certification_key.clone())
    }

    fn try_certify(&self, cert: Cert, userid: &UserID) -> Result<Cert, anyhow::Error> {
        let mut signer = self.get_keypair();
        let certification = userid.certify(
            &mut signer,
            &cert,
            Some(SignatureType::GenericCertification),
            None,
            None,
        )?;
        cert.insert_packets(certification)
    }
}

impl CertifierFactory for LocalCertifier {
    fn get_certifier(&self) -> &dyn Certifier {
        self
    }
}

#[async_trait]
impl Certifier for LocalCertifier {
    async fn certify(&self, cert: Cert, userid: &UserID) -> Cert {
        self.try_certify(cert.clone(), userid).unwrap_or(cert)
    }
}

fn cert_to_keypair(cert: Cert) -> KeyPair {
    let key = cert
        .keys()
        .unencrypted_secret()
        .next()
        .expect("No secret keys contained")
        .key();
    key.clone().into_keypair().expect("Key generation failed elsewhere")
}

pub fn deserialize_cert<'de, D>(deserializer: D) -> Result<Cert, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(deserializer)?;
    Cert::from_str(s).map_err(|_| D::Error::invalid_value(Unexpected::Str(s), &"an ASCII armored OpenPGP Certificate"))
}
