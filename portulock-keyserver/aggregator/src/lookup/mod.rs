/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::collections::HashMap;
use std::str::FromStr;

use anyhow::anyhow;
use sequoia_openpgp::{Cert, Fingerprint, KeyHandle, KeyID};
use serde::de::{Error, Unexpected};
use serde::{Deserialize, Deserializer};
use shared::filtering::filter_certs;
use shared::types::Email;
use shared::utils::merge_certs;

use crate::certification::CertifierConfig;
use crate::lookup::keyserver::Keyserver;

mod email;
mod handle;
pub mod keyserver;

pub async fn lookup(config: &LookupConfig, locator: SearchString) -> Result<Vec<Cert>, anyhow::Error> {
    let certs = match locator {
        SearchString::ByKeyID(k) => {
            handle::lookup_handle(config, &KeyHandle::KeyID(KeyID::from_str(k.as_str())?)).await
        }
        SearchString::ByFingerprint(f) => {
            handle::lookup_handle(config, &KeyHandle::Fingerprint(Fingerprint::from_str(f.as_str())?)).await
        }
        SearchString::ByEmail(e) => email::lookup_email(config, &e).await,
    }?;
    let certs = merge_certs(certs);
    let certs = filter_certs(certs);
    Ok(certs)
}

#[derive(Debug, Deserialize)]
pub struct LookupConfig {
    #[serde(default)]
    pub special_domains: HashMap<String, LookupDomainConfig>,
    #[serde(default)]
    pub fallbacks: HashMap<String, LookupDomainConfig>,
}

impl LookupConfig {
    fn config_for_domain(&self, domain: &str) -> Option<&LookupDomainConfig> {
        self.special_domains.get(domain)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct LookupDomainConfig {
    #[serde(default)]
    pub keyservers: Vec<Keyserver>,
    #[serde(deserialize_with = "deserialize_cert_vec")]
    #[serde(default)]
    pub expect_one_certification_from: Vec<Cert>,
    #[serde(default)]
    pub email_certifiers: Vec<CertifierConfig>,
    #[serde(default = "default_false")]
    pub use_wkd: bool,
    #[serde(default = "default_false")]
    pub use_for_keyhandle_query: bool,
}

fn default_false() -> bool {
    false
}

pub fn deserialize_cert_vec<'de, D>(deserializer: D) -> Result<Vec<Cert>, D::Error>
where
    D: Deserializer<'de>,
{
    let vec: Vec<&str> = Deserialize::deserialize(deserializer)?;
    let mut certs = vec![];
    for s in vec {
        let cert = Cert::from_str(s)
            .map_err(|_| D::Error::invalid_value(Unexpected::Str(s), &"an ASCII armored OpenPGP Certificate"))?;
        certs.push(cert);
    }
    Ok(certs)
}

#[allow(dead_code)]
pub async fn lookup_by_fpr(lookup_config: &LookupConfig, fpr: &Fingerprint) -> Result<Option<Cert>, anyhow::Error> {
    let locator = SearchString::ByFingerprint(fpr.to_string());
    let mut existing_certs = lookup(lookup_config, locator).await?;
    match existing_certs.len() {
        0 => Ok(None),
        1 => Ok(existing_certs.pop()),
        _ => Err(anyhow!("Fingerprint collision occurred! {}", fpr)),
    }
}

type KeyIDAlias = String;
type FingerprintAlias = String;

#[derive(Debug)]
pub enum SearchString {
    ByKeyID(KeyIDAlias),
    ByFingerprint(FingerprintAlias),
    ByEmail(Email),
}

impl SearchString {
    pub fn from_string(str: &str) -> Result<Self, anyhow::Error> {
        match Email::parse(str) {
            Ok(e) => Ok(SearchString::ByEmail(e)),
            Err(_) => {
                let str = str.to_ascii_uppercase();
                let str = str.trim_start_matches("0X");
                let len = hex::decode(str)
                    .map_err(|_| anyhow!("Expected Fingerprint or KeyID but got invalid hex string."))?
                    .len()
                    * 2;
                match len {
                    8 => Err(anyhow!("32bit KeyIDs are not supported.")),
                    16 => Ok(SearchString::ByKeyID(str.to_string() as KeyIDAlias)),
                    // 32 => Ok(SearchString::ByFingerprint(str.to_string() as Fingerprint)),
                    32 => Err(anyhow!("128bit V3 Fingerprints are not supported")),
                    40 => Ok(SearchString::ByFingerprint(str.to_string() as FingerprintAlias)),
                    _ => Err(anyhow!("Hex string of unexpected length")),
                }
            }
        }
    }

    #[allow(dead_code)]
    pub fn as_url_parameter(&self) -> String {
        match self {
            SearchString::ByKeyID(k) => k.to_string(),
            SearchString::ByFingerprint(f) => f.to_string(),
            SearchString::ByEmail(e) => e.to_string(),
        }
    }
}

impl From<KeyHandle> for SearchString {
    fn from(keyhandle: KeyHandle) -> Self {
        match keyhandle {
            KeyHandle::Fingerprint(f) => SearchString::ByFingerprint(f.to_string()),
            KeyHandle::KeyID(k) => SearchString::ByKeyID(k.to_string()),
        }
    }
}
