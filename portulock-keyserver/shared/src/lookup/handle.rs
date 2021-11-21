/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::collections::{HashMap, HashSet};

use sequoia_openpgp::{Cert, KeyHandle};

use crate::errors::CustomError;
use crate::filtering::filter_certs;
use crate::lookup::email::lookup_email;
use crate::lookup::keyserver::Keyserver;
use crate::lookup::LookupConfig;
use crate::types::Email;
use crate::utils::maps::map2vec_k;

pub async fn lookup_handle(config: &LookupConfig, handle: &KeyHandle) -> Result<Vec<Cert>, CustomError> {
    // This uses all keyservers to obtain a list of email addresses for the certs before querying the
    // respective authoritative sources for the certs. Data from non-authoritative sources is not relayed.

    let mut certs = Vec::new();
    for keyserver in config.get_all_keyservers() {
        let mut c = keyserver.lookup_locator(handle).await.unwrap_or_default();
        certs.append(&mut c);
    }
    let certs = filter_certs(certs);
    let mut authoritative_certs = vec![];
    for email in find_emails(certs.as_slice()) {
        authoritative_certs.append(&mut lookup_email(config, &email).await.unwrap_or_default());
    }

    Ok(authoritative_certs)
}

fn find_emails(certs: &[Cert]) -> Vec<Email> {
    let mut map = HashSet::new();
    for cert in certs {
        for uida in cert.userids() {
            if let Ok(Some(email)) = uida.component().email_normalized() {
                if let Ok(email) = Email::parse(email.as_str()) {
                    map.insert(email);
                }
            }
        }
    }
    map.drain().collect()
}

impl LookupConfig {
    fn get_all_keyservers(&self) -> Vec<Keyserver> {
        let mut ldc_vectors = Vec::new();
        ldc_vectors.append(&mut self.special_domains.values().collect());
        for ldc in &self.fallbacks {
            ldc_vectors.push(ldc)
        }
        let mut map = HashMap::new();
        for ldc in ldc_vectors {
            if ldc.use_for_keyhandle_query {
                for ks in &ldc.keyservers {
                    map.insert(ks.clone(), ());
                }
            }
        }
        map2vec_k(map)
    }
}
