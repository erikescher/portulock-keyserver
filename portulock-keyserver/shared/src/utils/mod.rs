/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

extern crate sequoia_openpgp as openpgp;

use std::collections::HashMap;

use openpgp::packet::UserID;
use openpgp::{Cert, Fingerprint};

use crate::types::Email;

pub mod armor;
pub mod async_helper;
pub mod maps;
pub mod rocket_helpers;

pub fn merge_certs(certs: Vec<Cert>) -> Vec<Cert> {
    let mut map: HashMap<Fingerprint, Cert> = HashMap::new();
    for cert in certs {
        let fingerprint = cert.fingerprint();
        let new_cert = match map.remove(&fingerprint) {
            None => cert,
            Some(c) => c.clone().merge_public(cert).unwrap_or(c),
        };
        map.insert(fingerprint, new_cert);
    }
    maps::map2vec_v(map)
}

pub fn any_email(cert: &Cert) -> Option<Email> {
    for uida in cert.userids() {
        match uida
            .component()
            .email_normalized()
            .unwrap_or(None)
            .and_then(|e| Email::parse_option(e.as_str()))
        {
            None => {}
            Some(e) => return Some(e),
        }
    }
    None
}

pub fn cert_contains_uid(cert: &Cert, uid: &UserID) -> bool {
    for existing_uida in cert.userids() {
        if existing_uida.component() == uid {
            return true;
        }
    }
    false
}
