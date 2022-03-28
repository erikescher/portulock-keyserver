/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use sequoia_openpgp::cert::amalgamation::UserIDAmalgamation;
use sequoia_openpgp::Cert;

pub struct CertWithSingleUID {
    cert: Cert,
}

impl CertWithSingleUID {
    pub fn new(cert: Cert) -> Option<Self> {
        match cert.userids().len() == 1 {
            true => Some(CertWithSingleUID { cert }),
            false => None,
        }
    }

    pub fn userid(&self) -> UserIDAmalgamation {
        self.cert
            .userids()
            .next()
            .expect("Contains exactly one UID by construction.")
    }

    pub fn cert(&self) -> &Cert {
        &self.cert
    }

    pub fn iterate_over_cert(cert: &Cert) -> Vec<CertWithSingleUID> {
        let mut certs = vec![];
        for uida in cert.userids() {
            certs.push(
                CertWithSingleUID::new(cert.clone().retain_userids(|a| uida == a))
                    .expect("Only contains one UID by construction."),
            );
        }
        certs
    }
}

impl From<CertWithSingleUID> for Cert {
    fn from(cert_holder: CertWithSingleUID) -> Self {
        cert_holder.cert
    }
}
