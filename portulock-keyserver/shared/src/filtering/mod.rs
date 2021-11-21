/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use filters::{
    KeyFilterStrippingBadSigs, KeyFilterStrippingUnknowns, KeyFilterStrippingUserAttributes,
    KeyFilterValidatingSelfSignatures,
};
use sequoia_openpgp::cert::amalgamation::UserIDAmalgamation;
use sequoia_openpgp::Cert;

use crate::filtering::applier::KeyFilterApplier;

pub mod applier;
pub mod filters;

pub fn filter_certs(certs: Vec<Cert>) -> Vec<Cert> {
    let mut filtered_certs = vec![];
    for cert in certs {
        filtered_certs.push(filter_cert(&cert));
    }
    filtered_certs
}

pub fn filter_cert(cert: &Cert) -> Cert {
    let cert = cert
        .clone()
        // Private keys might be more trusted by the client and are therefore dangerous.
        .strip_secret_key_material()
        // Schemas are not accepted as part of UserIDs because we currently can't verify control over them.
        .retain_userids(|uida: UserIDAmalgamation| {
            uida.component()
                .uri()
                .unwrap_or_else(|_| Some(String::from("")))
                .is_none()
        })
        // UserIDs currently need to include an email address that can be verified.
        .retain_userids(|uida: UserIDAmalgamation| uida.component().email_normalized().unwrap_or(None).is_some());
    // Names are optional as there may be good reasons to omit them.
    // Comments are currently ignored. They can't generally be verified but are too common to refuse.

    KeyFilterApplier::from(cert)
        // UserAttributes (PhotoIDs) are currently not accepted because verifying them is difficult and they might provide a false sense of security.
        .apply(KeyFilterStrippingUserAttributes {})
        // Valid Self-Signatures are needed on UserIDs and Subkeys.
        // This also verifies Cross-Certification on signing-capable subkeys.
        .apply(KeyFilterValidatingSelfSignatures {})
        // Signatures that don't belong to a component on the key are kind of pointless.
        .apply(KeyFilterStrippingBadSigs {})
        // Unknown Packets will be dropped for now.
        .apply(KeyFilterStrippingUnknowns {})
        .into()
}
