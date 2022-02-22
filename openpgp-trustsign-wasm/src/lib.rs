/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use sequoia_openpgp::packet::signature::SignatureBuilder;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::types::SignatureType;
use sequoia_openpgp::Cert;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn trust_sign(
    private_key: &str,
    ca_public_key: &str,
    domain_scope: Option<String>,
) -> Result<String, JsValue> {
    trust_sign_internal(private_key, ca_public_key, domain_scope)
        .map_err(|e| JsValue::from_str(e.to_string().as_str()))
}

fn trust_sign_internal(
    private_key: &str,
    ca_public_key: &str,
    domain_scope: Option<String>,
) -> Result<String, anyhow::Error> {
    console_error_panic_hook::set_once();

    let mut private_key = Cert::from_str(private_key)?
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()?
        .into_keypair()?;
    let ca_public_key = Cert::from_str(ca_public_key)?;

    let mut signatures: Vec<Signature> = vec![];

    for uida in ca_public_key.userids() {
        let signature_builder = SignatureBuilder::new(SignatureType::GenericCertification);

        let signature = match &domain_scope {
            Some(domain_scope) => {
                let regex_domain = domain_scope.replace('.', "\\.");
                let trust_regex = format!("<[^>]+[@.]{}>$", regex_domain);
                signature_builder
                    .set_trust_signature(1, 120)?
                    .set_regular_expression(trust_regex.as_str())?
            }
            None => signature_builder.set_trust_signature(255, 120)?,
        }
        .sign_userid_binding(
            &mut private_key,
            ca_public_key.primary_key().component(),
            uida.userid(),
        )?;
        signatures.push(signature);
    }

    let ca_public_key = ca_public_key.clone().insert_packets(signatures)?;
    let ca_public_key = ca_public_key.to_vec()?; // ASCII export did not seem to work in WASM before.
    Ok(base64::encode(ca_public_key))
}
