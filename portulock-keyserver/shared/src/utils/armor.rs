/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::io::Write;
use std::str::FromStr;

use sequoia_openpgp::armor::{Kind, Writer};
use sequoia_openpgp::cert::Cert;
use sequoia_openpgp::cert::CertParser;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::PacketPile;

use super::openpgp::parse::Parse;
use super::openpgp::serialize::{Serialize, SerializeInto};
use crate::errors::CustomError;

pub fn export_armored_cert(cert: &sequoia_openpgp::Cert) -> String {
    let serialized_certifications = cert.armored().export_to_vec().expect("Export failed");
    String::from_utf8(serialized_certifications)
        .expect("Failed to create String from UFT-8 due to UTF-8 Formatting Failure.")
}

pub fn export_armored_cert_including_secret_keys(cert: &sequoia_openpgp::Cert) -> String {
    let serialized_certifications = cert.as_tsk().armored().export_to_vec().expect("Export failed");
    String::from_utf8(serialized_certifications)
        .expect("Failed to create String from UFT-8 due to UTF-8 Formatting Failure.")
}

pub fn export_armored_certs(certs: &[sequoia_openpgp::Cert]) -> Result<String, anyhow::Error> {
    let mut collected_packets = Vec::new();
    for cert in certs {
        let mut packets = cert.clone().into_packets().collect();
        collected_packets.append(&mut packets);
    }

    let vec = PacketPile::from(collected_packets).export_to_vec()?;

    let mut writer = Writer::new(Vec::new(), Kind::PublicKey)?;
    writer.write_all(vec.as_slice())?;
    let vec = writer.finalize()?;

    Ok(String::from_utf8(vec)?)
}

pub fn parse_certs(armored_certs: &str) -> Result<Vec<Cert>, CustomError> {
    // We simply ignore any packets that can't be parsed.
    // Aborting and returning an Error to the user would not be helpful and logging it somewhere is likely pointless as well.
    Ok(CertParser::from_bytes(armored_certs.as_bytes())?.flatten().collect())
}

pub fn certificate_from_str(cert: &str) -> Cert {
    Cert::from_str(cert).unwrap_or_else(|_| panic!("Failed to parse <{}> as Cert!", cert))
}

pub fn certification_key_from_str(certification_key: &str) -> Cert {
    let certification_key = certificate_from_str(certification_key);

    // Check that the key is suitable for certification.
    certification_key
        .keys()
        .unencrypted_secret()
        .with_policy(&StandardPolicy::default(), None)
        .alive()
        .revoked(false)
        .for_certification()
        .next()
        .unwrap_or_else(|| {
            panic!(
                "No certification capable key found on key with fingerprint {}",
                certification_key.fingerprint()
            )
        });

    certification_key
}

pub fn armor_packet(packet: sequoia_openpgp::Packet) -> Result<String, CustomError> {
    let mut writer = Writer::new(vec![], Kind::Signature)?;
    packet.serialize(&mut writer)?;
    let bytes = writer.finalize()?;
    Ok(String::from_utf8(bytes)?)
}

pub fn armor_signature(signature: sequoia_openpgp::packet::Signature) -> Result<String, CustomError> {
    use super::openpgp::serialize::Marshal;
    let mut writer = Writer::new(vec![], Kind::Signature)?;
    signature.serialize(&mut writer)?;
    let bytes = writer.finalize()?;
    Ok(String::from_utf8(bytes)?)
}
