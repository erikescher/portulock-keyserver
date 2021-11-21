/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use core::iter;
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::ops::Not;

use sequoia_openpgp::cert::amalgamation::key::{PrimaryKeyAmalgamation, SubordinateKeyAmalgamation};
use sequoia_openpgp::cert::amalgamation::{ComponentAmalgamation, UserAttributeAmalgamation, UserIDAmalgamation};
use sequoia_openpgp::crypto::hash::Digest;
use sequoia_openpgp::packet::key::{PrimaryRole, PublicParts};
use sequoia_openpgp::packet::{Key, Signature, Tag, Unknown, UserAttribute, UserID};
use sequoia_openpgp::types::HashAlgorithm;
use sequoia_openpgp::{Cert, KeyHandle, Packet};

use crate::errors::CustomError;
use crate::filtering::applier::{KeyFilter, KeyFilterApplier};

pub struct KeyFilterStrippingBadSigs {}

impl KeyFilter for KeyFilterStrippingBadSigs {
    fn name(&self) -> String {
        "KeyFilterStrippingBadSigs".into()
    }

    fn filter_badsigs(&mut self, _badsig: &Signature) -> Vec<Packet> {
        vec![]
    }
}

pub struct KeyFilterMinimizingPrimary {}

impl KeyFilter for KeyFilterMinimizingPrimary {
    fn name(&self) -> String {
        "KeyFilterMinimizingPrimary".into()
    }

    fn filter_primary(&mut self, pka: PrimaryKeyAmalgamation<PublicParts>) -> Vec<Packet> {
        vec![pka.key().clone().into()]
    }
}

pub struct KeyFilterStrippingUserids {}

impl KeyFilter for KeyFilterStrippingUserids {
    fn name(&self) -> String {
        "KeyFilterStrippingUserIDs".into()
    }

    fn filter_uids(&mut self, _uida: ComponentAmalgamation<UserID>) -> Vec<Packet> {
        vec![]
    }
}

pub struct KeyFilterStrippingUserAttributes {}

impl KeyFilter for KeyFilterStrippingUserAttributes {
    fn name(&self) -> String {
        "KeyFilterStrippingUserAttributes".into()
    }

    fn filter_uas(&mut self, _uaa: ComponentAmalgamation<UserAttribute>) -> Vec<Packet> {
        vec![]
    }
}

pub struct KeyFilterStrippingSubkeys {}

impl KeyFilter for KeyFilterStrippingSubkeys {
    fn name(&self) -> String {
        "KeyFilterStrippingSubkeys".into()
    }

    fn filter_subkeys(&mut self, _suba: SubordinateKeyAmalgamation<PublicParts>) -> Vec<Packet> {
        vec![]
    }
}

pub struct KeyFilterStrippingUnknowns {}

impl KeyFilter for KeyFilterStrippingUnknowns {
    fn name(&self) -> String {
        "KeyFilterStrippingUnknowns".into()
    }

    fn filter_unknowns(&mut self, _unknowna: ComponentAmalgamation<Unknown>) -> Vec<Packet> {
        vec![]
    }
}

pub struct KeyFilterMinimizingKey {}

impl KeyFilter for KeyFilterMinimizingKey {
    fn name(&self) -> String {
        "KeyFilterMinimizingKey".into()
    }

    fn filter_primary(&mut self, pka: PrimaryKeyAmalgamation<PublicParts>) -> Vec<Packet> {
        vec![pka.key().clone().into()]
    }

    fn filter_uids(&mut self, _uida: ComponentAmalgamation<UserID>) -> Vec<Packet> {
        vec![]
    }

    fn filter_uas(&mut self, _uaa: ComponentAmalgamation<UserAttribute>) -> Vec<Packet> {
        vec![]
    }

    fn filter_subkeys(&mut self, _suba: SubordinateKeyAmalgamation<PublicParts>) -> Vec<Packet> {
        vec![]
    }

    fn filter_unknowns(&mut self, _unknowna: ComponentAmalgamation<Unknown>) -> Vec<Packet> {
        vec![]
    }

    fn filter_badsigs(&mut self, _badsig: &Signature) -> Vec<Packet> {
        vec![]
    }
}

pub struct KeyFilterSubtractingPackets {
    existing_packets: HashSet<Packet>,
}

impl KeyFilterSubtractingPackets {
    pub fn from_key(cert_to_subtract: &Cert) -> Self {
        KeyFilterSubtractingPackets::from_packets(cert_to_subtract.clone().into_packets())
    }

    pub fn from_packets(packets: impl Iterator<Item = Packet>) -> Self {
        KeyFilterSubtractingPackets {
            existing_packets: packets.collect(),
        }
    }

    #[allow(clippy::mutable_key_type)]
    pub fn from_hashset(hashset: HashSet<Packet>) -> Self {
        Self {
            existing_packets: hashset,
        }
    }
}

impl KeyFilter for KeyFilterSubtractingPackets {
    fn name(&self) -> String {
        "KeyFilterSubtractingPackets".into()
    }

    fn description(&self) -> Option<String> {
        Some(format!("packets to subtract: {:?}", self.existing_packets))
    }

    fn filter_all_packets(&mut self, packets: impl Iterator<Item = Packet>) -> Vec<Packet> {
        packets
            .filter(|p: &Packet| self.existing_packets.contains(p).not() || p.tag() == Tag::PublicKey)
            .collect()
    }
}

pub struct KeyFilterValidatingSelfSignatures {}

impl KeyFilter for KeyFilterValidatingSelfSignatures {
    fn name(&self) -> String {
        "KeyFilterValidatingSelfSignatures".into()
    }

    fn filter_cert(&mut self, cert: Cert) -> Cert {
        cert.clone()
            .retain_user_attributes(|uaa: UserAttributeAmalgamation| {
                verify_self_signature_on_amalgamation(&uaa, &cert, |mut s, pk, c| {
                    s.verify_user_attribute_binding(pk, pk, c)
                })
            })
            .retain_userids(|uida: UserIDAmalgamation| {
                verify_self_signature_on_amalgamation(&uida, &cert, |mut s, pk, c| s.verify_userid_binding(pk, pk, c))
            })
            .retain_subkeys(|suba: SubordinateKeyAmalgamation<'_, PublicParts>| {
                let suba = suba.component_amalgamation();
                verify_self_signature_on_amalgamation(suba, &cert, |mut s, pk, c| s.verify_subkey_binding(pk, pk, c))
            })
    }

    // NOTE: Unknown component amalgamations are currently not verified and simply passed through.
    //       Sequoia does not offer a suitable function for verifying them.
}

fn verify_self_signature_on_amalgamation<F, C>(
    component_amalgamation: &ComponentAmalgamation<C>,
    cert: &Cert,
    func: F,
) -> bool
where
    F: Fn(Signature, &Key<PublicParts, PrimaryRole>, &C) -> Result<(), anyhow::Error>,
{
    for ss in component_amalgamation.self_signatures() {
        if func(ss.clone(), &cert.primary_key(), component_amalgamation.component()).is_ok() {
            return true;
        }
    }
    false
}

pub struct KeyFilterWhitelistedCertifications {
    cache: HashMap<String, Key<PublicParts, PrimaryRole>>,
}

impl KeyFilterWhitelistedCertifications {
    pub fn new(certs: impl Iterator<Item = Cert>) -> Self {
        let mut filter = KeyFilterWhitelistedCertifications { cache: HashMap::new() };
        filter.seed(certs);
        filter
    }

    pub fn seed(&mut self, certs: impl Iterator<Item = Cert>) {
        for cert in certs {
            self.cache.insert(
                KeyHandle::Fingerprint(cert.fingerprint()).to_hex(),
                cert.primary_key().key().clone(),
            );
            self.cache.insert(
                KeyHandle::KeyID(cert.keyid()).to_hex(),
                cert.primary_key().key().clone(),
            );
        }
    }

    fn certs_for_keyhandles(&self, keyhandles: Vec<KeyHandle>) -> Vec<Key<PublicParts, PrimaryRole>> {
        keyhandles
            .into_iter()
            .filter_map(|kh: KeyHandle| self.cache.get(kh.to_hex().as_str()))
            .collect::<Vec<&Key<PublicParts, PrimaryRole>>>()
            .into_iter()
            .cloned()
            .collect()
    }

    fn finish<A>(
        component: ComponentAmalgamation<A>,
        other_sigs: Vec<&Signature>,
        component_packet: Packet,
    ) -> Vec<Packet> {
        iter::empty()
            .chain(component.self_signatures())
            .chain(component.self_revocations())
            .chain(other_sigs)
            .map(|s: &Signature| -> Packet { s.clone().into() })
            .chain(component_packet)
            .collect()
    }
}

impl KeyFilter for KeyFilterWhitelistedCertifications {
    fn name(&self) -> String {
        "KeyFilterValidatingSelfSignatures".into()
    }

    fn description(&self) -> Option<String> {
        Some(format!("whitelisted certificates: {:?}", self.cache))
    }

    fn filter_primary(&mut self, component: PrimaryKeyAmalgamation<PublicParts>) -> Vec<Packet> {
        let mut validated_certifications = vec![];
        for sig in component.certifications() {
            for key in &self.certs_for_keyhandles(sig.get_issuers()) {
                if sig.clone().verify_direct_key(key, component.key()).is_ok() {
                    validated_certifications.push(sig);
                    break;
                }
            }
        }
        validated_certifications.append(&mut component.component_amalgamation().other_revocations().collect());
        KeyFilterWhitelistedCertifications::finish(
            component.component_amalgamation().clone(),
            validated_certifications,
            component.component().clone().into(),
        )
    }

    fn filter_uids(&mut self, component: ComponentAmalgamation<UserID>) -> Vec<Packet> {
        let mut validated_certifications = vec![];
        for sig in component.certifications() {
            for key in &self.certs_for_keyhandles(sig.get_issuers()) {
                if sig
                    .clone()
                    .verify_userid_binding(key, component.cert().primary_key().key(), component.component())
                    .is_ok()
                {
                    validated_certifications.push(sig);
                    break;
                }
            }
        }
        for sig in component.certifications() {
            for key in &self.certs_for_keyhandles(sig.get_issuers()) {
                if sig
                    .clone()
                    .verify_userid_revocation(key, component.cert().primary_key().key(), component.component())
                    .is_ok()
                {
                    validated_certifications.push(sig);
                    break;
                }
            }
        }
        KeyFilterWhitelistedCertifications::finish(
            component.clone(),
            validated_certifications,
            component.component().clone().into(),
        )
    }

    fn filter_uas(&mut self, component: ComponentAmalgamation<UserAttribute>) -> Vec<Packet> {
        let mut validated_certifications = vec![];
        for sig in component.certifications() {
            for key in &self.certs_for_keyhandles(sig.get_issuers()) {
                if sig
                    .clone()
                    .verify_user_attribute_binding(key, component.cert().primary_key().key(), component.component())
                    .is_ok()
                {
                    validated_certifications.push(sig);
                    break;
                }
            }
        }
        for sig in component.certifications() {
            for key in &self.certs_for_keyhandles(sig.get_issuers()) {
                if sig
                    .clone()
                    .verify_user_attribute_revocation(key, component.cert().primary_key().key(), component.component())
                    .is_ok()
                {
                    validated_certifications.push(sig);
                    break;
                }
            }
        }
        KeyFilterWhitelistedCertifications::finish(
            component.clone(),
            validated_certifications,
            component.component().clone().into(),
        )
    }
}

pub struct KeyFilterAttestedCertifications {}

impl KeyFilter for KeyFilterAttestedCertifications {
    fn name(&self) -> String {
        "KeyFilterAttestedCertifications".into()
    }

    fn filter_cert(&mut self, cert: Cert) -> Cert {
        #[allow(clippy::mutable_key_type)]
        let mut packets_blacklist = HashSet::new();
        for uida in cert.userids() {
            let map = get_attested_hashes(&uida);
            for certification in uida.certifications() {
                if !check_certification_attested(certification, &map) {
                    let packet = Packet::from(certification.clone());
                    packets_blacklist.insert(packet);
                }
            }
        }
        KeyFilterApplier::from(cert)
            .apply(KeyFilterSubtractingPackets::from_hashset(packets_blacklist))
            .into()
    }
}

fn get_attested_hashes<'a>(uida: &'a UserIDAmalgamation) -> HashMap<HashAlgorithm, HashSet<&'a [u8]>> {
    let mut active_attestation_signatures = vec![];
    match uida.attestations().next() {
        None => {}
        Some(first_attestation_signature) => {
            for attestation_signature in uida.attestations() {
                if attestation_signature.signature_creation_time()
                    == first_attestation_signature.signature_creation_time()
                {
                    active_attestation_signatures.push(attestation_signature)
                }
            }
        }
    }

    let mut map: HashMap<HashAlgorithm, HashSet<&[u8]>> = HashMap::new();
    for attestation_key_signature in active_attestation_signatures {
        let algo = attestation_key_signature.hash_algo();
        let mut new_hashset = HashSet::new();
        let hashset = match map.get_mut(&algo) {
            None => &mut new_hashset,
            Some(hashset) => hashset,
        };
        if let Ok(hashes) = attestation_key_signature.attested_certifications() {
            for hash in hashes {
                hashset.insert(hash);
            }
        }
    }
    map
}

fn calculate_attestation_hash(certification: &Signature, hash_algo: &HashAlgorithm) -> Result<Vec<u8>, CustomError> {
    let mut hash = hash_algo.context()?;
    certification.hash_for_confirmation(&mut hash);
    Ok(hash.into_digest()?)
}

fn check_certification_attested(
    certification: &Signature,
    attested_hashes: &HashMap<HashAlgorithm, HashSet<&[u8]>>,
) -> bool {
    for (hash_algo, hashset) in attested_hashes.iter() {
        let actual_hash = match calculate_attestation_hash(certification, hash_algo) {
            Ok(h) => h,
            Err(_) => return false,
        };
        if hashset.contains(actual_hash.as_slice()) {
            return true;
        }
    }
    false
}

pub struct KeyFilterUIDsMatchingNames {
    names: HashSet<String>,
}

impl KeyFilterUIDsMatchingNames {
    pub fn new(names: Vec<String>) -> Self {
        KeyFilterUIDsMatchingNames {
            names: HashSet::from_iter(names),
        }
    }
}

impl KeyFilter for KeyFilterUIDsMatchingNames {
    fn name(&self) -> String {
        "KeyFilterUIDsMatchingNames".into()
    }

    fn description(&self) -> Option<String> {
        Some(format!("names: {:?}", self.names))
    }

    fn filter_cert(&mut self, cert: Cert) -> Cert {
        cert.retain_userids(|uida: UserIDAmalgamation| {
            let uid = uida.component();
            match uid.name() {
                Ok(o) => match o {
                    None => true,
                    Some(n) => self.names.contains(n.as_str()),
                },
                Err(_) => false,
            }
        })
    }
}

pub struct KeyFilterUIDsMatchingEmails {
    emails: HashSet<String>,
}

impl KeyFilterUIDsMatchingEmails {
    pub fn new(emails: Vec<String>) -> Self {
        KeyFilterUIDsMatchingEmails {
            emails: HashSet::from_iter(emails),
        }
    }
}

impl KeyFilter for KeyFilterUIDsMatchingEmails {
    fn name(&self) -> String {
        "KeyFilterUIDsMatchingEmails".into()
    }

    fn description(&self) -> Option<String> {
        Some(format!("emails: {:?}", self.emails))
    }

    fn filter_cert(&mut self, cert: Cert) -> Cert {
        cert.retain_userids(|uida: UserIDAmalgamation| {
            let uid = uida.component();
            match uid.email() {
                Ok(o) => match o {
                    None => true,
                    Some(e) => self.emails.contains(e.as_str()),
                },
                Err(_) => false,
            }
        })
    }
}

pub struct KeyFilterSubtractingUserIDs {
    uids: HashSet<UserID>,
}

impl KeyFilterSubtractingUserIDs {
    pub fn from_cert(cert: &Cert) -> Self {
        #[allow(clippy::mutable_key_type)]
        let uids = cert.userids().map(|uida| uida.userid().clone()).collect();
        Self { uids }
    }
}

impl KeyFilter for KeyFilterSubtractingUserIDs {
    fn name(&self) -> String {
        "KeyFilterSubtractingUserIDs".into()
    }

    fn description(&self) -> Option<String> {
        Some(format!("uids: {:?}", self.uids))
    }

    fn filter_cert(&mut self, cert: Cert) -> Cert {
        cert.retain_userids(|uida| !self.uids.contains(uida.userid()))
    }
}
