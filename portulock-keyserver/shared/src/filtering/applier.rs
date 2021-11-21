/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use core::iter;
use std::convert::TryFrom;

use sequoia_openpgp::cert::amalgamation::key::{PrimaryKeyAmalgamation, SubordinateKeyAmalgamation};
use sequoia_openpgp::cert::amalgamation::ComponentAmalgamation;
use sequoia_openpgp::packet::key::PublicParts;
use sequoia_openpgp::packet::{Signature, Unknown, UserAttribute, UserID};
use sequoia_openpgp::{Cert, Packet};

use crate::filtering::filters::KeyFilterMinimizingKey;

pub trait KeyFilter {
    fn name(&self) -> String;

    fn description(&self) -> Option<String> {
        None
    }

    fn filter_primary(&mut self, primary: PrimaryKeyAmalgamation<PublicParts>) -> Vec<Packet> {
        iter::once(primary.key().clone().into())
            .chain(noop_filter_component(&primary))
            .collect()
    }

    fn filter_uids(&mut self, uida: ComponentAmalgamation<UserID>) -> Vec<Packet> {
        iter::once(uida.component().clone().into())
            .chain(noop_filter_component(&uida))
            .collect()
    }

    fn filter_uas(&mut self, uaa: ComponentAmalgamation<UserAttribute>) -> Vec<Packet> {
        iter::once(uaa.component().clone().into())
            .chain(noop_filter_component(&uaa))
            .collect()
    }

    fn filter_subkeys(&mut self, suba: SubordinateKeyAmalgamation<PublicParts>) -> Vec<Packet> {
        iter::once(suba.component().clone().into())
            .chain(noop_filter_component(&suba))
            .collect()
    }

    fn filter_unknowns(&mut self, unknowna: ComponentAmalgamation<Unknown>) -> Vec<Packet> {
        iter::once(unknowna.component().clone().into())
            .chain(noop_filter_component(&unknowna))
            .collect()
    }

    fn filter_badsigs(&mut self, badsig: &Signature) -> Vec<Packet> {
        vec![badsig.clone().into()]
    }

    fn filter_all_packets(&mut self, packets: impl Iterator<Item = Packet>) -> Vec<Packet> {
        packets.collect()
    }

    fn filter_cert(&mut self, cert: Cert) -> Cert {
        cert
    }
}

pub struct KeyFilterApplier {
    cert: Cert,
}

impl KeyFilterApplier {
    pub fn apply(self, mut filter: impl KeyFilter) -> KeyFilterApplier {
        let mut packets = vec![];
        let cert = &self.cert;

        // Primary key and related signatures.
        packets.append(&mut filter.filter_primary(cert.primary_key()));

        // UserIDs and related signatures.
        for c in cert.userids() {
            packets.append(&mut filter.filter_uids(c));
        }

        // UserAttributes and related signatures.
        for c in cert.user_attributes() {
            packets.append(&mut filter.filter_uas(c))
        }

        // Subkeys and related signatures.
        for c in cert.keys().subkeys() {
            packets.append(&mut filter.filter_subkeys(c))
        }

        // Unknown components and related signatures.
        for c in cert.unknowns() {
            packets.append(&mut filter.filter_unknowns(c))
        }

        // Any signatures that we could not associate with a component.
        for s in cert.bad_signatures() {
            packets.append(&mut filter.filter_badsigs(s))
        }

        let packets = filter.filter_all_packets(packets.into_iter());

        let cert = KeyFilterApplier::packets_to_cert(packets);

        let cert = filter.filter_cert(cert);

        println!(
            "Applied KeyFilter: {} \n  ({:?})\n  BEFORE: {:?}\n  AFTER: {:?}",
            filter.name(),
            filter.description(),
            self.cert,
            cert
        );

        KeyFilterApplier { cert }
    }

    fn packets_to_cert(packets: Vec<Packet>) -> Cert {
        Cert::try_from(packets).expect("return type is Infallible")
    }

    pub fn any(self, filters: impl Iterator<Item = impl KeyFilter>) -> Self {
        let mut minimal: Cert = KeyFilterApplier::from(self.cert.clone())
            .apply(KeyFilterMinimizingKey {})
            .into();
        for filter in filters {
            let filtered = KeyFilterApplier::from(self.cert.clone()).apply(filter).into();
            minimal = minimal
                .merge_public(filtered)
                .expect("Primary Keys are identical by construction.");
        }
        KeyFilterApplier { cert: minimal }
    }

    pub fn all(self, filters: impl Iterator<Item = impl KeyFilter>) -> Self {
        let mut new_self = self;
        for filter in filters {
            new_self = new_self.apply(filter)
        }
        new_self
    }
}

impl From<Cert> for KeyFilterApplier {
    fn from(cert: Cert) -> Self {
        KeyFilterApplier { cert }
    }
}

impl From<KeyFilterApplier> for Cert {
    fn from(cf: KeyFilterApplier) -> Self {
        cf.cert
    }
}

fn noop_filter_component<'a, A>(component: &'a ComponentAmalgamation<A>) -> impl Iterator<Item = Packet> + 'a {
    iter::empty()
        .chain(component.self_signatures())
        .chain(component.certifications())
        .chain(component.self_revocations())
        .chain(component.other_revocations())
        .map(|s: &Signature| -> Packet { s.clone().into() })
}
