/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::str::FromStr;

use chrono::NaiveDateTime;
use diesel::RunQueryDsl;
use diesel::SqliteConnection;
use sequoia_openpgp::Cert;
use shared::utils::armor::export_armored_cert;
use shared::utils::merge_certs;

use crate::certs::CertWithSingleUID;
use crate::db::schema::*;
use crate::utils_verifier::expiration::ExpirationConfig;

#[derive(Debug)]
pub struct PendingCertWithoutUIDs {
    fpr: String,
    pending_cert: Cert,
    exp: NaiveDateTime,
}

#[derive(Queryable, Insertable, Debug)]
#[table_name = "pending_keys"]
struct PendingCertWithoutUIDsEntry {
    fpr: String,
    cert: String,
    exp: NaiveDateTime,
}

impl From<PendingCertWithoutUIDsEntry> for PendingCertWithoutUIDs {
    fn from(entry: PendingCertWithoutUIDsEntry) -> Self {
        PendingCertWithoutUIDs {
            fpr: entry.fpr,
            pending_cert: Cert::from_str(entry.cert.as_str()).expect("Failed to parse Cert from DB!"),
            exp: entry.exp,
        }
    }
}

impl From<PendingCertWithoutUIDs> for PendingCertWithoutUIDsEntry {
    fn from(value: PendingCertWithoutUIDs) -> Self {
        PendingCertWithoutUIDsEntry {
            fpr: value.fpr,
            cert: export_armored_cert(&value.pending_cert),
            exp: value.exp,
        }
    }
}

impl PendingCertWithoutUIDs {
    fn get(connection: &SqliteConnection, fingerprint: &str) -> Result<Vec<Self>, diesel::result::Error> {
        use diesel::{ExpressionMethods, QueryDsl};

        use crate::db::schema::pending_keys::dsl::*;
        let result: Vec<PendingCertWithoutUIDs> = pending_keys
            .filter(fpr.eq(fingerprint.to_string()))
            .load::<PendingCertWithoutUIDsEntry>(connection)?
            .into_iter()
            .filter(|vn: &PendingCertWithoutUIDsEntry| ExpirationConfig::is_valid(vn.exp))
            .map(PendingCertWithoutUIDs::from)
            .filter(|vn: &PendingCertWithoutUIDs| vn.pending_cert.fingerprint().to_hex() == fingerprint)
            .collect();
        Ok(result)
    }

    pub fn get_combined(
        connection: &SqliteConnection,
        fingerprint: &str,
    ) -> Result<Option<Self>, diesel::result::Error> {
        // Expiration will be the minimum of all stored entries.
        let mut expiration = ExpirationConfig::current_time();
        let result: Vec<Cert> = PendingCertWithoutUIDs::get(connection, fingerprint)?
            .into_iter()
            .map(|vn: PendingCertWithoutUIDs| {
                if vn.exp < expiration {
                    expiration = vn.exp
                }
                vn
            })
            .map(|vn: PendingCertWithoutUIDs| vn.pending_cert)
            .collect();
        let result = merge_certs(result).into_iter().next().map(|c| PendingCertWithoutUIDs {
            fpr: c.fingerprint().to_hex(),
            pending_cert: c,
            exp: expiration,
        });
        Ok(result)
    }

    pub fn store(self, connection: &SqliteConnection) -> Result<(), diesel::result::Error> {
        use crate::db::schema::pending_keys::dsl::*;

        let entry = PendingCertWithoutUIDsEntry::from(self);
        match diesel::insert_into(pending_keys).values(entry).execute(connection) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn insert(
        cert: Cert,
        connection: &SqliteConnection,
        expiration_config: &ExpirationConfig,
    ) -> Result<(), diesel::result::Error> {
        Self {
            fpr: cert.fingerprint().to_hex(),
            pending_cert: cert,
            exp: expiration_config.expiration(),
        }
        .store(connection)
    }
}

impl From<PendingCertWithoutUIDs> for Cert {
    fn from(pending: PendingCertWithoutUIDs) -> Self {
        pending.pending_cert
    }
}

#[derive(Queryable, Insertable)]
#[table_name = "pending_uids"]
struct UIDPendingVerificationEntry {
    fpr: String,
    name: String,
    email: String,
    comment: String,
    uid_packets: String,
    exp: NaiveDateTime,
}

impl From<UIDPendingVerificationEntry> for UIDPendingVerification {
    fn from(entry: UIDPendingVerificationEntry) -> Self {
        UIDPendingVerification {
            fpr: entry.fpr,
            name: entry.name,
            mail: entry.email,
            comment: entry.comment,
            cert_with_this_uid: Cert::from_str(entry.uid_packets.as_str()).expect("Failed to parse Cert from DB!"),
            exp: entry.exp,
        }
    }
}

impl From<UIDPendingVerification> for UIDPendingVerificationEntry {
    fn from(value: UIDPendingVerification) -> Self {
        UIDPendingVerificationEntry {
            fpr: value.fpr,
            name: value.name,
            email: value.mail,
            comment: value.comment,
            uid_packets: export_armored_cert(&value.cert_with_this_uid),
            exp: value.exp,
        }
    }
}

pub struct UIDPendingVerification {
    fpr: String,
    name: String,
    mail: String,
    comment: String,
    cert_with_this_uid: Cert,
    exp: NaiveDateTime,
}

impl UIDPendingVerification {
    pub fn get_all(connection: &SqliteConnection, fingerprint: &str) -> Result<Vec<Self>, diesel::result::Error> {
        use diesel::{ExpressionMethods, QueryDsl};

        use crate::db::schema::pending_uids::dsl::*;
        let result: Vec<UIDPendingVerification> = pending_uids
            .filter(fpr.eq(fingerprint.to_string()))
            .load::<UIDPendingVerificationEntry>(connection)?
            .into_iter()
            .map(UIDPendingVerification::from)
            .filter(|vn: &UIDPendingVerification| ExpirationConfig::is_valid(vn.exp))
            .collect();
        Ok(result)
    }

    pub(crate) fn store(self, connection: &SqliteConnection) -> Result<(), diesel::result::Error> {
        use crate::db::schema::pending_uids::dsl::*;

        match diesel::insert_into(pending_uids)
            .values(UIDPendingVerificationEntry::from(self))
            .execute(connection)
        {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn insert(
        cert_holder: CertWithSingleUID,
        connection: &SqliteConnection,
        expiration_config: &ExpirationConfig,
    ) -> Result<(), diesel::result::Error> {
        Self {
            fpr: cert_holder.cert().fingerprint().to_hex(),
            name: cert_holder.userid().name().unwrap_or_default().unwrap_or_default(),
            mail: cert_holder
                .userid()
                .email_normalized()
                .unwrap_or_default()
                .unwrap_or_default(),
            comment: cert_holder.userid().comment().unwrap_or_default().unwrap_or_default(),
            cert_with_this_uid: cert_holder.into(),
            exp: expiration_config.expiration(),
        }
        .store(connection)
    }
}

impl From<UIDPendingVerification> for Cert {
    fn from(pending: UIDPendingVerification) -> Self {
        pending.cert_with_this_uid
    }
}
