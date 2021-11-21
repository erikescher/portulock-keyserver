/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use chrono::NaiveDateTime;
use diesel::{ExpressionMethods, QueryDsl};
use diesel::{RunQueryDsl, SqliteConnection};
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::Fingerprint;

use crate::db::schema::*;
use crate::management_endpoint::revocations_from_string;
use crate::utils_verifier::expiration::ExpirationConfig;

#[derive(Queryable, Insertable, Debug)]
#[table_name = "pending_revocations"]
pub struct PendingRevocation {
    fpr: String,
    revocation: String,
    exp: NaiveDateTime,
}

impl PendingRevocation {
    pub(crate) fn get(
        connection: &SqliteConnection,
        fingerprint: &str,
    ) -> Result<Vec<Signature>, diesel::result::Error> {
        use crate::db::schema::pending_revocations::dsl::*;

        let result = pending_revocations
            .filter(fpr.eq(fingerprint.to_string()))
            .load::<Self>(connection)?
            .into_iter()
            .filter(|pr: &Self| ExpirationConfig::is_valid(pr.exp))
            .map(|pr| revocations_from_string(pr.revocation).ok())
            .flatten()
            .flatten()
            .collect();
        Ok(result)
    }

    fn store(self, connection: &SqliteConnection) -> Result<(), diesel::result::Error> {
        use crate::db::schema::pending_revocations::dsl::*;
        diesel::insert_into(pending_revocations)
            .values(self)
            .execute(connection)
            .map(|_| ())
    }

    pub(crate) fn insert(
        fpr: &Fingerprint,
        revocation: String,
        connection: &SqliteConnection,
        expiration_config: &ExpirationConfig,
    ) -> Result<(), diesel::result::Error> {
        Self {
            fpr: fpr.to_hex(),
            revocation,
            exp: expiration_config.expiration(),
        }
        .store(connection)
    }
}
