/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use chrono::NaiveDateTime;
use diesel::RunQueryDsl;
use diesel::SqliteConnection;
use diesel::{ExpressionMethods, QueryDsl};

use crate::db::schema::*;
use crate::utils_verifier::expiration::ExpirationConfig;

#[derive(Queryable, Insertable)]
#[table_name = "verified_names"]
pub struct VerifiedNameEntry {
    fpr: String,
    name: String,
    exp: NaiveDateTime,
}

impl VerifiedNameEntry {
    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn new(fpr: &str, name: &str, exp: i64) -> Self {
        VerifiedNameEntry {
            fpr: fpr.to_string(),
            name: name.to_string(),
            exp: NaiveDateTime::from_timestamp(exp, 0),
        }
    }

    pub fn list(connection: &SqliteConnection, fingerprint: &str) -> Result<Vec<Self>, diesel::result::Error> {
        use crate::db::schema::verified_names::dsl::*;

        let result: Vec<VerifiedNameEntry> = verified_names
            .filter(fpr.eq(fingerprint.to_string()))
            .load::<VerifiedNameEntry>(connection)?
            .into_iter()
            .filter(|vn: &VerifiedNameEntry| ExpirationConfig::is_valid(vn.exp))
            .collect();
        Ok(result)
    }

    pub fn store(&self, connection: &SqliteConnection) -> Result<(), diesel::result::Error> {
        use crate::db::schema::verified_names::dsl::*;

        match diesel::insert_into(verified_names)
            .values((fpr.eq(self.fpr.clone()), name.eq(self.name.clone()), exp.eq(self.exp)))
            .execute(connection)
        {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[derive(Queryable, Insertable, Debug)]
#[table_name = "verified_emails"]
pub struct VerifiedEmailEntry {
    fpr: String,
    email: String,
    exp: NaiveDateTime,
}

impl VerifiedEmailEntry {
    pub fn email(&self) -> String {
        self.email.clone()
    }
    pub fn fpr(&self) -> String {
        self.fpr.clone()
    }

    pub fn new(fpr: &str, email: &str, exp: i64) -> Self {
        VerifiedEmailEntry {
            fpr: fpr.to_string(),
            email: email.to_string(),
            exp: NaiveDateTime::from_timestamp(exp, 0),
        }
    }

    pub fn list(connection: &SqliteConnection, fingerprint: &str) -> Result<Vec<Self>, diesel::result::Error> {
        use crate::db::schema::verified_emails::dsl::*;

        let result: Vec<VerifiedEmailEntry> = verified_emails
            .filter(fpr.eq(fingerprint.to_string()))
            .load::<VerifiedEmailEntry>(connection)?
            .into_iter()
            .filter(|vn: &VerifiedEmailEntry| ExpirationConfig::is_valid(vn.exp))
            .collect();
        Ok(result)
    }

    pub fn list_by_email(
        connection: &SqliteConnection,
        email_address: &str,
    ) -> Result<Vec<Self>, diesel::result::Error> {
        use crate::db::schema::verified_emails::dsl::*;

        let result: Vec<VerifiedEmailEntry> = verified_emails
            .filter(email.eq(email_address.to_string()))
            .load::<VerifiedEmailEntry>(connection)?
            .into_iter()
            .filter(|vn: &VerifiedEmailEntry| ExpirationConfig::is_valid(vn.exp))
            .collect();
        Ok(result)
    }

    pub fn store(&self, connection: &SqliteConnection) -> Result<(), diesel::result::Error> {
        use crate::db::schema::verified_emails::dsl::*;

        match diesel::insert_into(verified_emails)
            .values((fpr.eq(self.fpr.clone()), email.eq(self.email.clone()), exp.eq(self.exp)))
            .execute(connection)
        {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}
