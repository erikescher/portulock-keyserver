/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use rocket::State;
use shared::errors::CustomError;
use shared::utils::async_helper::AsyncHelper;
use shared::utils::rocket_helpers::LimitedString;
use verifier_lib::db_new::DBWrapper;

use crate::db::diesel_sqlite::DieselSQliteDB;
use crate::db::SubmitterDBConn;
use crate::holders::InternalSecretHolder;

#[post("/internal/db_cleanup", data = "<secret>")]
#[tracing::instrument]
pub fn db_cleanup(
    secret: LimitedString,
    submitter_db: SubmitterDBConn,
    internal_secret: State<InternalSecretHolder>,
) -> Result<(), CustomError> {
    if internal_secret.inner().0 != String::from(secret) {
        return Err(CustomError::from("Invalid InternalSecret provided!"));
    }
    let submitter_db = DBWrapper {
        db: &DieselSQliteDB { conn: &submitter_db.0 },
    };

    AsyncHelper::new()
        .expect("Failed to create async runtime.")
        .wait_for(submitter_db.maintain())?;
    Ok(())
}
