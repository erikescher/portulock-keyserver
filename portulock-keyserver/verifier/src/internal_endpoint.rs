/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use rocket::State;
use shared::errors::CustomError;
use shared::utils::async_helper::AsyncHelper;
use shared::utils::rocket_helpers::LimitedString;
use verifier_lib::db::perform_maintenance;

use crate::holders::InternalSecretHolder;
use crate::SubmitterDBConn;

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
    AsyncHelper::new()
        .expect("Failed to create async runtime.")
        .wait_for(perform_maintenance(&submitter_db))?;
    Ok(())
}
