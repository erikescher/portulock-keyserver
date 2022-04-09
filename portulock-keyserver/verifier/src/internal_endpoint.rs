/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use anyhow::anyhow;
use rocket::State;
use verifier_lib::db_new::DBWrapper;

use crate::db::diesel_sqlite::DieselSQliteDB;
use crate::db::SubmitterDBConn;
use crate::error::AnyhowErrorResponse;
use crate::holders::InstanceSecretHolder;

#[post("/internal/db_cleanup", data = "<secret>")]
#[tracing::instrument]
pub async fn db_cleanup(
    secret: String,
    submitter_db: SubmitterDBConn,
    internal_secret: &State<InstanceSecretHolder>,
) -> Result<(), AnyhowErrorResponse> {
    if internal_secret.inner().0 != secret {
        return Err(anyhow!("Invalid InternalSecret provided!").into());
    }
    let submitter_db = DBWrapper {
        db: &DieselSQliteDB { conn: submitter_db },
    };

    submitter_db.maintain().await.map_err(AnyhowErrorResponse::from)
}
