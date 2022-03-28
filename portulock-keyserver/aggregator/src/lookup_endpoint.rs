/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use rocket::State;
use shared::errors::CustomError;
use shared::utils::armor::export_armored_certs;
use shared::utils::async_helper::AsyncHelper;

use crate::lookup;
use crate::lookup::{LookupConfig, SearchString};

#[get("/pks/lookup?<search>")]
#[tracing::instrument]
// parameters "exact" and "fingerprint" are implied and therefore ignored
// The "option(s)"/operation is assumed to be "GET". Index and VIndex are treated the same as GET operations.
pub fn lookup(search: SearchString, lookup_config: State<'_, LookupConfig>) -> Result<String, CustomError> {
    let lookup_config = lookup_config.inner();

    let certs = AsyncHelper::new()
        .expect("Failed to create async runtime.")
        .wait_for(lookup::lookup(lookup_config, search))?;

    let armored_certs = export_armored_certs(&certs)?;
    Ok(armored_certs)
}
