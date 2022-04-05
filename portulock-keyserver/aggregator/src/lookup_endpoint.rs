/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use rocket::State;
use shared::utils::armor::export_armored_certs;

use crate::error::AnyhowErrorResponse;
use crate::lookup::lookup as key_lookup;
use crate::lookup::{LookupConfig, SearchString};

#[get("/pks/lookup?<search>")]
#[tracing::instrument]
// parameters "exact" and "fingerprint" are implied and therefore ignored
// The "option(s)"/operation is assumed to be "GET". Index and VIndex are treated the same as GET operations.
pub async fn lookup(search: &str, lookup_config: &State<LookupConfig>) -> Result<String, AnyhowErrorResponse> {
    let lookup_config = lookup_config.inner();
    let search = SearchString::from_string(search)?;

    let certs = key_lookup(lookup_config, search).await?;

    let armored_certs = export_armored_certs(&certs)?;
    Ok(armored_certs)
}
