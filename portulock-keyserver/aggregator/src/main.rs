/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

#[macro_use]
extern crate rocket;

use rocket::{Build, Rocket};

use crate::async_helper::AsyncHelper;
use crate::lookup::LookupConfig;

mod async_helper;
mod certification;
mod error;
mod lookup;
mod lookup_endpoint;

#[tracing::instrument]
#[launch]
//noinspection RsMainFunctionNotFound
fn rocket() -> Rocket<Build> {
    tracing_subscriber::fmt::init();

    let rocket = rocket::build()
        .mount("/", routes![lookup_endpoint::lookup,])
        .manage(AsyncHelper::new());

    let figment = rocket.figment();
    let lookup_config: LookupConfig = figment.extract_inner("lookup_config").expect("Lookup Config missing!");

    rocket.manage(lookup_config)
}
