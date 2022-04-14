/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

#[macro_use]
extern crate rocket;

use rocket::{Build, Rocket};
use shared::utils::random;

use crate::lookup::LookupConfig;

mod certification;
mod error;
mod lookup;
mod lookup_endpoint;

#[tracing::instrument]
#[launch]
//noinspection RsMainFunctionNotFound
fn rocket() -> Rocket<Build> {
    tracing_subscriber::fmt::init();

    let figment = rocket::Config::figment()
        /* Compiling aggregator together with verifier enables the secret feature of rocket.
         * This feature is unused in aggregator but still requires a secret or will cause launch panics.
         */
        .join(("secret_key", random::random_key()));

    let rocket = rocket::custom(figment).mount("/", routes![lookup_endpoint::lookup,]);

    let figment = rocket.figment();
    let lookup_config: LookupConfig = figment.extract_inner("lookup_config").expect("Lookup Config missing!");

    rocket.manage(lookup_config)
}
