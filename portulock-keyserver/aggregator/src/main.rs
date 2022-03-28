/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

use config::lookup_config_from_config_table;
use rocket::fairing::AdHoc;
use rocket::Rocket;
use shared::utils::async_helper::AsyncHelper;

mod certification;
mod config;
mod lookup;
mod lookup_endpoint;

#[tracing::instrument]
fn main() {
    tracing_subscriber::fmt::init();

    let rocket = rocket::ignite()
        .mount("/", routes![lookup_endpoint::lookup,])
        .attach(AdHoc::on_attach("Lookup Config", |rocket: Rocket| {
            let lookup_config_table = rocket.config().get_table("lookup_config").unwrap();
            let lookup_config = lookup_config_from_config_table(lookup_config_table);
            Ok(rocket.manage(lookup_config))
        }))
        .manage(AsyncHelper::new());

    rocket.launch();
}
