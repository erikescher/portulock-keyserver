/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

use rocket::fairing::AdHoc;
use rocket::Rocket;
use shared::config::lookup_config_from_config_table;
use shared::utils::async_helper::AsyncHelper;

mod lookup_endpoint;

fn main() {
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
