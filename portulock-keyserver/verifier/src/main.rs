/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate diesel;
#[macro_use]
extern crate diesel_migrations;
#[macro_use]
extern crate rocket;

use std::collections::HashMap;
use std::time;

use chrono::Duration;
use num_traits::cast::ToPrimitive;
use rocket::fairing::AdHoc;
use rocket::{Build, Orbit, Rocket};
use rocket_dyn_templates::Template;
use shared::utils::armor;
use tracing::info;
use verifier_lib::db_new::DBWrapper;
use verifier_lib::key_storage::multi_keystore::MultiOpenPGPCALib;
use verifier_lib::key_storage::openpgp_ca_lib::OpenPGPCALib;
use verifier_lib::submission::mailer::MailerConfig;
use verifier_lib::submission::SubmissionConfig;
use verifier_lib::utils_verifier::expiration::ExpirationConfig;
use verifier_lib::verification::{TokenKey, VerificationConfig};
use verifier_lib::DeletionConfig;

use crate::holders::{ExternalURLHolder, KeyStoreHolder, MailerHolder};

pub mod async_helper;
mod db;
mod error;
mod holders;
mod management_endpoint;
mod submission_endpoint;
mod verification_endpoint;

use db::SubmitterDBConn;
use verifier_lib::key_storage::KeyStore;

use crate::db::diesel_sqlite::DieselSQliteDB;

//noinspection RsMainFunctionNotFound
#[tracing::instrument]
#[launch]
async fn rocket() -> Rocket<Build> {
    tracing_subscriber::fmt::init();

    // TODO convert each AdHoc Fairing to a proper one defined in fairings.rs!

    rocket::build()
        .mount(
            "/",
            routes![
                submission_endpoint::submission,
                verification_endpoint::verify_email,
                verification_endpoint::verify_email_request,
                verification_endpoint::verify_name_start,
                verification_endpoint::verify_oidc_code,
                verification_endpoint::verify_saml_acs,
                verification_endpoint::verify_saml_metadata,
                verification_endpoint::verify_saml_slo,
                verification_endpoint::verify_confirm,
                management_endpoint::delete_key,
                management_endpoint::challenge_decrypt,
                management_endpoint::challenge_decrypt_with_key,
                management_endpoint::challenge_email,
                management_endpoint::challenge_email_all_keys,
                management_endpoint::store_revocations,
                management_endpoint::status_page,
                management_endpoint::status_page_json,
                management_endpoint::authenticated_download,
            ],
        )
        .attach(Template::fairing())
        .attach(SubmitterDBConn::fairing())
        .attach(AdHoc::on_ignite(
            "Configuration: External Url",
            |rocket: Rocket<Build>| async move {
                let external_url: String = rocket
                    .figment()
                    .extract_inner("external_url")
                    .expect("Field external_url missing!");
                rocket.manage(ExternalURLHolder(external_url))
            },
        ))
        .attach(AdHoc::on_ignite(
            "Configuration: Keystores and Submission",
            |rocket: Rocket<Build>| async move {
                let figment = rocket.figment();
                let mut keystores = HashMap::new();
                let allowed_domains: Vec<String> = figment
                    .extract_inner("allowed_domains")
                    .expect("allowed_domains as a vector of strings");
                let certification_duration: i64 = figment.extract_inner("certification_duration").unwrap_or(365);
                let certification_duration = certification_duration
                    .to_u64()
                    .expect("certification duration must be positive");
                let certification_threshold: i64 = figment
                    .extract_inner("certification_duration")
                    .unwrap_or((certification_duration / 10) as i64);
                let certification_threshold = certification_threshold
                    .to_u64()
                    .expect("certification threshold must be positive");
                for allowed_domain in allowed_domains.clone() {
                    let openpgp_ca =
                        OpenPGPCALib::new(allowed_domain.as_str(), certification_duration, certification_threshold)
                            .unwrap();
                    match openpgp_ca.regenerate_wkd() {
                        Ok(_) => {
                            info!("Regenerated WKD for domain {} on startup.", allowed_domain)
                        }
                        Err(e) => {
                            error!(
                                "Failed to regenerate WKD for domain {} due to error: {:#?}",
                                allowed_domain, e
                            )
                        }
                    };
                    keystores.insert(allowed_domain, openpgp_ca);
                }
                let keystore = MultiOpenPGPCALib::new(keystores);

                let keystore_clone = keystore.clone();
                thread::spawn(move || loop {
                    match keystore_clone.perform_maintenance() {
                        Ok(_) => info!("CA maintenance performed!"),
                        Err(e) => error!("Error during CA maintenance: {:#?}", e),
                    };
                    thread::sleep(time::Duration::from_secs(60 * 60 * 8))
                });
                let allowed_certifying_keys: Vec<String> =
                    figment.extract_inner("allowed_certifying_keys").unwrap_or_default();
                let allowed_certifying_keys = allowed_certifying_keys
                    .into_iter()
                    .map(|s| armor::certification_key_from_str(&s).expect("Failed to parse openpgp key!"))
                    .collect();
                rocket
                    .manage(SubmissionConfig::new(allowed_domains, allowed_certifying_keys))
                    .manage(keystore.clone())
                    .manage(KeyStoreHolder::MultiOpenPGPCALib(keystore))
            },
        ))
        .attach(AdHoc::on_ignite(
            "Configuration: Verification",
            |rocket: Rocket<Build>| async move {
                let verification_config: VerificationConfig = rocket.figment().extract().expect("SSO configuration");
                let endpoint_url = rocket.state::<ExternalURLHolder>().unwrap().0.clone();

                let auth_system =
                    verifier_lib::create_auth_system(&verification_config.sso_config.entry, &endpoint_url)
                        .await
                        .expect("Failed to initialize auth system!");
                rocket.manage(verification_config).manage(auth_system)
            },
        ))
        .attach(AdHoc::on_ignite(
            "Configuration: Mailer",
            |rocket: Rocket<Build>| async move {
                let external_url = &rocket.state::<ExternalURLHolder>().unwrap().0;
                let mailer_config: MailerConfig = rocket.figment().extract().expect("Mailer configuration");
                let mailer = mailer_config.create_mailer(external_url);

                rocket.manage(MailerHolder::SmtpMailer(mailer))
            },
        ))
        .attach(AdHoc::on_ignite(
            "Configuration: Token Signing",
            |rocket: Rocket<Build>| async move {
                let token_signing_key: TokenKey = rocket
                    .figment()
                    .extract_inner("token_signing_key")
                    .expect("token_signing_key");
                rocket.manage(token_signing_key)
            },
        ))
        .attach(AdHoc::on_ignite(
            "Configuration: Expiration",
            |rocket: Rocket<Build>| async move {
                let expiration_hours: i64 = rocket.figment().extract_inner("expiration").unwrap_or(72);
                rocket.manage(ExpirationConfig::new(Duration::hours(expiration_hours)))
            },
        ))
        .attach(AdHoc::on_ignite(
            "Configuration: Deletion",
            |rocket: Rocket<Build>| async move {
                let figment = rocket.figment();
                let deletion_config: DeletionConfig = figment
                    .extract_inner("allow_deletion")
                    .unwrap_or(DeletionConfig::Never());
                rocket.manage(deletion_config)
            },
        ))
        .attach(AdHoc::on_ignite("Migrations", |rocket: Rocket<Build>| async move {
            let db_conn = SubmitterDBConn::get_one(&rocket)
                .await
                .expect("Failed to get db connection for migrations.");
            let submitter_db = DBWrapper {
                db: &DieselSQliteDB { conn: db_conn },
            };
            info!("performing DB migrations");
            submitter_db.migrate().await.expect("DB Migrations failed!");
            rocket
        }))
        .attach(AdHoc::on_liftoff("Database Maintenance", |rocket: &Rocket<Orbit>| {
            Box::pin(async move {
                let db_conn = SubmitterDBConn::get_one(rocket)
                    .await
                    .expect("Failed to get db connection for migrations.");

                tokio::spawn(async {
                    // TODO: if the DB connection dies, maintenance might continue to fail until the server restarts

                    let submitter_db = DBWrapper {
                        db: &DieselSQliteDB { conn: db_conn },
                    };
                    loop {
                        match submitter_db.maintain().await {
                            Ok(_) => println!("Database maintenance performed successfully!"),
                            Err(e) => println!("Error during database maintenance: {}", e),
                        };
                        tokio::time::sleep(time::Duration::from_secs(60 * 60 * 8)).await
                    }
                });
            })
        }))
        .attach(AdHoc::on_liftoff("Keystore Maintenance", |rocket: &Rocket<Orbit>| {
            let keystore: &MultiOpenPGPCALib = rocket.state().expect("Failed to get Keystore for maintenance!");
            let keystore = keystore.clone();
            Box::pin(async move {
                tokio::spawn(async move {
                    loop {
                        match keystore.perform_maintenance() {
                            Ok(_) => info!("Keystore maintenance performed!"),
                            Err(e) => error!("Error during keystore maintenance: {:#?}", e),
                        };
                        tokio::time::sleep(time::Duration::from_secs(60 * 60 * 8)).await
                    }
                });
            })
        }))
}
