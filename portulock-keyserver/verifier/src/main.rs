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
#[macro_use]
extern crate rocket_contrib;

use std::collections::HashMap;
use std::{thread, time};
use std::fmt::{Debug, Formatter};

use chrono::Duration;
use num_traits::ToPrimitive;
use rocket::config::{Table, Value};
use rocket::fairing::AdHoc;
use rocket::Rocket;
use rocket_contrib::templates::Template;
use tracing_log::LogTracer;
pub use shared::certification;
pub use shared::filtering;
pub use shared::lookup;
pub use shared::types;
pub use shared::utils;
use shared::utils::armor;
use submission::SubmissionConfig;
use utils::async_helper::AsyncHelper;

use crate::db::perform_migrations;
use crate::errors::VerifierError;
use crate::key_storage::multi_keystore::MultiOpenPGPCALib;
use crate::key_storage::openpgp_ca_lib::OpenPGPCALib;
use crate::key_storage::KeyStore;
use crate::management::random_string;
use crate::submission::{Mailer, NoopMailer, SmtpMailer};
use crate::utils_verifier::expiration::ExpirationConfig;
use crate::verification::tokens::oidc_verification::OidcVerifier;
use crate::verification::{OpenIDConnectConfig, OpenIDConnectConfigEntry, TokenKey, VerificationConfig};

mod certs;
mod db;
mod errors;
mod internal_endpoint;
mod key_storage;
mod management;
mod management_endpoint;
mod submission;
mod submission_endpoint;
mod utils_verifier;
mod verification;
mod verification_endpoint;

#[database("sqlite")]
#[derive(std::fmt::Debug)]
pub struct SubmitterDBConn(diesel::SqliteConnection);

impl Debug for SubmitterDBConn {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("SubmitterDBConn") // TODO add SQLite url
    }
}

#[tracing::instrument]
fn main() {
    LogTracer::init().expect("Failed to initialize system for converting logs to trace events");
    tracing_subscriber::fmt::init();

    let rocket = rocket::ignite()
        .mount(
            "/",
            routes![
                submission_endpoint::submission,
                verification_endpoint::verify_email,
                verification_endpoint::verify_email_request,
                verification_endpoint::verify_email_confirm,
                verification_endpoint::verify_name_start,
                verification_endpoint::verify_name_code,
                verification_endpoint::verify_name_confirm,
                management_endpoint::delete_key,
                management_endpoint::challenge_decrypt,
                management_endpoint::challenge_decrypt_with_key,
                management_endpoint::challenge_email,
                management_endpoint::challenge_email_all_keys,
                management_endpoint::store_revocations,
                management_endpoint::status_page,
                management_endpoint::status_page_json,
                management_endpoint::authenticated_download,
                internal_endpoint::db_cleanup,
            ],
        )
        .attach(Template::fairing())
        .attach(SubmitterDBConn::fairing())
        .attach(AdHoc::on_attach("Configuration", |rocket: Rocket| {
            let mut keystores = HashMap::new();
            let allowed_domains: Vec<String> = rocket
                .config()
                .get_slice("allowed_domains")
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            let certification_duration = rocket
                .config()
                .get_int("certification_duration")
                .unwrap_or(365)
                .to_u64()
                .unwrap();
            let certification_threshold = rocket
                .config()
                .get_int("certification_threshold")
                .unwrap_or((certification_duration / 10) as i64)
                .to_u64()
                .unwrap();
            for allowed_domain in allowed_domains.clone() {
                let openpgp_ca =
                    OpenPGPCALib::new(allowed_domain.as_str(), certification_duration, certification_threshold)
                        .unwrap();
                match openpgp_ca.regenerate_wkd() {
                    Ok(_) => {
                        println!("Regenerated WKD for domain {} on startup.", allowed_domain)
                    }
                    Err(e) => {
                        println!(
                            "Failed to regenerate WKD for domain {} due to error: {}",
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
                    Ok(_) => println!("CA maintenance performed!"),
                    Err(e) => println!("Error during CA maintenance: {}", e),
                };
                thread::sleep(time::Duration::from_secs(60 * 60 * 8))
            });
            let rocket = rocket.manage(KeyStoreHolder::MultiOpenPGPCALib(keystore));

            let allowed_certifying_keys = rocket
                .config()
                .get_table("allowed_certifying_keys")
                .unwrap_or(&Table::new())
                .values()
                .map(|v: &Value| armor::certification_key_from_str(v.as_str().unwrap()))
                .collect();
            let rocket = rocket.manage(SubmissionConfig::new(allowed_domains, allowed_certifying_keys));

            let verification_config = VerificationConfig {
                oidc_config: OpenIDConnectConfig {
                    entry: OpenIDConnectConfigEntry {
                        issuer_url: rocket.config().get_string("oidc_issuer_url").unwrap(),
                        client_id: rocket.config().get_string("oidc_client_id").unwrap(),
                        client_secret: match rocket.config().get_string("oidc_client_secret") {
                            Ok(s) => Some(s),
                            Err(_) => None,
                        },
                        endpoint_url: rocket.config().get_string("external_url").unwrap(),
                    },
                },
            };
            let oidc_verifier = AsyncHelper::new()
                .unwrap()
                .wait_for(create_verifier(&verification_config))
                .unwrap();
            let rocket = rocket.manage(verification_config);
            let rocket = rocket.manage(oidc_verifier);

            let external_url = rocket.config().get_str("external_url").unwrap().to_string();
            let rocket = rocket.manage(ExternalURLHolder(external_url));

            let mailer = SmtpMailer::new(
                rocket.config().get_str("smtp_host").unwrap(),
                rocket.config().get_str("smtp_user").unwrap(),
                rocket.config().get_str("smtp_pass").unwrap(),
                rocket.config().get_int("smtp_port").unwrap() as u16,
                rocket.config().get_str("smtp_from").unwrap(),
                rocket.config().get_str("external_url").unwrap(),
            );
            let rocket = rocket.manage(MailerHolder::SmtpMailer(mailer));

            let token_signing_key = rocket.config().get_str("token_signing_key").unwrap();
            let token_signing_key = TokenKey::new(token_signing_key).unwrap();
            let rocket = rocket.manage(token_signing_key);

            let expiration_hours = rocket.config().get_int("expiration").unwrap_or(72);
            let rocket = rocket.manage(ExpirationConfig::new(Duration::hours(expiration_hours)));

            let rocket = rocket.manage(InternalSecretHolder(random_string(32)));

            let deletion_config = match rocket.config().get_str("allow_deletion").unwrap_or("never") {
                "always" => DeletionConfig::Always(),
                "never" => DeletionConfig::Never(),
                _ => panic!("Unsupported value for \"allow_deletion\"!"),
            };
            let rocket = rocket.manage(deletion_config);

            Ok(rocket)
        }))
        .attach(AdHoc::on_launch("Migrations", |rocket: &Rocket| {
            let db_conn = SubmitterDBConn::get_one(rocket).expect("Failed to get db connection for migrations.");
            perform_migrations(&db_conn);
        }));

    let port = rocket.config().port;
    let internal_secret = rocket.state::<InternalSecretHolder>().unwrap().0.clone();

    thread::spawn(move || {
        let url = format!("http://127.0.0.1:{}/internal/db_cleanup", port);
        loop {
            match reqwest::blocking::Client::new()
                .post(url.as_str())
                .body(internal_secret.clone())
                .send()
            {
                Ok(_) => println!("Database maintenance performed successfully!"),
                Err(e) => println!("Error during database maintenance: {}", e),
            };
            thread::sleep(time::Duration::from_secs(60 * 60 * 8))
        }
    });

    rocket.launch();
}

pub struct ExternalURLHolder(String);

#[derive(Debug)]
pub enum KeyStoreHolder {
    OpenPGPCALib(OpenPGPCALib),
    MultiOpenPGPCALib(MultiOpenPGPCALib),
}

pub struct InternalSecretHolder(String);

pub enum DeletionConfig {
    Always(),
    Never(),
}

impl KeyStoreHolder {
    pub fn get_key_store(&self) -> Box<dyn KeyStore + '_> {
        match self {
            KeyStoreHolder::OpenPGPCALib(k) => Box::new(k),
            KeyStoreHolder::MultiOpenPGPCALib(k) => Box::new(k),
        }
    }
}

pub enum MailerHolder {
    NoopMailer(),
    SmtpMailer(SmtpMailer),
}

impl MailerHolder {
    fn get_mailer(&self) -> &dyn Mailer {
        if let MailerHolder::SmtpMailer(s) = self {
            s
        } else {
            &NoopMailer {}
        }
    }
}

async fn create_verifier(verification_config: &VerificationConfig) -> Result<OidcVerifier, VerifierError> {
    let config_entry = &verification_config.oidc_config.entry;
    OidcVerifier::new(
        config_entry.issuer_url.as_str(),
        config_entry.client_id.as_str(),
        config_entry.client_secret.as_deref(),
        config_entry.endpoint_url.as_str(),
    )
    .await
}
