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
use std::{thread, time};

use async_helper::AsyncHelper;
use chrono::Duration;
use num_traits::ToPrimitive;
use rocket::config::{Array, Table, Value};
use rocket::fairing::AdHoc;
use rocket::Rocket;
use rocket_contrib::templates::Template;
use shared::utils::armor;
use tracing::info;
use verifier_lib::db_new::DBWrapper;
use verifier_lib::key_storage::multi_keystore::MultiOpenPGPCALib;
use verifier_lib::key_storage::openpgp_ca_lib::OpenPGPCALib;
use verifier_lib::management::random_string;
use verifier_lib::submission::mailer::{SmtpConnectionSecurity, SmtpMailer};
use verifier_lib::submission::SubmissionConfig;
use verifier_lib::utils_verifier::expiration::ExpirationConfig;
use verifier_lib::verification::{
    OpenIDConnectConfigEntry, SAMLConfigEntry, SSOConfig, SSOConfigEntry, TokenKey, VerificationConfig,
};
use verifier_lib::DeletionConfig;

use crate::holders::{ExternalURLHolder, InternalSecretHolder, KeyStoreHolder, MailerHolder};

pub mod async_helper;
mod db;
mod holders;
mod internal_endpoint;
mod management_endpoint;
pub mod rocket_helpers;
mod submission_endpoint;
mod verification_endpoint;

use db::SubmitterDBConn;

use crate::db::diesel_sqlite::DieselSQliteDB;

#[tracing::instrument]
fn main() {
    tracing_subscriber::fmt::init();

    let rocket = rocket::ignite()
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
                sso_config: SSOConfig {
                    entry: match rocket.config().get_str("sso_type").unwrap() {
                        "oidc" => SSOConfigEntry::Oidc(OpenIDConnectConfigEntry {
                            issuer_url: rocket.config().get_string("oidc_issuer_url").unwrap(),
                            client_id: rocket.config().get_string("oidc_client_id").unwrap(),
                            client_secret: match rocket.config().get_string("oidc_client_secret") {
                                Ok(s) => Some(s),
                                Err(_) => None,
                            },
                            endpoint_url: rocket.config().get_string("external_url").unwrap(),
                        }),
                        "saml" => {
                            let attribute_selectors_name = rocket
                                .config()
                                .get_slice("saml_attribute_selectors_name")
                                .unwrap_or(&Array::new())
                                .iter()
                                .map(|e| e.as_str().unwrap().to_string())
                                .collect();
                            let attribute_selectors_email = rocket
                                .config()
                                .get_slice("saml_attribute_selectors_email")
                                .unwrap_or(&Array::new())
                                .iter()
                                .map(|e| e.as_str().unwrap().to_string())
                                .collect();
                            SSOConfigEntry::Saml(SAMLConfigEntry {
                                idp_url: rocket.config().get_string("saml_idp_url").unwrap(),
                                idp_metadata_url: rocket.config().get_string("saml_idp_metadata_url").unwrap(),
                                endpoint_url: rocket.config().get_string("external_url").unwrap(),
                                sp_entity_id: rocket.config().get_string("saml_sp_entity_id").unwrap(),
                                sp_certificate_pem: rocket.config().get_string("saml_sp_certificate_pem").unwrap(),
                                sp_private_key_pem: rocket.config().get_string("saml_sp_private_key_pem").unwrap(),
                                attribute_selectors_name,
                                attribute_selectors_email,
                            })
                        }
                        other => panic!("Unsupported sso_type: {}! Supported types are: oidc, saml.", other),
                    },
                },
            };
            let auth_system = AsyncHelper::new()
                .unwrap()
                .wait_for(verifier_lib::create_auth_system(&verification_config.sso_config.entry))
                .unwrap();
            let rocket = rocket.manage(verification_config);
            let rocket = rocket.manage(auth_system);

            let external_url = rocket.config().get_str("external_url").unwrap().to_string();
            let rocket = rocket.manage(ExternalURLHolder(external_url));

            let smtp_security = match rocket.config().get_str("smtp_security").unwrap_or("tls") {
                "tls" => SmtpConnectionSecurity::Tls,
                "starttls" => SmtpConnectionSecurity::StartTls,
                "none" => SmtpConnectionSecurity::None,
                other => panic!(
                    "Unknown value for smtp_security: {}. Known values: tls, starttls, none.",
                    other
                ),
            };

            let mailer = SmtpMailer::new(
                rocket.config().get_str("smtp_host").unwrap(),
                rocket.config().get_str("smtp_user").unwrap(),
                rocket.config().get_str("smtp_pass").unwrap(),
                rocket.config().get_int("smtp_port").unwrap() as u16,
                rocket.config().get_str("smtp_from").unwrap(),
                rocket.config().get_str("external_url").unwrap(),
                &smtp_security,
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
            let submitter_db = DBWrapper {
                db: &DieselSQliteDB { conn: &db_conn },
            };
            info!("performing DB migrations");
            submitter_db.migrate().expect("DB Migrations failed!");
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
