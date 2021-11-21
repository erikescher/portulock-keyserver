/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use sequoia_openpgp::cert::prelude::UserIDAmalgamation;
use sequoia_openpgp::Cert;

use crate::certification::CertifierFactory;
use crate::errors::CustomError;
use crate::filtering::filter_certs;
use crate::lookup::keyserver::Keyserver;
use crate::lookup::{LookupConfig, LookupDomainConfig};
use crate::types::Email;
use crate::utils::merge_certs;

pub async fn lookup_email(config: &LookupConfig, email: &Email) -> Result<Vec<Cert>, CustomError> {
    let certs = match config.config_for_domain(email.get_domain()) {
        Some(domain_config) => lookup_email_from_lookup_domain_config(domain_config, email)
            .await
            .unwrap_or_default(),
        None => {
            let mut certs = vec![];
            for fallback_lookup_domain_config in &config.fallbacks {
                certs.append(
                    &mut lookup_email_from_lookup_domain_config(fallback_lookup_domain_config, email)
                        .await
                        .unwrap_or_default(),
                );
            }
            certs
        }
    };
    Ok(certs)
}

async fn lookup_email_from_lookup_domain_config(
    lookup_domain_config: &LookupDomainConfig,
    email: &Email,
) -> Result<Vec<Cert>, CustomError> {
    println!(
        "lookup_email_from_ldc ldc: {:#?} email: {}",
        lookup_domain_config, email
    );
    let mut certs = vec![];
    certs.append(
        &mut lookup_email_from_keyservers_filtered_by_domain(
            &lookup_domain_config.keyservers,
            email,
            email.get_domain(),
        )
        .await
        .unwrap_or_default(),
    );
    println!("certs from keyserver: {:?}", certs);
    if lookup_domain_config.use_wkd {
        certs.append(&mut lookup_email_via_wkd(email).await.unwrap_or_default());
    }
    println!("certs from keyserver and wkd: {:?}", certs);

    if !lookup_domain_config.expect_one_certification_from.is_empty() {
        certs = certs
            .into_iter()
            .map(|c| {
                c.retain_userids(|ua| {
                    verify_userid_certified_by_ca_from_list(&ua, &lookup_domain_config.expect_one_certification_from)
                })
            })
            .filter(|c| c.userids().count() > 0)
            .collect();
    }
    println!("certs after filtering for expected certifications: {:?}", certs);

    let certs = filter_certs(certs);

    println!("certs after filtering undesired components: {:?}", certs);

    let mut certified_certs = certs.clone();

    for cert in certs {
        for certifier in &lookup_domain_config.email_certifiers {
            for uid in cert.userids().map(|uida| uida.component()) {
                println!("certifying uid={:?}", uid);
                certified_certs.push(certifier.get_certifier().certify(cert.clone(), uid).await);
            }
        }
    }
    let certs = certified_certs;
    println!("certs after certification: {:?}", certs);
    let certs = merge_certs(certs);
    println!("certs after merging:  {:?}", certs);

    Ok(certs)
}

async fn lookup_email_from_keyservers_filtered_by_domain(
    keyservers: &[Keyserver],
    email: &Email,
    domain: &str,
) -> Result<Vec<Cert>, CustomError> {
    let certs = lookup_email_from_keyservers(keyservers, email).await;
    let certs = filter_certs_by_domain(certs, domain);
    Ok(certs)
}

async fn lookup_email_from_keyservers(keyservers: &[Keyserver], email: &Email) -> Vec<Cert> {
    let mut certs = Vec::new();
    for keyserver in keyservers {
        let mut c = keyserver.lookup_email(email).await.unwrap_or_default();
        certs.append(&mut c);
    }
    certs
}

async fn lookup_email_via_wkd(email: &Email) -> Result<Vec<Cert>, CustomError> {
    let certs = sequoia_net::wkd::get(email.to_string().as_str()).await?;
    let certs = filter_certs_by_domain(certs, email.get_domain());
    Ok(certs)
}

fn verify_userid_certified_by_ca_from_list(ua: &UserIDAmalgamation, ca_list: &[Cert]) -> bool {
    for certification in ua.certifications() {
        for ca in ca_list {
            if ca.fingerprint() == ua.cert().fingerprint() {
                return true;
            }
            for issuer_key_handle in certification.get_issuers() {
                if ca.key_handle().aliases(issuer_key_handle)
                    && certification
                        .clone()
                        .verify_userid_binding(&ca.primary_key(), &ua.cert().primary_key(), ua.userid())
                        .is_ok()
                {
                    println!("UID <{}> certified by CA <{}>", ua.userid(), ca.fingerprint());
                    return true;
                }
            }
        }
    }
    false
}

fn filter_certs_by_domain(certs: Vec<Cert>, domain: &str) -> Vec<Cert> {
    println!("filtering certs by domain: {}", domain);
    certs
        .into_iter()
        .map(|c| {
            c.retain_userids(|ua| match ua.userid().email_normalized() {
                Ok(e) => {
                    println!("UID <{}>, email is: {:?}", ua.userid(), e);
                    match e {
                        Some(e) => match Email::parse(e.as_str()) {
                            Ok(e) => e.get_domain() == domain,
                            Err(e) => {
                                println!("failed to parse email: {}", e);
                                false
                            }
                        },
                        None => false,
                    }
                }
                Err(_) => false,
            })
        })
        .filter(|c| c.userids().count() > 0)
        .collect()
}
