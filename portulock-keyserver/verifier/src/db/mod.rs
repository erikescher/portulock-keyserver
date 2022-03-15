/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use core::iter;
use std::collections::HashMap;

use chrono::NaiveDateTime;
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SqliteConnection};
use diesel_migrations::embed_migrations;
use pending::{PendingCertWithoutUIDs, UIDPendingVerification};
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::{Cert, Fingerprint};
use serde::Serialize;
use shared::utils::armor::armor_signature;
use tracing::info;

use crate::certs::CertWithSingleUID;
use crate::db::revocations::PendingRevocation;
use crate::db::verified::{VerifiedEmailEntry, VerifiedNameEntry};
use crate::filtering::applier::KeyFilterApplier;
use crate::filtering::filters::{KeyFilterStrippingUserids, KeyFilterSubtractingPackets};
use crate::types::Email;
use crate::utils::merge_certs;
use crate::utils_verifier::expiration::ExpirationConfig;
use crate::SubmitterDBConn;

mod pending;
mod revocations;
mod schema;
mod verified;

#[derive(Serialize, Clone, Debug)]
#[serde(tag = "type")]
pub enum VerificationChallenge {
    Name(NameVerificationChallenge),
    Email(EmailVerificationChallenge),
}

#[derive(Clone, Debug, Serialize)]
pub struct NameVerificationChallenge {
    fpr: String,
    name: String,
}

impl NameVerificationChallenge {
    pub fn name(&self) -> &str {
        self.name.as_str()
    }
    pub fn fpr(&self) -> &str {
        self.fpr.as_str()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct EmailVerificationChallenge {
    fpr: String,
    email: String,
}

impl EmailVerificationChallenge {
    pub fn new(fpr: &Fingerprint, email: &Email) -> Self {
        Self {
            fpr: fpr.to_hex(),
            email: email.get_email(),
        }
    }
    pub fn email(&self) -> &str {
        self.email.as_str()
    }
    pub fn fpr(&self) -> &str {
        self.fpr.as_str()
    }
}

#[tracing::instrument]
pub fn create_verification_challenges(cert: Cert) -> Vec<VerificationChallenge> {
    let mut challenge_holder = ChallengeHolder::new(cert.fingerprint().to_hex().as_str());
    for cert_holder in CertWithSingleUID::iterate_over_cert(&cert) {
        let uid = cert_holder.userid().component();
        match uid.name().unwrap_or_default() {
            None => {}
            Some(n) => {
                challenge_holder.add_name(n.as_str());
            }
        };
        match uid.email_normalized().unwrap_or_default() {
            None => {}
            Some(e) => {
                challenge_holder.add_email(e.as_str());
            }
        };
    }
    challenge_holder.into()
}

#[tracing::instrument]
pub async fn store_uids_pending_verification(
    submitter_db: &SubmitterDBConn,
    expiration_config: &ExpirationConfig,
    cert: Cert,
) -> Result<(), diesel::result::Error> {
    println!("STORE_UIDS_PENDING_VERIFICATION cert: {:?}", cert);
    let cert_without_uids = KeyFilterApplier::from(cert.clone())
        .apply(KeyFilterStrippingUserids {})
        .into();
    let cert_with_just_uids = KeyFilterApplier::from(cert)
        .apply(KeyFilterSubtractingPackets::from_key(&cert_without_uids))
        .into();

    PendingCertWithoutUIDs::insert(cert_without_uids, &*submitter_db, expiration_config)?;
    for cert_holder in CertWithSingleUID::iterate_over_cert(&cert_with_just_uids) {
        UIDPendingVerification::insert(cert_holder, &*submitter_db, expiration_config)?;
    }
    Ok(())
}

#[tracing::instrument]
pub async fn store_pending_revocation(
    submitter_db: &SubmitterDBConn,
    expiration_config: &ExpirationConfig,
    revocation: Signature,
    fpr: &Fingerprint,
) -> Result<(), diesel::result::Error> {
    PendingRevocation::insert(
        fpr,
        armor_signature(revocation).unwrap(),
        &*submitter_db,
        expiration_config,
    )
}

#[tracing::instrument]
pub async fn get_stored_revocations(
    submitter_db: &SubmitterDBConn,
    fpr: &Fingerprint,
) -> Result<Vec<Signature>, diesel::result::Error> {
    PendingRevocation::get(&*submitter_db, fpr.to_hex().as_str())
}

#[tracing::instrument]
pub async fn perform_maintenance(submitter_db: &SubmitterDBConn) -> Result<(), diesel::result::Error> {
    maintenance_delete_verified_names(&*submitter_db).await?;
    maintenance_delete_verified_emails(&*submitter_db).await?;
    maintenance_delete_pending_keys(&*submitter_db).await?;
    maintenance_delete_pending_uids(&*submitter_db).await?;

    Ok(())
}

async fn maintenance_delete_verified_names(connection: &SqliteConnection) -> Result<usize, diesel::result::Error> {
    use crate::db::schema::verified_names::columns::exp;
    use crate::db::schema::verified_names::dsl::verified_names;

    let current_timestamp = ExpirationConfig::current_time();

    diesel::delete(verified_names.filter(exp.eq(current_timestamp))).execute(connection)
}

async fn maintenance_delete_verified_emails(connection: &SqliteConnection) -> Result<usize, diesel::result::Error> {
    use crate::db::schema::verified_emails::columns::exp;
    use crate::db::schema::verified_emails::dsl::verified_emails;

    let current_timestamp = ExpirationConfig::current_time();

    diesel::delete(verified_emails.filter(exp.eq(current_timestamp))).execute(connection)
}

async fn maintenance_delete_pending_keys(connection: &SqliteConnection) -> Result<usize, diesel::result::Error> {
    use crate::db::schema::pending_keys::columns::exp;
    use crate::db::schema::pending_keys::dsl::pending_keys;

    let current_timestamp = ExpirationConfig::current_time();

    diesel::delete(pending_keys.filter(exp.eq(current_timestamp))).execute(connection)
}

async fn maintenance_delete_pending_uids(connection: &SqliteConnection) -> Result<usize, diesel::result::Error> {
    use crate::db::schema::pending_uids::columns::exp;
    use crate::db::schema::pending_uids::dsl::pending_uids;

    let current_timestamp = ExpirationConfig::current_time();

    diesel::delete(pending_uids.filter(exp.eq(current_timestamp))).execute(connection)
}

#[tracing::instrument]
pub async fn delete_data_for_fingerprint(
    fpr: &Fingerprint,
    submitter_db: &SubmitterDBConn,
) -> Result<(), diesel::result::Error> {
    delete_pending_keys_for_fingerprint(fpr.to_hex().as_str(), &*submitter_db).await?;
    delete_pending_uids_for_fingerprint(fpr.to_hex().as_str(), &*submitter_db).await?;
    delete_verified_names_for_fingerprint(fpr.to_hex().as_str(), &*submitter_db).await?;
    delete_verified_emails_for_fingerprint(fpr.to_hex().as_str(), &*submitter_db).await?;

    Ok(())
}

async fn delete_pending_keys_for_fingerprint(
    fingerprint: &str,
    connection: &SqliteConnection,
) -> Result<usize, diesel::result::Error> {
    use crate::db::schema::pending_keys::columns::fpr;
    use crate::db::schema::pending_keys::dsl::pending_keys;
    diesel::delete(pending_keys.filter(fpr.eq(fingerprint))).execute(connection)
}

async fn delete_pending_uids_for_fingerprint(
    fingerprint: &str,
    connection: &SqliteConnection,
) -> Result<usize, diesel::result::Error> {
    use crate::db::schema::pending_uids::columns::fpr;
    use crate::db::schema::pending_uids::dsl::pending_uids;
    diesel::delete(pending_uids.filter(fpr.eq(fingerprint))).execute(connection)
}

async fn delete_verified_names_for_fingerprint(
    fingerprint: &str,
    connection: &SqliteConnection,
) -> Result<usize, diesel::result::Error> {
    use crate::db::schema::verified_names::columns::fpr;
    use crate::db::schema::verified_names::dsl::verified_names;
    diesel::delete(verified_names.filter(fpr.eq(fingerprint))).execute(connection)
}

async fn delete_verified_emails_for_fingerprint(
    fingerprint: &str,
    connection: &SqliteConnection,
) -> Result<usize, diesel::result::Error> {
    use crate::db::schema::verified_emails::columns::fpr;
    use crate::db::schema::verified_emails::dsl::verified_emails;
    diesel::delete(verified_emails.filter(fpr.eq(fingerprint))).execute(connection)
}

pub async fn store_verified_email(
    submitter_db: &SubmitterDBConn,
    fpr: &str,
    email: &str,
    exp: NaiveDateTime,
) -> Result<(), diesel::result::Error> {
    VerifiedEmailEntry::new(fpr, email, exp.timestamp()).store(&*submitter_db)
}

#[tracing::instrument]
pub async fn store_verified_name(
    submitter_db: &SubmitterDBConn,
    fpr: &str,
    name: &str,
    exp: NaiveDateTime,
) -> Result<(), diesel::result::Error> {
    VerifiedNameEntry::new(fpr, name, exp.timestamp()).store(&*submitter_db)
}

#[tracing::instrument]
pub async fn get_pending_cert(
    submitter_db: &SubmitterDBConn,
    fpr: &Fingerprint,
) -> Result<Option<Cert>, diesel::result::Error> {
    let fpr = fpr.to_hex();
    let fpr = fpr.as_str();
    let key = PendingCertWithoutUIDs::get_combined(&*submitter_db, fpr)?;
    let uids: Vec<Cert> = UIDPendingVerification::get_all(&*submitter_db, fpr)?
        .into_iter()
        .map(|pending: UIDPendingVerification| pending.into())
        .collect();
    println!(
        "GET_PENDING_CERT: \ncert_without_uids: {:?} \n uids_vec {:?}",
        key, uids
    );
    let mut certs = uids;
    match key {
        None => {}
        Some(c) => certs.push(c.into()),
    }
    Ok(merge_certs(certs).into_iter().next())
}

#[tracing::instrument]
pub async fn get_pending_certs_by_email(
    submitter_db: &SubmitterDBConn,
    email: &Email,
) -> Result<Vec<Cert>, diesel::result::Error> {
    let fingerprints = VerifiedEmailEntry::list_by_email(&*submitter_db, email.get_email().as_str())?
        .into_iter()
        .filter_map(|vee| Fingerprint::from_hex(vee.fpr().as_str()).ok());

    let mut certs = vec![];
    for fpr in fingerprints {
        match get_pending_cert(&*submitter_db, &fpr).await? {
            None => {}
            Some(c) => certs.push(c),
        }
    }

    Ok(certs)
}

#[tracing::instrument]
pub async fn get_approved_names(
    submitter_db: &SubmitterDBConn,
    fpr: &Fingerprint,
) -> Result<Vec<String>, diesel::result::Error> {
    Ok(VerifiedNameEntry::list(&*submitter_db, fpr.to_hex().as_str())?
        .into_iter()
        .map(|vne: VerifiedNameEntry| vne.name())
        .collect())
}

#[tracing::instrument]
pub async fn get_approved_emails(
    submitter_db: &SubmitterDBConn,
    fpr: &Fingerprint,
) -> Result<Vec<String>, diesel::result::Error> {
    Ok(VerifiedEmailEntry::list(&*submitter_db, fpr.to_hex().as_str())?
        .into_iter()
        .map(|vee: VerifiedEmailEntry| vee.email())
        .collect())
}

#[derive(Debug)]
struct ChallengeHolder {
    fpr: String,
    names: HashMap<String, NameVerificationChallenge>,
    mails: HashMap<String, EmailVerificationChallenge>,
}

impl ChallengeHolder {
    fn new(fpr: &str) -> Self {
        ChallengeHolder {
            fpr: fpr.to_string(),
            names: HashMap::new(),
            mails: HashMap::new(),
        }
    }

    fn add_name(&mut self, n: &str) {
        match self.names.get(n) {
            None => {
                self.names.insert(
                    String::from(n),
                    NameVerificationChallenge {
                        fpr: self.fpr.clone(),
                        name: String::from(n),
                    },
                );
            }
            Some(_) => {}
        }
    }

    fn add_email(&mut self, e: &str) {
        match self.mails.get(e) {
            None => {
                self.mails.insert(
                    String::from(e),
                    EmailVerificationChallenge {
                        fpr: self.fpr.clone(),
                        email: String::from(e),
                    },
                );
            }
            Some(_) => {}
        }
    }
}

impl From<ChallengeHolder> for Vec<VerificationChallenge> {
    fn from(mut ch: ChallengeHolder) -> Self {
        iter::empty()
            .chain(ch.names.drain().map(|(_, n)| VerificationChallenge::Name(n)))
            .chain(ch.mails.drain().map(|(_, e)| VerificationChallenge::Email(e)))
            .collect()
    }
}

embed_migrations!();

pub fn perform_migrations(connection: &SqliteConnection) {
    info!("performing DB migrations");
    embedded_migrations::run_with_output(connection, &mut std::io::stdout()).expect("DB Migrations failed!");
}
