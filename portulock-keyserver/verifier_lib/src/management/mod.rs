/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::collections::hash_map::RandomState;
use std::collections::HashSet;
use std::io::Write;
use std::iter::FromIterator;

use anyhow::anyhow;
use rand::distributions::Alphanumeric;
use rand::Rng;
use sequoia_openpgp::cert::prelude::{ErasedKeyAmalgamation, ValidErasedKeyAmalgamation};
use sequoia_openpgp::packet::key::{KeyRole, PublicParts};
use sequoia_openpgp::packet::{Key, Signature};
use sequoia_openpgp::parse::{PacketParserBuilder, PacketParserResult, Parse};
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::{Armorer, Encryptor, LiteralWriter, Message};
use sequoia_openpgp::types::{PublicKeyAlgorithm, SignatureType};
use sequoia_openpgp::{Cert, Fingerprint, Packet};
use serde::{Deserialize, Serialize};
use shared::filtering::applier::KeyFilterApplier;
use shared::filtering::filters::KeyFilterSubtractingPackets;
use shared::types::Email;
use shared::utils::armor::{armor_signature, export_armored_cert};
use shared::utils::merge_certs;

use crate::db_new::DBWrapper;
use crate::key_storage::emails_from_cert;
use crate::key_storage::KeyStore;
use crate::submission::mailer::Mailer;
use crate::utils_verifier::expiration::ExpirationConfig;
use crate::verification::tokens::SignedToken;
use crate::verification::TokenKey;
use crate::DeletionConfig;

#[tracing::instrument]
pub async fn challenge_decrypt(
    fpr: &Fingerprint,
    token_key: &TokenKey,
    expiration_config: &ExpirationConfig,
    keystore: &(impl KeyStore + ?Sized),
    submitter_db: &DBWrapper<'_>,
) -> Result<String, anyhow::Error> {
    // TODO: might be obsolete and unused
    let cert = match keystore.get_by_fpr(fpr).await? {
        Some(cert) => cert,
        None => submitter_db
            .get_pending_cert_by_fpr(fpr)
            .await?
            .ok_or_else(|| anyhow!("No key with this Fingerprint found in the keystore"))?,
    };
    challenge_decrypt_with_key(&cert, token_key, expiration_config).await
}

#[tracing::instrument]
pub async fn challenge_decrypt_with_key(
    cert: &Cert,
    token_key: &TokenKey,
    expiration_config: &ExpirationConfig,
) -> Result<String, anyhow::Error> {
    let fpr = cert.fingerprint();
    let challenge = create_management_token(&fpr, token_key, expiration_config);
    let challenge = ChallengeHolder::new(challenge);
    let challenge = serde_json::to_string(&challenge)?;

    let policy = StandardPolicy::new();
    let keys = cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption();

    println!("Decryption_Challenge: \n cert: {} \n encryption_keys: {:?}", cert, keys);

    let mut sink = vec![];
    let message = Message::new(&mut sink);
    let message = Armorer::new(message).build()?;
    let keys: Vec<ValidErasedKeyAmalgamation<PublicParts>> = keys
        .into_iter()
        .map(|key| {
            println!("encryption_key: {:?}", key);
            key
        })
        .collect();
    let message = Encryptor::for_recipients(message, keys).build()?;
    let mut message = LiteralWriter::new(message).build()?;
    message.write_all(challenge.as_bytes())?;
    message.finalize()?;
    let string = String::from_utf8(sink)?;
    Ok(string)
}

#[tracing::instrument]
pub async fn challenge_email_all_keys(
    email: Email,
    token_key: &TokenKey,
    expiration_config: &ExpirationConfig,
    mailer: &dyn Mailer,
    keystore: &(impl KeyStore + ?Sized),
    submitter_db: &DBWrapper<'_>,
) -> Result<(), anyhow::Error> {
    let mut certs = vec![];
    certs.append(&mut keystore.list_by_email(email.get_email().as_str()).await?);
    certs.append(&mut submitter_db.get_pending_cert_by_email(&email).await?);
    let certs = merge_certs(certs);

    for cert in certs {
        let fpr = cert.fingerprint();
        let token = create_management_token(&fpr, token_key, expiration_config);
        mailer.send_signed_management_token(&token, &email).await?;
    }
    Ok(())
}

#[tracing::instrument]
pub async fn challenge_email(
    fpr: &Fingerprint,
    email: Option<Email>,
    token_key: &TokenKey,
    expiration_config: &ExpirationConfig,
    mailer: &dyn Mailer,
    keystore: &(impl KeyStore + ?Sized),
    submitter_db: &DBWrapper<'_>,
) -> Result<(), anyhow::Error> {
    let published_cert = keystore.get_by_fpr(fpr).await?;
    let pending_cert = submitter_db.get_pending_cert_by_fpr(fpr).await?;

    let certs = vec![published_cert, pending_cert].into_iter().flatten().collect();
    let cert = merge_certs(certs)
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("No key with this UID found in the keystore"))?;

    let mut emails: Vec<Email> = emails_from_cert(&cert)
        .iter()
        .filter_map(|e| Email::parse_option(e.as_str()))
        .collect();
    if let Some(e) = email {
        if emails.contains(&e) {
            emails = vec![e]
        }
    }
    let token = create_management_token(fpr, token_key, expiration_config);
    for email in emails {
        mailer.send_signed_management_token(&token, &email).await?;
    }
    Ok(())
}

#[tracing::instrument]
fn create_management_token<'a>(
    fpr: &'a Fingerprint,
    token_key: &'a TokenKey,
    expiration_config: &ExpirationConfig,
) -> SignedToken<'a, ManagementToken> {
    let challenge = ManagementToken {
        fpr: fpr.to_string(),
        iat: ExpirationConfig::current_time_u64(),
        nbf: ExpirationConfig::current_time_u64(),
        exp: expiration_config.expiration_u64(),
    };
    SignedToken::sign(challenge, token_key)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ChallengeHolder<'a> {
    reason: String,
    token: SignedToken<'a, ManagementToken>,
    nonce: String,
}

impl<'a> ChallengeHolder<'a> {
    fn new(token: SignedToken<'a, ManagementToken>) -> Self {
        ChallengeHolder {
            reason: "GPG Keyserver Management Challenge".to_string(),
            token,
            nonce: random_nonce(),
        }
    }
}

fn random_nonce() -> String {
    random_string(32)
}

pub fn random_string(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

#[tracing::instrument]
pub async fn delete_key(
    management_token: SignedToken<'_, ManagementToken>,
    token_key: &TokenKey,
    keystore: &(impl KeyStore + ?Sized),
    submitter_db: &DBWrapper<'_>,
    deletion_config: &DeletionConfig,
) -> Result<(), anyhow::Error> {
    let management_token = management_token.verify(token_key)?;
    let fpr = management_token.fpr;
    let fpr = Fingerprint::from_hex(fpr.as_str())?;

    match deletion_config {
        DeletionConfig::Always() => {}
        DeletionConfig::Never() => {
            return Err(anyhow!("Deletion is not allowed on this server!"));
        }
    }

    keystore.delete(&fpr).await?;
    submitter_db.delete_data_for_fpr(&fpr).await?;
    Ok(())
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ManagementToken {
    fpr: String,
    iat: u64,
    nbf: u64,
    exp: u64,
}

#[tracing::instrument]
pub async fn store_revocations(
    fpr: &Fingerprint,
    revocations: Vec<Signature>,
    keystore: &(impl KeyStore + ?Sized),
    submitter_db: &DBWrapper<'_>,
    expiration_config: &ExpirationConfig,
) -> Result<(), anyhow::Error> {
    if !keystore.can_store_revocations_without_publishing() {
        return Err(anyhow!("Not implemented for KeyStores other than OpenPGP-CA!"));
    }

    match get_published_and_pending_cert(fpr, keystore, submitter_db).await? {
        (Some(published), _) => {
            let revocations = verify_revocations(revocations.into_iter(), published.clone());
            keystore
                .store_revocations_without_publishing(&published, revocations.collect())
                .await
        }
        (None, Some(pending)) => {
            let fpr = pending.fingerprint();
            for revocation in verify_revocations(revocations.into_iter(), pending) {
                submitter_db
                    .store_pending_revocation(&revocation, &fpr, expiration_config.expiration_u64())
                    .await?
            }
            Ok(())
        }
        (None, None) => Err(anyhow!("No associated certificate found!")),
    }
}

fn verify_revocations(revocations: impl Iterator<Item = Signature>, cert: Cert) -> impl Iterator<Item = Signature> {
    revocations.filter(move |rev| {
        rev.clone()
            .verify_primary_key_revocation(cert.primary_key().key(), cert.primary_key().key())
            .is_ok()
    })
}

#[derive(Serialize, Debug)]
pub struct KeyStatus {
    fpr: String,
    approved_names: Vec<String>,
    approved_emails: Vec<String>,
    published_primary: Option<PubKeyInfo>,
    published_subkeys: Vec<PubKeyInfo>,
    published_uids: Vec<String>,
    published_cert: Option<String>,
    pending_primary: Option<PubKeyInfo>,
    pending_subkeys: Vec<PubKeyInfo>,
    pending_uids: Vec<PendingUserIDInfo>,
    pending_cert: Option<String>,
    stored_revocations: Vec<String>,
    management_token: Option<String>,
    deletion_allowed: bool,
}

#[derive(Serialize, Debug)]
pub struct PubKeyInfo {
    keyid: String,
    fpr: String,
    algo: String,
    size: String,
    flags: String,
}

#[derive(Serialize, Debug)]
pub struct PendingUserIDInfo {
    full: String,
    email: Option<String>,
    name: Option<String>,
    email_verification_required: bool,
    name_verification_required: bool,
}

#[tracing::instrument]
pub async fn get_key_status_authenticated(
    signed_management_token: SignedToken<'_, ManagementToken>,
    keystore: &(impl KeyStore + ?Sized),
    submitter_db: &DBWrapper<'_>,
    token_key: &TokenKey,
    deletion_config: &DeletionConfig,
) -> Result<KeyStatus, anyhow::Error> {
    let management_token = signed_management_token.verify(token_key)?;
    let fpr = Fingerprint::from_hex(management_token.fpr.as_str())?;
    get_key_status(&fpr, keystore, submitter_db, deletion_config)
        .await
        .map(|mut key_status| {
            key_status.management_token = Some(String::from(signed_management_token.get_data()));
            key_status
        })
}

#[tracing::instrument]
pub async fn get_key_status(
    fpr: &Fingerprint,
    keystore: &(impl KeyStore + ?Sized),
    submitter_db: &DBWrapper<'_>,
    deletion_config: &DeletionConfig,
) -> Result<KeyStatus, anyhow::Error> {
    let (published_cert, pending_cert) = get_published_and_pending_cert(fpr, keystore, submitter_db).await?;
    let approved_names = submitter_db.get_approved_names(fpr).await?;
    let approved_emails = submitter_db.get_approved_emails(fpr).await?;

    let deletion_allowed = match deletion_config {
        DeletionConfig::Always() => true,
        DeletionConfig::Never() => false,
    };

    let stored_revocations = submitter_db
        .get_stored_revocations(fpr)
        .await?
        .into_iter()
        .chain(keystore.get_stored_revocations(fpr).await?)
        .filter_map(|sig| armor_signature(sig).ok());
    let stored_revocations: HashSet<String, RandomState> = HashSet::from_iter(stored_revocations);
    let stored_revocations = stored_revocations.into_iter().collect();

    Ok(KeyStatus {
        fpr: fpr.to_hex(),
        published_primary: published_cert.as_ref().map(|p| key_to_keyinfo(p.primary_key().key())),
        published_subkeys: published_cert
            .as_ref()
            .map(|p| {
                p.keys()
                    .filter(|k| k.fingerprint() != *fpr)
                    .map(|k| subkey_to_keyinfo(&k))
                    .collect()
            })
            .unwrap_or_default(),
        published_uids: published_cert
            .as_ref()
            .map(|p| p.userids().map(|u| u.userid().to_string()).collect())
            .unwrap_or_default(),
        published_cert: published_cert.map(|c| export_armored_cert(&c)),
        pending_primary: pending_cert.as_ref().map(|p| key_to_keyinfo(p.primary_key().key())),
        pending_subkeys: pending_cert
            .as_ref()
            .map(|p| {
                p.keys()
                    .filter(|k| k.fingerprint() != *fpr)
                    .map(|k| subkey_to_keyinfo(&k))
                    .collect()
            })
            .unwrap_or_default(),
        pending_uids: pending_cert
            .as_ref()
            .map(|p| {
                p.userids()
                    .map(|u| {
                        let name = u.userid().name().unwrap_or(None);
                        let email = u.userid().email_normalized().unwrap_or(None);
                        PendingUserIDInfo {
                            full: u.userid().to_string(),
                            email_verification_required: match &email {
                                None => false,
                                Some(email) => !approved_emails.contains(email),
                            },
                            name_verification_required: match &name {
                                None => false,
                                Some(name) => !approved_names.contains(name),
                            },
                            email,
                            name,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default(),
        pending_cert: pending_cert.map(|c| export_armored_cert(&c)),
        management_token: None,
        stored_revocations,
        approved_names,
        approved_emails,
        deletion_allowed,
    })
}

#[tracing::instrument]
pub async fn authenticated_download(
    signed_management_token: SignedToken<'_, ManagementToken>,
    keystore: &(impl KeyStore + ?Sized),
    submitter_db: &DBWrapper<'_>,
    token_key: &TokenKey,
) -> Result<Cert, anyhow::Error> {
    let management_token = signed_management_token.verify(token_key)?;
    let fpr = Fingerprint::from_hex(management_token.fpr.as_str())?;
    let (published_cert, pending_cert) = get_published_and_pending_cert(&fpr, keystore, submitter_db).await?;
    let certs = vec![published_cert, pending_cert].into_iter().flatten().collect();
    merge_certs(certs)
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("No key found for fingerprint!"))
}

#[tracing::instrument]
async fn get_published_and_pending_cert(
    fpr: &Fingerprint,
    keystore: &(impl KeyStore + ?Sized),
    submitter_db: &DBWrapper<'_>,
) -> Result<(Option<Cert>, Option<Cert>), anyhow::Error> {
    let published_cert = keystore.get_by_fpr(fpr).await?;
    let pending_cert = submitter_db.get_pending_cert_by_fpr(fpr).await?;
    Ok(match (published_cert, pending_cert) {
        (Some(publ), Some(pend)) => {
            let pending_cert: Cert = KeyFilterApplier::from(pend)
                .apply(KeyFilterSubtractingPackets::from_key(&publ))
                .into();
            let pending_cert = if pending_cert.clone().into_packets().count() > 1
            /* not just primary key packet */
            {
                Some(pending_cert)
            } else {
                None
            };
            (Some(publ), pending_cert)
        }
        a => a,
    })
}

pub fn key_to_keyinfo<T: KeyRole>(key: &Key<PublicParts, T>) -> PubKeyInfo {
    PubKeyInfo {
        keyid: key.keyid().to_hex(),
        fpr: key.fingerprint().to_hex(),
        algo: key_algo_to_string(key.pk_algo()),
        size: key
            .mpis()
            .bits()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "????".to_string()),
        flags: "".to_string(),
    }
}

fn subkey_to_keyinfo(key: &ErasedKeyAmalgamation<PublicParts>) -> PubKeyInfo {
    let mut info = key_to_keyinfo(key.key());
    if let Some(sig) = key.self_signatures().next() {
        if let Some(flags) = sig.key_flags() {
            let mut string = "".to_string();
            if flags.for_certification() {
                string += "C";
            }
            if flags.for_signing() {
                string += "S"
            }
            if flags.for_authentication() {
                string += "A"
            }
            if flags.for_transport_encryption() || flags.for_storage_encryption() {
                string += "E"
            }
            info.flags = string
        }
    }
    info
}

fn key_algo_to_string(algo: PublicKeyAlgorithm) -> String {
    #[allow(deprecated)]
    match algo {
        PublicKeyAlgorithm::RSAEncryptSign => "RSA".into(),
        PublicKeyAlgorithm::RSAEncrypt => "RSA".into(),
        PublicKeyAlgorithm::RSASign => "RSA".into(),
        PublicKeyAlgorithm::ElGamalEncrypt => "ElGamal".into(),
        PublicKeyAlgorithm::DSA => "DSA".into(),
        PublicKeyAlgorithm::ECDH => "ECDH".into(),
        PublicKeyAlgorithm::ECDSA => "ECDSA".into(),
        PublicKeyAlgorithm::ElGamalEncryptSign => "ElGamal".into(),
        PublicKeyAlgorithm::EdDSA => "EdDSA".into(),
        PublicKeyAlgorithm::Private(n) => format!("Private Algorithm (No. {})", n),
        PublicKeyAlgorithm::Unknown(n) => format!("Unknown Algorithm (No. {})", n),
        _ => "Unknown Algorithm".into(),
    }
}

#[tracing::instrument]
pub fn revocations_from_string(revocations: String) -> Result<Vec<Signature>, anyhow::Error> {
    let mut packet_parser_result = PacketParserBuilder::from_bytes(revocations.as_bytes())?
        .buffer_unread_content()
        .build()?;
    let mut parsed = vec![];
    while let PacketParserResult::Some(packet_parser) = packet_parser_result {
        let (packet, next_ppr) = packet_parser.next()?;
        packet_parser_result = next_ppr;

        if let Packet::Signature(sig) = packet {
            if sig.typ() == SignatureType::KeyRevocation {
                parsed.push(sig.clone())
            }
        }
    }
    Ok(parsed)
}
