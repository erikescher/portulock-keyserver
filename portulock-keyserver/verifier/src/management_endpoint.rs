/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use rocket::State;
use rocket_contrib::json::Json;
use rocket_contrib::templates::Template;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::parse::{PacketParserBuilder, PacketParserResult, Parse};
use sequoia_openpgp::types::SignatureType;
use sequoia_openpgp::{Fingerprint, Packet};
use shared::errors::CustomError;
use shared::utils::armor::{export_armored_cert, parse_certs};

use crate::management::{KeyStatus, ManagementToken};
use crate::types::Email;
use crate::utils::async_helper::AsyncHelper;
use crate::utils::rocket_helpers::LimitedString;
use crate::utils_verifier::expiration::ExpirationConfig;
use crate::verification::tokens::SignedToken;
use crate::verification::TokenKey;
use crate::{management, DeletionConfig, KeyStoreHolder, MailerHolder, SubmitterDBConn};

#[get("/manage/delete?<management_token>")]
pub fn delete_key(
    management_token: String,
    token_key: State<TokenKey>,
    keystore: State<'_, KeyStoreHolder>,
    submitter_db: SubmitterDBConn,
    deletion_config: State<DeletionConfig>,
) -> Result<String, CustomError> {
    let keystore = keystore.inner().get_key_store();
    let management_token = SignedToken::from(management_token);
    let token_key = token_key.inner();
    AsyncHelper::new()
        .expect("Failed to create async runtime.")
        .wait_for(management::delete_key(
            management_token,
            token_key,
            &*keystore,
            &submitter_db,
            deletion_config.inner(),
        ))
        .map(|()| "Key deleted successfully!".into())
}

#[get("/manage/challenge_decrypt?<fpr>")]
pub fn challenge_decrypt(
    fpr: String,
    token_key: State<TokenKey>,
    expiration_config: State<ExpirationConfig>,
    keystore: State<'_, KeyStoreHolder>,
    submitter_db: SubmitterDBConn,
) -> Result<String, CustomError> {
    let keystore = keystore.inner().get_key_store();
    let token_key = token_key.inner();
    let expiration_config = expiration_config.inner();
    let fpr = Fingerprint::from_hex(fpr.as_str())?;

    AsyncHelper::new()
        .expect("Failed to create async runtime.")
        .wait_for(management::challenge_decrypt(
            &fpr,
            token_key,
            expiration_config,
            &*keystore,
            &submitter_db,
        ))
}

#[post("/manage/challenge_decrypt", data = "<public_key>")]
pub fn challenge_decrypt_with_key(
    public_key: LimitedString,
    token_key: State<TokenKey>,
    expiration_config: State<ExpirationConfig>,
) -> Result<String, CustomError> {
    let token_key = token_key.inner();
    let expiration_config = expiration_config.inner();
    let public_key = String::from(public_key);
    let public_key = parse_certs(public_key.as_str())?;
    let public_key = public_key.first().ok_or("No certificate provided!")?;

    AsyncHelper::new()
        .expect("Failed to create async runtime.")
        .wait_for(management::challenge_decrypt_with_key(
            public_key,
            token_key,
            expiration_config,
        ))
}

#[get("/manage/challenge_email_all?<email>")]
pub fn challenge_email_all_keys(
    email: String,
    token_key: State<TokenKey>,
    expiration_config: State<ExpirationConfig>,
    mailer: State<MailerHolder>,
    keystore: State<'_, KeyStoreHolder>,
    submitter_db: SubmitterDBConn,
) -> Result<(), CustomError> {
    let email = Email::parse(email.as_str())?;
    let token_key = token_key.inner();
    let expiration_config = expiration_config.inner();
    let mailer = mailer.inner().get_mailer();
    let keystore = keystore.inner().get_key_store();
    AsyncHelper::new()
        .expect("Failed to create async runtime.")
        .wait_for(management::challenge_email_all_keys(
            email,
            token_key,
            expiration_config,
            mailer,
            &*keystore,
            &submitter_db,
        ))
}

#[get("/manage/challenge_email?<fpr>&<email>")]
pub fn challenge_email(
    fpr: String,
    email: Option<String>,
    token_key: State<TokenKey>,
    expiration_config: State<ExpirationConfig>,
    mailer: State<MailerHolder>,
    keystore: State<'_, KeyStoreHolder>,
    submitter_db: SubmitterDBConn,
) -> Result<(), CustomError> {
    let fpr = Fingerprint::from_hex(fpr.as_str())?;
    let email = email.and_then(|e| Email::parse_option(e.as_str()));
    let token_key = token_key.inner();
    let expiration_config = expiration_config.inner();
    let mailer = mailer.inner().get_mailer();
    let keystore = keystore.inner().get_key_store();
    AsyncHelper::new()
        .expect("Failed to create async runtime.")
        .wait_for(management::challenge_email(
            &fpr,
            email,
            token_key,
            expiration_config,
            mailer,
            &*keystore,
            &submitter_db,
        ))
}

#[post("/manage/store_revocations?<fpr>", data = "<revocations>")]
pub fn store_revocations(
    fpr: String,
    revocations: LimitedString,
    keystore: State<'_, KeyStoreHolder>,
    submitter_db: SubmitterDBConn,
    expiration_config: State<ExpirationConfig>,
) -> Result<(), CustomError> {
    let keystore = keystore.inner().get_key_store();
    let fpr = Fingerprint::from_hex(fpr.as_str())?;
    let revocations: Vec<Signature> = revocations_from_string(revocations.into())?;

    AsyncHelper::new()
        .expect("Failed to create async runtime.")
        .wait_for(management::store_revocations(
            &fpr,
            revocations,
            &*keystore,
            &submitter_db,
            expiration_config.inner(),
        ))
}

#[get("/manage/status?<management_token>", rank = 2)]
pub fn status_page(
    management_token: String,
    keystore: State<'_, KeyStoreHolder>,
    token_key: State<TokenKey>,
    submitter_db: SubmitterDBConn,
    deletion_config: State<DeletionConfig>,
) -> Result<Template, CustomError> {
    let keystore = keystore.inner().get_key_store();
    let token_key = token_key.inner();
    let management_token: SignedToken<ManagementToken> = SignedToken::from(management_token);

    let key_status = AsyncHelper::new().expect("Failed to create async runtime.").wait_for(
        management::get_key_status_authenticated(
            management_token,
            &*keystore,
            &submitter_db,
            token_key,
            deletion_config.inner(),
        ),
    )?;
    Ok(Template::render("status_page", key_status))
}

#[get("/manage/status_json?<management_token>", rank = 2)]
pub fn status_page_json(
    management_token: String,
    keystore: State<'_, KeyStoreHolder>,
    token_key: State<TokenKey>,
    submitter_db: SubmitterDBConn,
    deletion_config: State<DeletionConfig>,
) -> Result<Json<KeyStatus>, CustomError> {
    let keystore = keystore.inner().get_key_store();
    let token_key = token_key.inner();
    let management_token = SignedToken::from(management_token);

    let key_status = AsyncHelper::new().expect("Failed to create async runtime.").wait_for(
        management::get_key_status_authenticated(
            management_token,
            &*keystore,
            &submitter_db,
            token_key,
            deletion_config.inner(),
        ),
    )?;
    Ok(Json(key_status))
}

#[get("/manage/download_authenticated?<management_token>")]
pub fn authenticated_download(
    management_token: String,
    keystore: State<'_, KeyStoreHolder>,
    token_key: State<TokenKey>,
    submitter_db: SubmitterDBConn,
) -> Result<String, CustomError> {
    let keystore = keystore.inner().get_key_store();
    let token_key = token_key.inner();
    let management_token = SignedToken::from(management_token);

    let cert =
        AsyncHelper::new()
            .expect("Failed to create async runtime.")
            .wait_for(management::authenticated_download(
                management_token,
                &*keystore,
                &submitter_db,
                token_key,
            ))?;
    Ok(export_armored_cert(&cert))
}

pub fn revocations_from_string(revocations: String) -> Result<Vec<Signature>, CustomError> {
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