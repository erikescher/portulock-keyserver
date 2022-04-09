/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use anyhow::anyhow;
use rocket::serde::json::Json;
use rocket::State;
use rocket_dyn_templates::Template;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::Fingerprint;
use shared::types::Email;
use shared::utils::armor::{export_armored_cert, parse_certs};
use verifier_lib::db_new::DBWrapper;
use verifier_lib::management::{KeyStatus, ManagementToken};
use verifier_lib::utils_verifier::expiration::ExpirationConfig;
use verifier_lib::verification::tokens::SignedToken;
use verifier_lib::verification::TokenKey;
use verifier_lib::{management, DeletionConfig};

use crate::db::diesel_sqlite::DieselSQliteDB;
use crate::db::SubmitterDBConn;
use crate::error::AnyhowErrorResponse;
use crate::holders::{KeyStoreHolder, MailerHolder};

#[get("/manage/delete?<management_token>")]
#[tracing::instrument]
pub async fn delete_key(
    management_token: String,
    token_key: &State<TokenKey>,
    keystore: &State<KeyStoreHolder>,
    submitter_db: SubmitterDBConn,
    deletion_config: &State<DeletionConfig>,
) -> Result<String, AnyhowErrorResponse> {
    let keystore = keystore.inner().get_key_store();
    let management_token = SignedToken::from(management_token);
    let token_key = token_key.inner();
    let submitter_db = DBWrapper {
        db: &DieselSQliteDB { conn: submitter_db },
    };
    management::delete_key(
        management_token,
        token_key,
        &*keystore,
        &submitter_db,
        deletion_config.inner(),
    )
    .await
    .map(|_| "Key deleted successfully!".into())
    .map_err(|e| e.into())
}

#[get("/manage/challenge_decrypt?<fpr>")]
#[tracing::instrument]
pub async fn challenge_decrypt(
    fpr: String,
    token_key: &State<TokenKey>,
    expiration_config: &State<ExpirationConfig>,
    keystore: &State<KeyStoreHolder>,
    submitter_db: SubmitterDBConn,
) -> Result<String, AnyhowErrorResponse> {
    let keystore = keystore.inner().get_key_store();
    let token_key = token_key.inner();
    let expiration_config = expiration_config.inner();
    let fpr = Fingerprint::from_hex(fpr.as_str())?;
    let submitter_db = DBWrapper {
        db: &DieselSQliteDB { conn: submitter_db },
    };

    management::challenge_decrypt(&fpr, token_key, expiration_config, &*keystore, &submitter_db)
        .await
        .map_err(|e| e.into())
}

#[post("/manage/challenge_decrypt", data = "<public_key>")]
#[tracing::instrument]
pub async fn challenge_decrypt_with_key(
    public_key: String,
    token_key: &State<TokenKey>,
    expiration_config: &State<ExpirationConfig>,
) -> Result<String, AnyhowErrorResponse> {
    let token_key = token_key.inner();
    let expiration_config = expiration_config.inner();
    let public_key = public_key;
    let public_key = parse_certs(public_key.as_str())?;
    let public_key = public_key
        .first()
        .ok_or_else::<AnyhowErrorResponse, _>(|| anyhow!("No certificate provided!").into())?;

    management::challenge_decrypt_with_key(public_key, token_key, expiration_config)
        .await
        .map_err(|e| e.into())
}

#[get("/manage/challenge_email_all?<email>")]
#[tracing::instrument]
pub async fn challenge_email_all_keys(
    email: String,
    token_key: &State<TokenKey>,
    expiration_config: &State<ExpirationConfig>,
    mailer: &State<MailerHolder>,
    keystore: &State<KeyStoreHolder>,
    submitter_db: SubmitterDBConn,
) -> Result<(), AnyhowErrorResponse> {
    let email = Email::parse(email.as_str())?;
    let token_key = token_key.inner();
    let expiration_config = expiration_config.inner();
    let mailer = mailer.inner().get_mailer();
    let keystore = keystore.inner().get_key_store();
    let submitter_db = DBWrapper {
        db: &DieselSQliteDB { conn: submitter_db },
    };
    management::challenge_email_all_keys(email, token_key, expiration_config, mailer, &*keystore, &submitter_db)
        .await
        .map_err(|e| e.into())
}

#[get("/manage/challenge_email?<fpr>&<email>")]
#[tracing::instrument]
pub async fn challenge_email(
    fpr: String,
    email: Option<String>,
    token_key: &State<TokenKey>,
    expiration_config: &State<ExpirationConfig>,
    mailer: &State<MailerHolder>,
    keystore: &State<KeyStoreHolder>,
    submitter_db: SubmitterDBConn,
) -> Result<(), AnyhowErrorResponse> {
    let fpr = Fingerprint::from_hex(fpr.as_str())?;
    let email = email.and_then(|e| Email::parse_option(e.as_str()));
    let token_key = token_key.inner();
    let expiration_config = expiration_config.inner();
    let mailer = mailer.inner().get_mailer();
    let keystore = keystore.inner().get_key_store();
    let submitter_db = DBWrapper {
        db: &DieselSQliteDB { conn: submitter_db },
    };
    management::challenge_email(
        &fpr,
        email,
        token_key,
        expiration_config,
        mailer,
        &*keystore,
        &submitter_db,
    )
    .await
    .map_err(|e| e.into())
}

#[post("/manage/store_revocations?<fpr>", data = "<revocations>")]
#[tracing::instrument]
pub async fn store_revocations(
    fpr: String,
    revocations: String,
    keystore: &State<KeyStoreHolder>,
    submitter_db: SubmitterDBConn,
    expiration_config: &State<ExpirationConfig>,
) -> Result<(), AnyhowErrorResponse> {
    let keystore = keystore.inner().get_key_store();
    let fpr = Fingerprint::from_hex(fpr.as_str())?;
    let revocations: Vec<Signature> = management::revocations_from_string(revocations)?;
    let submitter_db = DBWrapper {
        db: &DieselSQliteDB { conn: submitter_db },
    };

    management::store_revocations(&fpr, revocations, &*keystore, &submitter_db, expiration_config.inner())
        .await
        .map_err(|e| e.into())
}

#[get("/manage/status?<management_token>", rank = 2)]
#[tracing::instrument]
pub async fn status_page(
    management_token: String,
    keystore: &State<KeyStoreHolder>,
    token_key: &State<TokenKey>,
    submitter_db: SubmitterDBConn,
    deletion_config: &State<DeletionConfig>,
) -> Result<Template, AnyhowErrorResponse> {
    let keystore = keystore.inner().get_key_store();
    let token_key = token_key.inner();
    let management_token: SignedToken<ManagementToken> = SignedToken::from(management_token);
    let submitter_db = DBWrapper {
        db: &DieselSQliteDB { conn: submitter_db },
    };

    let key_status = management::get_key_status_authenticated(
        management_token,
        &*keystore,
        &submitter_db,
        token_key,
        deletion_config.inner(),
    )
    .await?;
    Ok(Template::render("status_page", key_status))
}

#[get("/manage/status_json?<management_token>", rank = 2)]
#[tracing::instrument]
pub async fn status_page_json(
    management_token: String,
    keystore: &State<KeyStoreHolder>,
    token_key: &State<TokenKey>,
    submitter_db: SubmitterDBConn,
    deletion_config: &State<DeletionConfig>,
) -> Result<Json<KeyStatus>, AnyhowErrorResponse> {
    let keystore = keystore.inner().get_key_store();
    let token_key = token_key.inner();
    let management_token = SignedToken::from(management_token);
    let submitter_db = DBWrapper {
        db: &DieselSQliteDB { conn: submitter_db },
    };

    let key_status = management::get_key_status_authenticated(
        management_token,
        &*keystore,
        &submitter_db,
        token_key,
        deletion_config.inner(),
    )
    .await?;
    Ok(Json(key_status))
}

#[get("/manage/download_authenticated?<management_token>")]
#[tracing::instrument]
pub async fn authenticated_download(
    management_token: String,
    keystore: &State<KeyStoreHolder>,
    token_key: &State<TokenKey>,
    submitter_db: SubmitterDBConn,
) -> Result<String, AnyhowErrorResponse> {
    let keystore = keystore.inner().get_key_store();
    let token_key = token_key.inner();
    let management_token = SignedToken::from(management_token);
    let submitter_db = DBWrapper {
        db: &DieselSQliteDB { conn: submitter_db },
    };

    let cert = management::authenticated_download(management_token, &*keystore, &submitter_db, token_key).await?;
    Ok(export_armored_cert(&cert))
}
