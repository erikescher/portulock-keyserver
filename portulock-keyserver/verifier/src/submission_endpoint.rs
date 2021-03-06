/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use anyhow::anyhow;
use rocket::form::Form;
use rocket::State;
use shared::utils::armor;
use verifier_lib::db_new::DBWrapper;
use verifier_lib::submission::submit_keys;
use verifier_lib::submission::SubmissionConfig;
use verifier_lib::utils_verifier::expiration::ExpirationConfig;
use verifier_lib::verification::TokenKey;

use crate::db::diesel_sqlite::DieselSQliteDB;
use crate::db::SubmitterDBConn;
use crate::error::AnyhowErrorResponse;
use crate::holders::{KeyStoreHolder, MailerHolder};

#[derive(FromForm, Debug)]
pub struct KeySubmission {
    keytext: String,
}

#[post("/pks/add?<no_mails>", data = "<submission>")]
#[allow(clippy::too_many_arguments)]
#[tracing::instrument]
pub async fn submission(
    submitter_db: SubmitterDBConn,
    mailer: &State<MailerHolder>,
    submission_config: &State<SubmissionConfig>,
    expiration_config: &State<ExpirationConfig>,
    token_key: &State<TokenKey>,
    submission: Form<KeySubmission>,
    keystore: &State<KeyStoreHolder>,
    no_mails: Option<bool>,
) -> Result<String, AnyhowErrorResponse> {
    let key_submission = submission.into_inner();
    let keytext = key_submission.keytext.as_str();
    let submission_config = submission_config.inner();
    let expiration_config = expiration_config.inner();
    let keystore = keystore.inner().get_key_store();
    let mailer = match no_mails {
        Some(false) => &MailerHolder::NoopMailer(),
        _ => mailer.inner(),
    };
    let mailer = mailer.get_mailer();
    let certs = armor::parse_certs(keytext)?;
    let token_key = token_key.inner();
    let submitter_db = DBWrapper {
        db: &DieselSQliteDB { conn: submitter_db },
    };

    let result = submit_keys(
        &submitter_db,
        mailer,
        submission_config,
        expiration_config,
        token_key,
        certs,
        &*keystore,
    )
    .await?;

    serde_json::to_string(&result).map_err(|e| anyhow!(e).into())
}
