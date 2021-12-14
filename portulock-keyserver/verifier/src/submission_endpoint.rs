/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use rocket::request::Form;
use rocket::State;
use shared::errors::CustomError;

use crate::submission::submit_keys;
use crate::submission::SubmissionConfig;
use crate::utils::armor;
use crate::utils::async_helper::AsyncHelper;
use crate::utils_verifier::expiration::ExpirationConfig;
use crate::verification::TokenKey;
use crate::{KeyStoreHolder, MailerHolder, SubmitterDBConn};

#[derive(FromForm)]
pub struct KeySubmission {
    keytext: String,
}

#[post("/pks/add?<no_mails>", data = "<submission>")]
#[allow(clippy::too_many_arguments)]
pub fn submission(
    submission_db: SubmitterDBConn,
    mailer: State<MailerHolder>,
    submission_config: State<SubmissionConfig>,
    expiration_config: State<ExpirationConfig>,
    token_key: State<TokenKey>,
    submission: Form<KeySubmission>,
    keystore: State<KeyStoreHolder>,
    no_mails: Option<bool>,
) -> Result<String, CustomError> {
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

    let result = AsyncHelper::new()
        .expect("Failed to create async runtime.")
        .wait_for(submit_keys(
            &submission_db,
            mailer,
            submission_config,
            expiration_config,
            token_key,
            certs,
            &*keystore,
        ))?;

    serde_json::to_string(&result).map_err(CustomError::from)
}