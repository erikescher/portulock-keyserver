/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::iter::FromIterator;
use std::str::FromStr;

use rocket::http::{Cookie, Cookies, SameSite};
use rocket::request::Form;
use rocket::response::Redirect;
use rocket::State;
use rocket_contrib::templates::Template;
use sequoia_openpgp::Fingerprint;
use shared::errors::CustomError;
use shared::types::Email;
use shared::utils::async_helper::AsyncHelper;
use verifier_lib::utils_verifier::expiration::ExpirationConfig;
use verifier_lib::verification;
use verifier_lib::verification::tokens::oidc_verification::OidcVerifier;
use verifier_lib::verification::tokens::{SignedEmailVerificationToken, SignedNameVerificationToken};
use verifier_lib::verification::{AuthChallengeCookie, TokenKey};

use crate::holders::{KeyStoreHolder, MailerHolder};
use crate::SubmitterDBConn;

#[get("/verify/email_request?<fpr>&<email>")]
#[tracing::instrument]
pub fn verify_email_request(
    fpr: String,
    email: String,
    token_key: State<TokenKey>,
    expiration_config: State<ExpirationConfig>,
    mailer: State<MailerHolder>,
) -> Result<String, CustomError> {
    let fpr = Fingerprint::from_hex(fpr.as_str())?;
    let email = Email::parse(email.as_str())?;
    let token_key = token_key.inner();
    let expiration_config = expiration_config.inner();
    let mailer = mailer.inner().get_mailer();
    AsyncHelper::new()
        .expect("Failed to create async runtime.")
        .wait_for(verification::verify_email_request(
            &fpr,
            &email,
            token_key,
            expiration_config,
            mailer,
        ))?;
    Ok("Verification email requested!".into())
}

#[get("/verify/email?<token>")]
#[tracing::instrument]
pub fn verify_email(token: String, token_key: State<TokenKey>) -> Result<Template, CustomError> {
    let email_token = SignedEmailVerificationToken::from(token);
    let token_key = token_key.inner();

    let context: HashMap<&str, String, RandomState> = HashMap::from_iter([
        ("email", email_token.verify(token_key)?.email),
        ("fpr", email_token.verify(token_key)?.fpr),
        ("confirm_url", "/verify/email_confirm".to_string()),
        ("email_token", email_token.get_data().to_string()),
    ]);
    Ok(Template::render("verify_email", context))
}

#[derive(FromForm, Debug)]
pub struct ConfirmEmailPayload {
    email_token: String,
}

#[post("/verify/email_confirm", data = "<payload>")]
#[tracing::instrument]
pub fn verify_email_confirm(
    payload: Form<ConfirmEmailPayload>,
    submitter_db: SubmitterDBConn,
    keystore: State<KeyStoreHolder>,
    token_key: State<TokenKey>,
) -> Result<String, CustomError> {
    let keystore = keystore.inner().get_key_store();
    let token = SignedEmailVerificationToken::from(payload.email_token.clone());
    let token_key = token_key.inner();
    AsyncHelper::new()
        .expect("Failed to create async runtime.")
        .wait_for(verification::verify_email(token, &submitter_db, token_key, &*keystore))?;

    Ok("Email verified successfully!".to_string())
}

const COOKIE_KEY: &str = "auth_challenge";

#[get("/verify/name_start?<fpr>")]
#[tracing::instrument]
pub fn verify_name_start(
    fpr: String,
    oidc_verifier: State<OidcVerifier>,
    mut cookies: Cookies,
) -> Result<Redirect, CustomError> {
    let fpr = Fingerprint::from_str(fpr.as_str())?;
    let oidc_verifier = oidc_verifier.inner();

    let (auth_url, cookie_data) = AsyncHelper::new()
        .expect("Failed to create async runtime.")
        .wait_for(verification::verify_name_start(fpr, oidc_verifier))?;

    let cookie = Cookie::build(COOKIE_KEY, serde_json::to_string(&cookie_data)?)
        .same_site(SameSite::Lax)
        .finish();
    cookies.add_private(cookie);

    Ok(Redirect::to(auth_url))
}

#[get("/verify/name_code?<state>&<code>")]
#[tracing::instrument]
pub fn verify_name_code(
    state: String,
    code: String,
    oidc_verifier: State<OidcVerifier>,
    mut cookies: Cookies,
    token_key: State<TokenKey>,
    expiration_config: State<ExpirationConfig>,
) -> Result<Template, CustomError> {
    let cookie = cookies
        .get_private(COOKIE_KEY)
        .ok_or("No auth_challenge cookie found!")?;
    let cookie_data: AuthChallengeCookie = serde_json::from_str(cookie.value())?;
    let oidc_verifier = oidc_verifier.inner();
    let token_key = token_key.inner();
    let expiration_config = expiration_config.inner();

    let (name_token, email_token) =
        AsyncHelper::new()
            .expect("Failed to create async runtime.")
            .wait_for(verification::verify_name_code(
                state,
                code,
                oidc_verifier,
                cookie_data,
                token_key,
                expiration_config,
            ))?;

    cookies.remove_private(cookie);

    let email_token = email_token.unwrap_or_else(|| SignedEmailVerificationToken::from("".to_string()));

    let name_token_data = name_token.verify(token_key)?;
    let context: HashMap<&str, String, RandomState> = HashMap::from_iter([
        ("name", name_token_data.name),
        ("email", email_token.verify(token_key)?.email),
        ("fpr", name_token_data.fpr),
        ("confirm_url", "/verify/name_confirm".to_string()),
        ("name_token", name_token.get_data().to_string()),
        ("email_token", email_token.get_data().to_string()),
    ]);
    Ok(Template::render("verify_name_code", context))
}

#[derive(FromForm, Debug)]
pub struct ConfirmNamePayload {
    name_token: String,
    email_token: Option<String>,
}

#[post("/verify/name_confirm", data = "<payload>")]
#[tracing::instrument]
pub fn verify_name_confirm(
    payload: Form<ConfirmNamePayload>,
    submitter_db: SubmitterDBConn,
    keystore: State<'_, KeyStoreHolder>,
    token_key: State<TokenKey>,
) -> Result<String, CustomError> {
    let keystore = keystore.inner().get_key_store();
    let name_token = SignedNameVerificationToken::from(payload.name_token.clone());
    let email_token = payload.email_token.clone().map(SignedEmailVerificationToken::from);
    let token_key = token_key.inner();

    AsyncHelper::new()
        .expect("Failed to create async runtime.")
        .wait_for(verification::verify_name_confirm(
            name_token,
            email_token,
            token_key,
            &submitter_db,
            &*keystore,
        ))?;

    Ok("Name verified successfully!".to_string())
}
