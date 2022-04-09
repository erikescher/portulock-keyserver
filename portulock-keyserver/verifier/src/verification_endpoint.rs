/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::iter::FromIterator;
use std::str::FromStr;

use anyhow::anyhow;
use rocket::form::Form;
use rocket::http::{Cookie, CookieJar, SameSite};
use rocket::response::Redirect;
use rocket::State;
use rocket_dyn_templates::Template;
use sequoia_openpgp::Fingerprint;
use shared::types::Email;
use verifier_lib::db_new::DBWrapper;
use verifier_lib::key_storage::KeyStore;
use verifier_lib::utils_verifier::expiration::ExpirationConfig;
use verifier_lib::verification;
use verifier_lib::verification::sso::AuthSystem;
use verifier_lib::verification::tokens::{SignedEmailVerificationToken, SignedNameVerificationToken};
use verifier_lib::verification::{AuthChallengeCookie, TokenKey};

use crate::db::diesel_sqlite::DieselSQliteDB;
use crate::db::SubmitterDBConn;
use crate::error::AnyhowErrorResponse;
use crate::holders::{KeyStoreHolder, MailerHolder};

#[get("/verify/email_request?<fpr>&<email>")]
#[tracing::instrument]
pub async fn verify_email_request(
    fpr: String,
    email: String,
    token_key: &State<TokenKey>,
    expiration_config: &State<ExpirationConfig>,
    mailer: &State<MailerHolder>,
) -> Result<String, AnyhowErrorResponse> {
    let fpr = Fingerprint::from_hex(fpr.as_str())?;
    let email = Email::parse(email.as_str())?;
    let token_key = token_key.inner();
    let expiration_config = expiration_config.inner();
    let mailer = mailer.inner().get_mailer();
    verification::verify_email_request(&fpr, &email, token_key, expiration_config, mailer).await?;
    Ok("Verification email requested!".into())
}

#[get("/verify/email?<token>")]
#[tracing::instrument]
pub async fn verify_email(token: String, token_key: &State<TokenKey>) -> Result<Template, AnyhowErrorResponse> {
    let email_token = SignedEmailVerificationToken::from(token);
    let token_key = token_key.inner();

    let context: HashMap<&str, String, RandomState> = HashMap::from_iter([
        ("email", email_token.verify(token_key)?.email),
        ("fpr", email_token.verify(token_key)?.fpr),
        ("confirm_url", "/verify/confirm".to_string()),
        ("email_token", email_token.get_data().to_string()),
    ]);
    Ok(Template::render("verify_email", context))
}

const COOKIE_KEY: &str = "auth_challenge";

#[get("/verify/name_start?<fpr>")]
#[tracing::instrument]
pub async fn verify_name_start(
    fpr: String,
    auth_system: &State<AuthSystem>,
    cookies: &CookieJar<'_>,
) -> Result<Redirect, AnyhowErrorResponse> {
    let fpr = Fingerprint::from_str(fpr.as_str())?;
    let auth_system = auth_system.inner();

    let (auth_url, cookie_data) = verification::verify_name_start(fpr, auth_system).await?;

    let cookie = Cookie::build(COOKIE_KEY, serde_json::to_string(&cookie_data).map_err(|e| anyhow!(e))?)
        .same_site(SameSite::None)
        .secure(true)
        .finish();
    cookies.add_private(cookie);

    Ok(Redirect::to(auth_url))
}

#[get("/verify/name_code?<state>&<code>")]
#[tracing::instrument]
pub async fn verify_oidc_code(
    state: &str,
    code: &str,
    auth_system: &State<AuthSystem>,
    cookies: &CookieJar<'_>,
    token_key: &State<TokenKey>,
    expiration_config: &State<ExpirationConfig>,
) -> Result<Template, AnyhowErrorResponse> {
    verify_name_auth_system(
        Some(&state.to_string()),
        code,
        auth_system,
        cookies,
        token_key,
        expiration_config,
    )
    .await
    .map_err(|e| e.into())
}

#[get("/verify/saml/metadata")]
#[tracing::instrument]
pub async fn verify_saml_metadata(auth_system: &State<AuthSystem>) -> Result<String, AnyhowErrorResponse> {
    match auth_system.inner() {
        AuthSystem::Saml(saml) => Ok(saml.get_metadata().to_string()),
        AuthSystem::Oidc(_) => Err(anyhow!("SAML metadata requested for OIDC AuthSystem!").into()),
    }
}

#[post("/verify/saml/slo")]
#[tracing::instrument]
pub async fn verify_saml_slo() -> Result<String, AnyhowErrorResponse> {
    Err(anyhow!("SAML Single Logout Service is not implemented!").into())
}

#[derive(FromForm, Debug)]
pub struct AssertionConsumerServiceMessage {
    #[field(name = "SAMLResponse")]
    saml_response: String,
    #[field(name = "RelayState")]
    relay_state: Option<String>,
}

#[post("/verify/saml/acs", data = "<acs_message>")]
#[tracing::instrument]
pub async fn verify_saml_acs(
    acs_message: Form<AssertionConsumerServiceMessage>,
    auth_system: &State<AuthSystem>,
    cookies: &CookieJar<'_>,
    token_key: &State<TokenKey>,
    expiration_config: &State<ExpirationConfig>,
) -> Result<Template, AnyhowErrorResponse> {
    verify_name_auth_system(
        acs_message.relay_state.as_ref(),
        &acs_message.saml_response,
        auth_system,
        cookies,
        token_key,
        expiration_config,
    )
    .await
    .map_err(|e| e.into())
}

#[tracing::instrument]
async fn verify_name_auth_system(
    auth_state: Option<&String>,
    auth_response: &str,
    auth_system: &State<AuthSystem>,
    cookies: &CookieJar<'_>,
    token_key: &State<TokenKey>,
    expiration_config: &State<ExpirationConfig>,
) -> Result<Template, anyhow::Error> {
    let cookie = cookies
        .get_private(COOKIE_KEY)
        .ok_or_else(|| anyhow!("No auth_challenge cookie found!"))?;
    let cookie_data: AuthChallengeCookie = serde_json::from_str(cookie.value())?;
    let fpr = cookie_data.fpr.clone();
    let auth_system = auth_system.inner();
    let token_key = token_key.inner();
    let expiration_config = expiration_config.inner();

    let (name_tokens, email_tokens) = verification::verify_name_auth_system(
        auth_state,
        auth_response,
        cookie_data,
        auth_system,
        token_key,
        expiration_config,
    )
    .await?;

    cookies.remove_private(cookie);

    let (names, emails, name_tokens_combined, email_tokens_combined) =
        tokens_to_context(name_tokens, email_tokens, token_key)?;

    let context: HashMap<&str, String, RandomState> = HashMap::from_iter([
        ("name", names),
        ("email", emails),
        ("fpr", fpr),
        ("confirm_url", "/verify/confirm".to_string()),
        ("name_token", name_tokens_combined),
        ("email_token", email_tokens_combined),
    ]);
    Ok(Template::render("verify_name_code", context))
}

#[tracing::instrument]
fn tokens_to_context(
    name_tokens: Vec<SignedNameVerificationToken>,
    email_tokens: Vec<SignedEmailVerificationToken>,
    token_key: &TokenKey,
) -> Result<(String, String, String, String), anyhow::Error> {
    let names = name_tokens
        .iter()
        .flat_map(|name_token| name_token.verify(token_key))
        .map(|t| t.name)
        .collect();
    let names = concat_strings(&names, ", ");

    let mut name_tokens_combined = String::new();
    for token in name_tokens {
        name_tokens_combined += token.get_data();
        name_tokens_combined += ":";
    }
    let name_tokens_combined = truncate_last_char(&name_tokens_combined);

    let emails = email_tokens
        .iter()
        .flat_map(|email_token| email_token.verify(token_key))
        .map(|t| t.email)
        .collect();
    let emails = concat_strings(&emails, ", ");

    let mut email_tokens_combined = String::new();
    for token in email_tokens {
        email_tokens_combined += token.get_data();
        email_tokens_combined += ":";
    }
    let email_tokens_combined = truncate_last_char(&email_tokens_combined);

    Ok((names, emails, name_tokens_combined, email_tokens_combined))
}

fn truncate_last_char(string: &str) -> String {
    let mut chars = string.chars();
    chars.next_back(); // discard last character
    chars.as_str().to_string()
}

fn concat_strings(strings: &Vec<String>, separator: &str) -> String {
    let mut result = String::new();
    for string in strings {
        result += string;
        result += separator;
    }
    for _ in separator.chars() {
        result = truncate_last_char(&result);
    }
    result
}

#[derive(FromForm, Debug)]
pub struct ConfirmPayload {
    name_token: Option<String>,
    email_token: Option<String>,
}

#[post("/verify/confirm", data = "<payload>")]
#[tracing::instrument]
pub async fn verify_confirm(
    payload: Form<ConfirmPayload>,
    submitter_db: SubmitterDBConn,
    keystore: &State<KeyStoreHolder>,
    token_key: &State<TokenKey>,
) -> Result<String, AnyhowErrorResponse> {
    let submitter_db = DBWrapper {
        db: &DieselSQliteDB { conn: submitter_db },
    };
    verify_confirm_async(
        payload.into_inner(),
        &submitter_db,
        &*keystore.inner().get_key_store(),
        token_key.inner(),
    )
    .await
}

#[tracing::instrument]
async fn verify_confirm_async(
    payload: ConfirmPayload,
    submitter_db: &DBWrapper<'_>,
    keystore: &(impl KeyStore + ?Sized),
    token_key: &TokenKey,
) -> Result<String, AnyhowErrorResponse> {
    if let Some(name_tokens) = payload.name_token {
        let name_tokens = name_tokens.split(':');
        for name_token in name_tokens {
            let name_token = SignedNameVerificationToken::from(name_token.to_string());
            verification::verify_name(name_token, submitter_db, token_key, keystore).await?;
        }
    }
    if let Some(email_tokens) = payload.email_token {
        let email_tokens = email_tokens.split(':');
        for email_token in email_tokens {
            let email_token = SignedEmailVerificationToken::from(email_token.to_string());
            verification::verify_email(email_token, submitter_db, token_key, keystore).await?;
        }
    }
    Ok("Verified successfully.".into())
}
