/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::iter::FromIterator;

use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreGenderClaim, CoreIdTokenClaims, CoreProviderMetadata,
};
use openidconnect::reqwest::Error;
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EmptyAdditionalClaims, HttpRequest,
    HttpResponse, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, UserInfoClaims,
};
use openidconnect::{OAuth2TokenResponse, TokenResponse};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use shared::errors::CustomError;

use crate::errors::VerifierError;

pub struct OidcVerifier {
    client: CoreClient,
}

pub async fn async_http_client(request: HttpRequest) -> Result<HttpResponse, Error<reqwest::Error>> {
    let client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(Error::Reqwest)?;

    let request = client
        .request(request.method, request.url.as_str())
        .headers(HeaderMap::from_iter(
            request
                .headers
                .iter()
                .map(|(n, v)| (HeaderName::from(n), HeaderValue::from(v))),
        ))
        .body(request.body)
        .build()
        .map_err(Error::Reqwest)?;

    println!("OIDC Backend Request: {:?}", request);

    let response = client.execute(request).await.map_err(Error::Reqwest)?;

    println!("OIDC Backend Response: {:?}", response);

    Ok(HttpResponse {
        status_code: response.status(),
        headers: response.headers().to_owned(),
        body: response.bytes().await.map_err(Error::Reqwest)?.to_vec(),
    })
}

impl OidcVerifier {
    pub async fn new(
        issuer_url: &str,
        client_id: &str,
        client_secret: Option<&str>,
        endpoint_url: &str,
    ) -> Result<Self, VerifierError> {
        let provider_metadata =
            CoreProviderMetadata::discover_async(IssuerUrl::new(issuer_url.to_string())?, async_http_client)
                .await
                .map_err(|e| CustomError::String(e.to_string()))?;
        let client_secret = client_secret.map(|s| ClientSecret::new(s.to_string()));
        let redirect_url = endpoint_url.to_string() + "/verify/name_code";
        let client =
            CoreClient::from_provider_metadata(provider_metadata, ClientId::new(client_id.to_string()), client_secret)
                .set_redirect_uri(RedirectUrl::new(redirect_url)?);

        Ok(Self { client })
    }

    pub fn get_auth_url(&self) -> (Url, OIDCAuthChallenge) {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (auth_url, csrf_token, nonce) = self
            .client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("profile".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        println!("Authentication Challenge:\n auth_url: {}\n", auth_url);

        (auth_url, OIDCAuthChallenge::new(csrf_token, nonce, pkce_verifier))
    }

    pub async fn verify_token_and_extract_claims(
        &self,
        auth_challenge: OIDCAuthChallenge,
        authorization_code: &str,
    ) -> Result<VerifiedOpenIDConnectClaims, CustomError> {
        let token_response = self
            .client
            .exchange_code(AuthorizationCode::new(authorization_code.to_string()))
            .set_pkce_verifier(auth_challenge.pkce_verifier)
            .request_async(async_http_client)
            .await
            .map_err(|e| CustomError::String(e.to_string()))?;

        let id_token = token_response
            .id_token()
            .ok_or_else(|| CustomError::String("Server did not return an ID token".to_string()))?;

        let claims = id_token
            .claims(&self.client.id_token_verifier(), &auth_challenge.nonce)
            .map_err(|e| CustomError::String(e.to_string()))?;

        println!("Claims from Token: {:?}", claims);

        let mut claims_in_progress = OpenIDConnectClaimsInProgress::from(claims);
        if !claims_in_progress.check_complete() {
            // We could not obtain sufficient information from the IDToken itself and need to consult the userinfo-endpoint.

            // Verify an AccessTokenHash if provided. This prevents us from combining UserInfo of a different user with our IDToken.
            if let Some(expected_access_token_hash) = claims.access_token_hash() {
                let actual_access_token_hash = AccessTokenHash::from_token(
                    token_response.access_token(),
                    &id_token.signing_alg().map_err(|e| CustomError::String(e.to_string()))?,
                )
                .map_err(|e| CustomError::String(e.to_string()))?;
                if actual_access_token_hash != *expected_access_token_hash {
                    return Err(CustomError::String("Invalid access token".to_string()));
                }
            }

            let userinfo_request = self
                .client
                .user_info(token_response.access_token().to_owned(), Some(claims.subject().clone()));
            if let Ok(request) = userinfo_request {
                if let Ok(claims) = request.request_async(async_http_client).await {
                    println!("Claims from UserInfo: {:?}", claims);
                    claims_in_progress.add_userinfo_claims(claims)
                }
            }
        }

        claims_in_progress.complete()
    }
}

struct OpenIDConnectClaimsInProgress {
    name: Option<String>,
    verified_email: Option<String>,
}

impl OpenIDConnectClaimsInProgress {
    fn complete(self) -> Result<VerifiedOpenIDConnectClaims, CustomError> {
        match self.name {
            None => Err(CustomError::String(
                "Failed to obtain Name from both the IdentityToken and (if available) the UserInfo Endpoint!"
                    .to_string(),
            )),
            Some(name) => Ok(VerifiedOpenIDConnectClaims {
                name,
                verified_email: self.verified_email,
            }),
        }
    }

    fn check_complete(&self) -> bool {
        self.name.is_some()
    }

    fn add_userinfo_claims(&mut self, claims: UserInfoClaims<EmptyAdditionalClaims, CoreGenderClaim>) {
        if self.name.is_none() {
            self.name = claims
                .name()
                .and_then(|ln| ln.iter().next())
                .map(|(_, n)| n.to_string());
        }

        if self.verified_email.is_none() && claims.email_verified() == Some(true) {
            self.verified_email = claims.email().map(|e| e.to_string());
        }
    }
}

impl From<&CoreIdTokenClaims> for OpenIDConnectClaimsInProgress {
    fn from(claims: &CoreIdTokenClaims) -> Self {
        let email_verified = matches!(claims.email_verified(), Some(true));
        Self {
            name: claims
                .name()
                .and_then(|ln| ln.iter().next())
                .map(|(_, n)| n.to_string()),
            verified_email: claims.email().and_then(|e| match email_verified {
                true => Some(e.to_string()),
                false => None,
            }),
        }
    }
}

#[derive(Debug)]
pub struct VerifiedOpenIDConnectClaims {
    pub name: String,
    pub verified_email: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OIDCAuthChallenge {
    csrf_token: CsrfToken,
    nonce: Nonce,
    pkce_verifier: PkceCodeVerifier,
}

impl OIDCAuthChallenge {
    fn new(csrf_token: CsrfToken, nonce: Nonce, pkce_verifier: PkceCodeVerifier) -> Self {
        Self {
            csrf_token,
            nonce,
            pkce_verifier,
        }
    }

    pub fn get_state(&self) -> &str {
        self.csrf_token.secret().as_str()
    }
}
