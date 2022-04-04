/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::convert::TryFrom;
use std::iter::FromIterator;

use anyhow::anyhow;
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
use tracing::{info, trace};

use crate::verification::sso::{AuthChallengeData, VerifiedSSOClaims};

#[derive(Debug)]
pub struct OidcVerifier {
    client: CoreClient,
}

#[tracing::instrument]
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

    trace!("OIDC Backend Request: {:?}", request);

    let response = client.execute(request).await.map_err(Error::Reqwest)?;

    let response = HttpResponse {
        status_code: response.status(),
        headers: response.headers().to_owned(),
        body: response.bytes().await.map_err(Error::Reqwest)?.to_vec(),
    };
    trace!(
        "OIDC Backend Response:\n status:{}\n headers: {:#?}\n body_as_text: {}",
        response.status_code,
        response.headers,
        String::from_utf8_lossy(response.body.as_slice())
    );
    Ok(response)
}

impl OidcVerifier {
    #[tracing::instrument]
    pub async fn new(
        issuer_url: &str,
        client_id: &str,
        client_secret: Option<&str>,
        endpoint_url: &str,
    ) -> Result<Self, anyhow::Error> {
        let provider_metadata =
            CoreProviderMetadata::discover_async(IssuerUrl::new(issuer_url.to_string())?, async_http_client)
                .await
                .map_err(|e| anyhow!(e))?;
        let client_secret = client_secret.map(|s| ClientSecret::new(s.to_string()));
        let redirect_url = endpoint_url.to_string() + "/verify/name_code";
        let client =
            CoreClient::from_provider_metadata(provider_metadata, ClientId::new(client_id.to_string()), client_secret)
                .set_redirect_uri(RedirectUrl::new(redirect_url)?);

        Ok(Self { client })
    }

    #[tracing::instrument]
    pub fn get_auth_url(&self) -> Result<(Url, AuthChallengeData), anyhow::Error> {
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

        info!(
            "OIDC Authentication Challenge:\n auth_url: {}\n nonce: {}",
            auth_url,
            nonce.secret()
        );

        Ok((
            auth_url,
            OIDCAuthChallenge::new(csrf_token, nonce, pkce_verifier).into(),
        ))
    }

    #[tracing::instrument]
    pub async fn verify_and_extract_claims(
        &self,
        auth_challenge: AuthChallengeData,
        auth_response: &str,
        auth_state: &str,
    ) -> Result<VerifiedSSOClaims, anyhow::Error> {
        let auth_challenge = OIDCAuthChallenge::try_from(auth_challenge)?;

        if auth_challenge.get_state() != auth_state {
            return Err(anyhow!("Failed to validate OAuth State parameter!"));
        }

        let token_response = self
            .client
            .exchange_code(AuthorizationCode::new(auth_response.to_string()))
            .set_pkce_verifier(auth_challenge.pkce_verifier)
            .request_async(async_http_client)
            .await
            .map_err(|e| anyhow!(e))?;

        info!("OIDC ID Token: {:?}", token_response.id_token()); // TODO strip signature from log

        let id_token = token_response
            .id_token()
            .ok_or_else(|| anyhow!("Server did not return an ID token"))?;

        let claims = id_token
            .claims(&self.client.id_token_verifier(), &auth_challenge.nonce)
            .map_err(|e| anyhow!(e))?;

        info!("OIDC Claims from Token: {:?}", claims);

        let mut claims_in_progress = OpenIDConnectClaimsInProgress::from(claims);
        if !claims_in_progress.check_complete() {
            // We could not obtain sufficient information from the IDToken itself and need to consult the userinfo-endpoint.

            // Verify an AccessTokenHash if provided. This prevents us from combining UserInfo of a different user with our IDToken.
            if let Some(expected_access_token_hash) = claims.access_token_hash() {
                let actual_access_token_hash = AccessTokenHash::from_token(
                    token_response.access_token(),
                    &id_token.signing_alg().map_err(|e| anyhow!(e))?,
                )
                .map_err(|e| anyhow!(e))?;
                if actual_access_token_hash != *expected_access_token_hash {
                    return Err(anyhow!("Invalid access token"));
                }
            }

            let userinfo_request = self
                .client
                .user_info(token_response.access_token().to_owned(), Some(claims.subject().clone()));
            // TODO log the error even if we are ignoring it.
            if let Ok(request) = userinfo_request {
                if let Ok(claims) = request.request_async(async_http_client).await {
                    info!("OIDC Claims from UserInfo: {:?}", claims);
                    claims_in_progress.add_userinfo_claims(claims)
                }
                // TODO log the error even if we are ignoring it.
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
    fn complete(self) -> Result<VerifiedSSOClaims, anyhow::Error> {
        let mut emails = vec![];
        if let Some(email) = self.verified_email {
            emails.push(email)
        }
        match self.name {
            None => Err(anyhow!(
                "Failed to obtain Name from both the IdentityToken and (if available) the UserInfo Endpoint!"
            )),
            Some(name) => Ok(VerifiedSSOClaims {
                names: vec![name],
                emails,
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

impl TryFrom<AuthChallengeData> for OIDCAuthChallenge {
    type Error = anyhow::Error;

    fn try_from(value: AuthChallengeData) -> Result<Self, Self::Error> {
        let challenge_type = value
            .get("type")
            .ok_or_else(|| anyhow!("Missing type in AuthChallenge!"))?;
        if challenge_type != "oidc" {
            return Err(anyhow!("Wrong type in AuthChallenge!"));
        }
        Ok(Self {
            csrf_token: CsrfToken::new(
                value
                    .get("csrf_token")
                    .ok_or_else(|| anyhow!("Missing csrf_token in oidc AuthChallenge!"))?
                    .to_string(),
            ),
            nonce: Nonce::new(
                value
                    .get("nonce")
                    .ok_or_else(|| anyhow!("Missing nonce in oidc AuthChallenge!"))?
                    .to_string(),
            ),
            pkce_verifier: PkceCodeVerifier::new(
                value
                    .get("pkce_verifier")
                    .ok_or_else(|| anyhow!("Missing pkce_verifier in oidc AuthChallenge!"))?
                    .to_string(),
            ),
        })
    }
}

impl From<OIDCAuthChallenge> for AuthChallengeData {
    fn from(oidc: OIDCAuthChallenge) -> Self {
        let mut map = AuthChallengeData::new();
        map.insert("type".to_string(), "oidc".to_string());
        map.insert("csrf_token".to_string(), oidc.csrf_token.secret().to_string());
        map.insert("nonce".to_string(), oidc.nonce.secret().to_string());
        map.insert("pkce_verifier".to_string(), oidc.pkce_verifier.secret().to_string());
        map
    }
}
