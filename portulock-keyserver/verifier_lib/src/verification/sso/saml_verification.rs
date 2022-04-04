/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::convert::TryFrom;
use std::fmt::{Debug, Formatter};

use anyhow::anyhow;
use reqwest::Url;
use samael::metadata::EntityDescriptor;
use samael::schema::AttributeStatement;
use samael::service_provider::ServiceProvider;
use samael::service_provider::ServiceProviderBuilder;
use serde::{Deserialize, Serialize};

use crate::verification::sso::{AuthChallengeData, VerifiedSSOClaims};

pub struct SamlVerifier {
    idp_url: String,
    sp: ServiceProvider,
    metadata: String,
    attribute_selectors_name: Vec<String>,
    attribute_selectors_email: Vec<String>,
}

impl Debug for SamlVerifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SamlVerifier:\n idp_url: {}\n sp: [DEBUG not implemented]\n metadata: {}\n attr_select_name: {:?}\n attr_select_mail: {:?}\n", self.idp_url, self.metadata, self.attribute_selectors_name, self.attribute_selectors_email)
        // TODO debug output for SP
    }
}

impl SamlVerifier {
    #[tracing::instrument]
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        idp_url: &str,
        idp_metadata_url: &str,
        endpoint_url: &str,
        entity_id: &str,
        certificate: &str,
        private_key: &str,
        attribute_selectors_name: Vec<String>,
        attribute_selectors_email: Vec<String>,
    ) -> Result<Self, anyhow::Error> {
        let idp_metadata = reqwest::get(idp_metadata_url).await?.text().await?;

        let idp_metadata: EntityDescriptor = samael::metadata::de::from_str(&idp_metadata)?;
        let sp_certificate = openssl::x509::X509::from_pem(certificate.as_bytes())?;
        let sp_private_key = openssl::rsa::Rsa::private_key_from_pem(private_key.as_bytes())?;

        let service_provider: ServiceProvider = ServiceProviderBuilder::default()
            .entity_id(entity_id.to_string())
            .key(sp_private_key)
            .certificate(sp_certificate)
            .allow_idp_initiated(false)
            //.contact_person()
            .idp_metadata(idp_metadata)
            .acs_url(endpoint_url.to_string() + "/verify/saml/acs")
            .slo_url(endpoint_url.to_string() + "/verify/saml/slo")
            .build()?;

        let sp_metadata = service_provider
            .metadata()
            .map_err(|e| anyhow!("std::error::Error: {:?}", e.as_ref()))?
            .to_xml()
            .map_err(|e| anyhow!("std::error::Error: {:?}", e.as_ref()))?;

        Ok(Self {
            idp_url: idp_url.to_string(),
            sp: service_provider,
            metadata: sp_metadata,
            attribute_selectors_name,
            attribute_selectors_email,
        })
    }

    #[tracing::instrument]
    pub fn get_metadata(&self) -> &str {
        self.metadata.as_str()
    }

    #[tracing::instrument]
    pub fn get_auth_url(&self) -> Result<(Url, AuthChallengeData), anyhow::Error> {
        let auth_request = self
            .sp
            .make_authentication_request(&self.idp_url)
            .map_err(|e| anyhow!("std::error::Error: {:?}", e.as_ref()))?;
        let auth_url = auth_request
            .redirect("")
            .map_err(|e| anyhow!("std::error::Error: {:?}", e.as_ref()))?
            .ok_or_else(|| anyhow!("Failed to generate AuthURL!"))?;
        println!(
            "Authentication Challenge:\n auth_url: {}\n request_id: {}\n",
            auth_url, auth_request.id
        );
        Ok((
            auth_url,
            SAMLAuthChallenge {
                request_id: auth_request.id,
            }
            .into(),
        ))
    }

    #[tracing::instrument]
    pub async fn verify_and_extract_claims(
        &self,
        auth_challenge: AuthChallengeData,
        auth_response: &str,
    ) -> Result<VerifiedSSOClaims, anyhow::Error> {
        let auth_challenge = SAMLAuthChallenge::try_from(auth_challenge)?;
        let assertion = self
            .sp
            .parse_response(auth_response, &[auth_challenge.request_id])
            .map_err(|e| anyhow!("std::error::Error: {:?}", e.as_ref()))?;

        let names = extract_values_from_matching_attributes(
            &assertion.attribute_statements.clone().unwrap_or_default(),
            &self.attribute_selectors_name,
        );
        let emails = extract_values_from_matching_attributes(
            &assertion.attribute_statements.clone().unwrap_or_default(),
            &self.attribute_selectors_email,
        );

        println!(
            "Authentication Response:\n response_id: {}\n assertion: {:?}\n names: {:?}\n emails: {:?}",
            assertion.id, assertion, names, emails
        );

        Ok(VerifiedSSOClaims { names, emails })
    }
}

fn extract_values_from_matching_attributes(
    attribute_statements: &Vec<AttributeStatement>,
    selectors: &Vec<String>,
) -> Vec<String> {
    let mut values = vec![];
    for attribute_statement in attribute_statements {
        for attribute in &attribute_statement.attributes {
            for selector in selectors {
                if let Some(attribute_name) = &attribute.name {
                    if selector == attribute_name {
                        for value in &attribute.values {
                            if let Some(value) = &value.value {
                                values.push(value.clone())
                            }
                        }
                    }
                }
            }
        }
    }
    values
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SAMLAuthChallenge {
    request_id: String,
}

impl TryFrom<AuthChallengeData> for SAMLAuthChallenge {
    type Error = anyhow::Error;

    fn try_from(value: AuthChallengeData) -> Result<Self, Self::Error> {
        let challenge_type = value
            .get("type")
            .ok_or_else(|| anyhow!("Missing type in AuthChallenge!"))?;
        if challenge_type != "saml" {
            return Err(anyhow!("Wrong type in AuthChallenge!"));
        }
        Ok(Self {
            request_id: value
                .get("request_id")
                .ok_or_else(|| anyhow!("Missing request_id in saml AuthChallenge!"))?
                .to_string(),
        })
    }
}

impl From<SAMLAuthChallenge> for AuthChallengeData {
    fn from(saml: SAMLAuthChallenge) -> Self {
        let mut map = AuthChallengeData::new();
        map.insert("type".to_string(), "saml".to_string());
        map.insert("request_id".to_string(), saml.request_id);
        map
    }
}
