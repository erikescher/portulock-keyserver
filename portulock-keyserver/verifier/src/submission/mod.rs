/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

pub use mailer::Mailer;
pub use mailer::NoopMailer;
pub use mailer::SmtpMailer;
use sequoia_openpgp::Cert;

use crate::db::VerificationChallenge;
use crate::errors::VerifierError;
use crate::key_storage::KeyStore;
use crate::utils_verifier::expiration::ExpirationConfig;
use crate::verification::TokenKey;
use crate::SubmitterDBConn;

mod internal_submission;
mod mailer;

pub struct SubmissionConfig {
    allowed_domains: Vec<String>,
    additional_allowed_certifying_keys: Vec<Cert>,
}

impl SubmissionConfig {
    pub fn new(allowed_domains: Vec<String>, additional_allowed_certifying_keys: Vec<Cert>) -> Self {
        Self {
            allowed_domains,
            additional_allowed_certifying_keys,
        }
    }

    fn additional_allowed_certifying_keys(&self) -> Vec<Cert> {
        self.additional_allowed_certifying_keys.clone()
    }

    fn is_allowed_domain(&self, domain: &str) -> bool {
        self.allowed_domains.contains(&domain.to_string())
    }
}

pub async fn submit_keys(
    submitter_db: &SubmitterDBConn,
    mailer: &dyn Mailer,
    submission_config: &SubmissionConfig,
    expiration_config: &ExpirationConfig,
    token_key: &TokenKey,
    certs: Vec<Cert>,
    keystore: &(impl KeyStore + ?Sized),
) -> Result<Vec<VerificationChallenge>, VerifierError> {
    let mut combined_challenges = vec![];
    for cert in certs {
        let mut challenges = internal_submission::submit_key(
            submitter_db,
            mailer,
            submission_config,
            expiration_config,
            token_key,
            cert,
            &*keystore,
        )
        .await?;
        combined_challenges.append(&mut challenges);
    }
    Ok(combined_challenges)
}
