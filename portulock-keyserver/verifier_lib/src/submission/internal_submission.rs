/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use sequoia_openpgp::cert::amalgamation::UserIDAmalgamation;
use sequoia_openpgp::Cert;
use shared::errors::CustomError;
use shared::filtering::applier::{KeyFilter, KeyFilterApplier};
use shared::filtering::filter_cert;
use shared::filtering::filters::KeyFilterSubtractingUserIDs;
use shared::filtering::filters::{
    KeyFilterAttestedCertifications, KeyFilterSubtractingPackets, KeyFilterWhitelistedCertifications,
};
use shared::types::Email;
use shared::utils::any_email;

use crate::db::{
    create_verification_challenges, get_pending_cert, store_uids_pending_verification, VerificationChallenge,
};
use crate::errors::VerifierError;
use crate::key_storage::{certify_and_publish_approved_cert, filter_cert_by_approved_uids, KeyStore};
use crate::submission::mailer::Mailer;
use crate::submission::SubmissionConfig;
use crate::utils_verifier::expiration::ExpirationConfig;
use crate::verification::tokens::EmailVerificationToken;
use crate::verification::{trigger_certification_and_publishing, TokenKey};
use crate::SubmitterDBConn;

#[tracing::instrument]
pub async fn submit_key(
    submitter_db: &SubmitterDBConn,
    mailer: &dyn Mailer,
    submission_config: &SubmissionConfig,
    expiration_config: &ExpirationConfig,
    token_key: &TokenKey,
    cert: Cert,
    keystore: &(impl KeyStore + ?Sized),
) -> Result<Vec<VerificationChallenge>, VerifierError> {
    println!("SUBMIT_KEY raw_submission: {:?}", cert);
    let cert = filter_unwanted_data(cert, submission_config, &*keystore).await?;
    println!("SUBMIT_KEY filtered for unwanted data: {:?}", cert);

    // Publish packets that are already verified/approved.
    let approved_cert = filter_cert_by_approved_uids(submitter_db, cert.clone()).await?;
    let cert: Cert = KeyFilterApplier::from(cert)
        .apply(KeyFilterSubtractingUserIDs::from_cert(&approved_cert))
        .into();
    println!(
        "SUBMISSION approved_certs: Storing {} approved UserIDs.",
        approved_cert.userids().len()
    );
    println!(
        "SUBMIT_KEY approved_cert: \n  {:?} remaining_cert: \n  {:?}",
        approved_cert, cert
    );
    if approved_cert.userids().len() > 0 {
        certify_and_publish_approved_cert(&*keystore, approved_cert).await?;
    }

    trigger_certification_and_publishing(cert.fingerprint().to_hex().as_str(), submitter_db, &*keystore).await?;

    // Skip packets that are already pending verification.
    let cert = match get_pending_cert(submitter_db, &cert.fingerprint()).await? {
        None => cert,
        Some(pc) => KeyFilterApplier::from(cert)
            .apply(KeyFilterSubtractingPackets::from_key(&pc))
            .into(),
    };
    println!("SUBMIT_KEY after subtracting pending packets: {:?}", cert);

    for userid in cert.userids() {
        println!("UserID Pending Verification: {:?}", userid.component())
    }

    // Issue verification challenges for the remaining packets and store them.
    // They will be published as the verification challenges are completed.
    store_uids_pending_verification(submitter_db, expiration_config, cert.clone()).await?;
    create_and_send_challenges(cert, mailer, token_key, expiration_config).await
}

#[tracing::instrument]
async fn filter_unwanted_data(
    cert: Cert,
    submission_config: &SubmissionConfig,
    keystore: &(impl KeyStore + ?Sized),
) -> Result<Cert, CustomError> {
    // Filter undesired data.
    let cert = filter_cert(&cert);

    // Filter by allowed email domains.
    let cert = filter_cert_by_allowed_domains(cert, submission_config);

    let cert: Cert = KeyFilterApplier::from(cert)
        .apply(KeyFiterAllowedCertifications {
            certs: submission_config.additional_allowed_certifying_keys(),
        })
        .into();

    // Skip packets that are already in the keystore.
    let cert = match keystore.get_by_fpr(&cert.fingerprint()).await? {
        None => cert,
        Some(ec) => KeyFilterApplier::from(cert)
            .apply(KeyFilterSubtractingPackets::from_key(&ec))
            .into(),
    };
    Ok(cert)
}

#[tracing::instrument]
async fn create_and_send_challenges(
    cert: Cert,
    mailer: &dyn Mailer,
    token_key: &TokenKey,
    expiration_config: &ExpirationConfig,
) -> Result<Vec<VerificationChallenge>, VerifierError> {
    let verification_challenges = create_verification_challenges(cert.clone());
    let primary_mail = any_email(&cert);
    for challenge in &verification_challenges {
        match challenge {
            VerificationChallenge::Name(nvc) => match primary_mail {
                None => return Err("Found no email to send NameVerificationChallenge to.".into()),
                Some(ref pm) => mailer.send_name_challenge(nvc, pm).await?,
            },
            VerificationChallenge::Email(evc) => {
                mailer
                    .send_signed_email_challenge(
                        &EmailVerificationToken::from(evc, expiration_config).sign(token_key),
                        &Email::parse(evc.email())?,
                    )
                    .await?
            }
        }
    }
    Ok(verification_challenges)
}

#[derive(Debug)]
struct KeyFiterAllowedCertifications {
    certs: Vec<Cert>,
}

impl KeyFilter for KeyFiterAllowedCertifications {
    fn name(&self) -> String {
        "KeyFilterAllowedCertifications".into()
    }

    fn description(&self) -> Option<String> {
        Some(format!("certs: {:?}", self.certs))
    }

    fn filter_cert(&mut self, cert: Cert) -> Cert {
        let whitelist = KeyFilterWhitelistedCertifications::new(self.certs.clone().into_iter());
        let whitelisted: Cert = KeyFilterApplier::from(cert.clone()).apply(whitelist).into();
        let attested = KeyFilterApplier::from(cert)
            .apply(KeyFilterAttestedCertifications {})
            .into();
        whitelisted
            .merge_public(attested)
            .expect("Public Keys are identical by construction!")
    }
}

#[tracing::instrument]
fn filter_cert_by_allowed_domains(cert: Cert, submission_config: &SubmissionConfig) -> Cert {
    cert.retain_userids(|uida: UserIDAmalgamation| match uida.component().email_normalized() {
        Ok(o) => match o {
            Some(e) => match Email::parse(e.as_str()) {
                Ok(e) => submission_config.is_allowed_domain(e.get_domain()),
                Err(_) => false,
            },
            None => false,
        },
        Err(_) => false,
    })
}
