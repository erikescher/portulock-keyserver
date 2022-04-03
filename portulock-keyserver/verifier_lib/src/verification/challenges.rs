use std::collections::HashMap;
use std::iter;

use sequoia_openpgp::{Cert, Fingerprint};
use serde::Serialize;
use shared::types::Email;

use crate::certs::CertWithSingleUID;

#[derive(Serialize, Clone, Debug)]
#[serde(tag = "type")]
pub enum VerificationChallenge {
    Name(NameVerificationChallenge),
    Email(EmailVerificationChallenge),
}

#[derive(Clone, Debug, Serialize)]
pub struct NameVerificationChallenge {
    fpr: String,
    name: String,
}

impl NameVerificationChallenge {
    pub fn name(&self) -> &str {
        self.name.as_str()
    }
    pub fn fpr(&self) -> &str {
        self.fpr.as_str()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct EmailVerificationChallenge {
    fpr: String,
    email: String,
}

impl EmailVerificationChallenge {
    pub fn new(fpr: &Fingerprint, email: &Email) -> Self {
        Self {
            fpr: fpr.to_hex(),
            email: email.get_email(),
        }
    }
    pub fn email(&self) -> &str {
        self.email.as_str()
    }
    pub fn fpr(&self) -> &str {
        self.fpr.as_str()
    }
}

#[tracing::instrument]
pub fn create_verification_challenges(cert: Cert) -> Vec<VerificationChallenge> {
    let mut challenge_holder = ChallengeHolder::new(cert.fingerprint().to_hex().as_str());
    for cert_holder in CertWithSingleUID::iterate_over_cert(&cert) {
        let uid = cert_holder.userid().component();
        match uid.name().unwrap_or_default() {
            None => {}
            Some(n) => {
                challenge_holder.add_name(n.as_str());
            }
        };
        match uid.email_normalized().unwrap_or_default() {
            None => {}
            Some(e) => {
                challenge_holder.add_email(e.as_str());
            }
        };
    }
    challenge_holder.into()
}

#[derive(Debug)]
struct ChallengeHolder {
    fpr: String,
    names: HashMap<String, NameVerificationChallenge>,
    mails: HashMap<String, EmailVerificationChallenge>,
}

impl ChallengeHolder {
    fn new(fpr: &str) -> Self {
        ChallengeHolder {
            fpr: fpr.to_string(),
            names: HashMap::new(),
            mails: HashMap::new(),
        }
    }

    fn add_name(&mut self, n: &str) {
        match self.names.get(n) {
            None => {
                self.names.insert(
                    String::from(n),
                    NameVerificationChallenge {
                        fpr: self.fpr.clone(),
                        name: String::from(n),
                    },
                );
            }
            Some(_) => {}
        }
    }

    fn add_email(&mut self, e: &str) {
        match self.mails.get(e) {
            None => {
                self.mails.insert(
                    String::from(e),
                    EmailVerificationChallenge {
                        fpr: self.fpr.clone(),
                        email: String::from(e),
                    },
                );
            }
            Some(_) => {}
        }
    }
}

impl From<ChallengeHolder> for Vec<VerificationChallenge> {
    fn from(mut ch: ChallengeHolder) -> Self {
        iter::empty()
            .chain(ch.names.drain().map(|(_, n)| VerificationChallenge::Name(n)))
            .chain(ch.mails.drain().map(|(_, e)| VerificationChallenge::Email(e)))
            .collect()
    }
}
