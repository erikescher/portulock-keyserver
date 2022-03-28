extern crate alloc;
use alloc::boxed::Box;
use alloc::string::String;

use verifier_lib::key_storage::multi_keystore::MultiOpenPGPCALib;
use verifier_lib::key_storage::openpgp_ca_lib::OpenPGPCALib;
use verifier_lib::key_storage::KeyStore;
use verifier_lib::submission::mailer::{Mailer, NoopMailer, SmtpMailer};

#[derive(Debug)]
pub struct ExternalURLHolder(pub(crate) String);

#[derive(Debug)]
pub enum KeyStoreHolder {
    #[allow(dead_code)]
    OpenPGPCALib(OpenPGPCALib),
    MultiOpenPGPCALib(MultiOpenPGPCALib),
}

#[derive(Debug)] // TODO do not print secret to logs
pub struct InternalSecretHolder(pub(crate) String);

impl KeyStoreHolder {
    pub fn get_key_store(&self) -> Box<dyn KeyStore + '_> {
        match self {
            KeyStoreHolder::OpenPGPCALib(k) => Box::new(k),
            KeyStoreHolder::MultiOpenPGPCALib(k) => Box::new(k),
        }
    }
}

#[derive(Debug)]
pub enum MailerHolder {
    NoopMailer(),
    SmtpMailer(SmtpMailer),
}

impl MailerHolder {
    pub(crate) fn get_mailer(&self) -> &dyn Mailer {
        if let MailerHolder::SmtpMailer(s) = self {
            s
        } else {
            &NoopMailer {}
        }
    }
}
