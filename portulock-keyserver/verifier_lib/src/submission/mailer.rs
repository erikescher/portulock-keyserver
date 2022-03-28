/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::fmt::{Debug, Formatter};
use std::str::FromStr;

use async_trait::async_trait;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Address, Message, SmtpTransport, Transport};
use shared::types::Email;

use crate::db::NameVerificationChallenge;
use crate::errors::VerifierError;
use crate::management::ManagementToken;
use crate::verification::tokens::{SignedEmailVerificationToken, SignedToken};

#[async_trait]
pub trait Mailer: Debug {
    async fn send_signed_email_challenge(
        &self,
        token: &SignedEmailVerificationToken,
        email: &Email,
    ) -> Result<(), VerifierError>;
    async fn send_name_challenge(
        &self,
        challenge: &NameVerificationChallenge,
        email: &Email,
    ) -> Result<(), VerifierError>;
    async fn send_signed_management_token(
        &self,
        token: &SignedToken<ManagementToken>,
        email: &Email,
    ) -> Result<(), VerifierError>;
}

pub struct SmtpMailer {
    connection: SmtpTransport,
    from: Mailbox,
    verification_endpoint_url: String,
}

impl Debug for SmtpMailer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SmtpMailer: \n from: {:?}\n verification_endpoint_url: {}",
            self.from, self.verification_endpoint_url
        )
    }
}

pub enum SmtpConnectionSecurity {
    None,
    Tls,
    StartTls,
}

impl SmtpMailer {
    pub fn new(
        host: &str,
        user: &str,
        pass: &str,
        port: u16,
        from: &str,
        verification_endpoint_url: &str,
        connection_security: &SmtpConnectionSecurity,
    ) -> Self {
        let connection = match connection_security {
            SmtpConnectionSecurity::None => SmtpTransport::builder_dangerous(host),
            SmtpConnectionSecurity::Tls => SmtpTransport::relay(host).unwrap(),
            SmtpConnectionSecurity::StartTls => SmtpTransport::starttls_relay(host).unwrap(),
        }
        .credentials(Credentials::new(user.to_string(), pass.to_string()))
        .port(port)
        .build();

        SmtpMailer {
            connection,
            from: Mailbox::new(None, Address::from_str(from).unwrap()),
            verification_endpoint_url: verification_endpoint_url.to_string(),
        }
    }

    fn send_mail(&self, email: &Email, body: &str, subject: &str) -> Result<(), VerifierError> {
        println!("MAILER send message: TO={}  SUBJECT={} ", email, subject);
        let message = Message::builder()
            .from(self.from.clone())
            .to(Mailbox::new(None, Address::from_str(email.to_string().as_str())?))
            .subject(subject)
            .body(body.to_string())?;
        let response = self.connection.send(&message);
        // Ignoring send errors, which can be caused by the email address not existing or similar.
        // Not much point in taking action here.
        println!("MAILER send result: {:#?}", response);
        Ok(())
    }
}

#[async_trait]
impl Mailer for SmtpMailer {
    async fn send_signed_email_challenge(
        &self,
        challenge: &SignedEmailVerificationToken,
        email: &Email,
    ) -> Result<(), VerifierError> {
        let subject = "Verify your Email";
        let body = format!(
            "\
            Please confirm your email address by clicking this link.\n\
            Link: {}/verify/email?token={}\n\
            ",
            self.verification_endpoint_url,
            challenge.get_data()
        );
        self.send_mail(email, body.as_str(), subject)
    }

    async fn send_name_challenge(
        &self,
        challenge: &NameVerificationChallenge,
        email: &Email,
    ) -> Result<(), VerifierError> {
        println!("sending to <{}>: {:?}", email, challenge);
        let subject = "Verify your Name";
        let body = format!(
            "\
            Please confirm your name by clicking this link and logging in using your SSO account: \n\
            Name: '{}' \n\
            Fingerprint: {} \n\
            Link: {}/verify/name_start?fpr={}&name={} \n\
            ",
            sanitize_name(challenge.name()),
            challenge.fpr(),
            self.verification_endpoint_url,
            challenge.fpr(),
            urlencoding::encode(challenge.name())
        );
        self.send_mail(email, body.as_str(), subject)
    }
    async fn send_signed_management_token(
        &self,
        token: &SignedToken<ManagementToken>,
        email: &Email,
    ) -> Result<(), VerifierError> {
        let subject = "Key Status Page";
        let body = format!(
            "\
            The following link can be used to see the status of your key (including unpublished data) and authorize changes.\n\
            Link: {}/manage/status?management_token={}\n\
            ",
            self.verification_endpoint_url,
            token.get_data()
        );
        self.send_mail(email, body.as_str(), subject)
    }
}

#[derive(Debug)]
pub struct NoopMailer {}

#[async_trait]
impl Mailer for NoopMailer {
    async fn send_signed_email_challenge(
        &self,
        _challenge: &SignedEmailVerificationToken,
        _email: &Email,
    ) -> Result<(), VerifierError> {
        Ok(())
    }
    async fn send_name_challenge(
        &self,
        _challenge: &NameVerificationChallenge,
        _email: &Email,
    ) -> Result<(), VerifierError> {
        Ok(())
    }
    async fn send_signed_management_token(
        &self,
        _token: &SignedToken<ManagementToken>,
        _email: &Email,
    ) -> Result<(), VerifierError> {
        Ok(())
    }
}

fn sanitize_name(name: &str) -> String {
    let mut name = name.replace('<', "□").replace('>', "□");
    if name.chars().count() > 256 {
        name = name.chars().take(256).collect();
        name.push_str("[...]")
    }
    name
}
