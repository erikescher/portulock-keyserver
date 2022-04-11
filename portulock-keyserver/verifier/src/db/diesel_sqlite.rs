use anyhow::Error;
use async_trait::async_trait;
use chrono::NaiveDateTime;
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SqliteConnection};
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::{Cert, Fingerprint};
use shared::types::Email;
use shared::utils::armor::{armor_signature, export_armored_cert};
use shared::utils::merge_certs;
use tracing::info;
use verifier_lib::certs::CertWithSingleUID;
use verifier_lib::db_new::DB;
use verifier_lib::management::revocations_from_string;
use verifier_lib::utils_verifier::expiration::ExpirationConfig;

use crate::db::diesel_types::{
    PendingCertWithoutUIDs, PendingCertWithoutUIDsEntry, PendingRevocation, UIDPendingVerification,
    UIDPendingVerificationEntry,
};
use crate::db::diesel_types::{VerifiedEmailEntry, VerifiedNameEntry};
use crate::db::schema::pending_keys::columns::exp as pending_keys_exp;
use crate::db::schema::pending_keys::dsl::pending_keys;
use crate::db::schema::pending_uids::columns::exp as pending_uids_exp;
use crate::db::schema::pending_uids::dsl::pending_uids;
use crate::db::schema::verified_emails::columns::exp as verified_emails_exp;
use crate::db::schema::verified_emails::dsl::verified_emails;
use crate::db::schema::verified_names::columns::exp as verified_names_exp;
use crate::db::schema::verified_names::dsl::verified_names;
use crate::SubmitterDBConn;

pub struct DieselSQliteDB {
    pub conn: SubmitterDBConn,
}

impl DieselSQliteDB {
    /*fn sqlite_conn(&self) -> Result<&SqliteConnection, anyhow::Error> {
        Ok(self.conn)
    }*/
}

impl DieselSQliteDB {
    fn get_pending_cert_without_uid(
        connection: &SqliteConnection,
        fingerprint: Fingerprint,
    ) -> Result<Option<PendingCertWithoutUIDs>, anyhow::Error> {
        use crate::db::schema::pending_keys::dsl::*;

        let mut expiration = ExpirationConfig::current_time();

        let result = pending_keys
            .filter(fpr.eq(fingerprint.to_string()))
            .load::<PendingCertWithoutUIDsEntry>(connection)?
            .into_iter()
            .filter(|vn: &PendingCertWithoutUIDsEntry| ExpirationConfig::is_valid(vn.exp))
            .map(PendingCertWithoutUIDs::from)
            .filter(|vn: &PendingCertWithoutUIDs| vn.pending_cert.fingerprint() == fingerprint);
        // Expiration will be the minimum of all stored entries.

        let result: Vec<Cert> = result
            .map(|vn: PendingCertWithoutUIDs| {
                if vn.exp < expiration {
                    expiration = vn.exp
                }
                vn
            })
            .map(|vn: PendingCertWithoutUIDs| vn.pending_cert)
            .collect();
        let result = merge_certs(result).into_iter().next().map(|c| PendingCertWithoutUIDs {
            fpr: c.fingerprint().to_hex(),
            pending_cert: c,
            exp: expiration,
        });
        Ok(result)
    }

    fn get_pending_uids_by_fpr(
        connection: &SqliteConnection,
        fingerprint: Fingerprint,
    ) -> Result<Vec<Cert>, anyhow::Error> {
        use crate::db::schema::pending_uids::dsl::*;
        let result: Vec<Cert> = pending_uids
            .filter(fpr.eq(fingerprint.to_string()))
            .load::<UIDPendingVerificationEntry>(connection)?
            .into_iter()
            .map(UIDPendingVerification::from)
            .filter(|vn: &UIDPendingVerification| ExpirationConfig::is_valid(vn.exp))
            .map(|e| e.into())
            .collect();
        Ok(result)
    }

    fn get_pending_cert_by_fpr(connection: &SqliteConnection, fingerprint: Fingerprint) -> Result<Option<Cert>, Error> {
        let mut certs = DieselSQliteDB::get_pending_uids_by_fpr(connection, fingerprint.clone())?;
        if let Some(c) = DieselSQliteDB::get_pending_cert_without_uid(connection, fingerprint)? {
            certs.push(c.into())
        }
        Ok(merge_certs(certs).into_iter().next())
    }
}

embed_migrations!();

#[async_trait]
impl DB for DieselSQliteDB {
    async fn migrate(&self) -> Result<(), Error> {
        self.conn
            .run(|connection| {
                info!("performing DB migrations");
                embedded_migrations::run_with_output(connection, &mut std::io::stdout())
                    .expect("DB Migrations failed!");
                Ok(())
            })
            .await
    }

    async fn maintain(&self) -> Result<(), Error> {
        let current_timestamp = ExpirationConfig::current_time();
        self.conn
            .run(move |connection| {
                diesel::delete(verified_names.filter(verified_names_exp.eq(current_timestamp))).execute(connection)?;
                diesel::delete(verified_emails.filter(verified_emails_exp.eq(current_timestamp)))
                    .execute(connection)?;
                diesel::delete(pending_keys.filter(pending_keys_exp.eq(current_timestamp))).execute(connection)?;
                diesel::delete(pending_uids.filter(pending_uids_exp.eq(current_timestamp))).execute(connection)?;
                Ok(())
            })
            .await
    }

    async fn get_approved_names(&self, fingerprint: Fingerprint) -> Result<Vec<String>, Error> {
        use crate::db::schema::verified_names::dsl::*;
        self.conn
            .run(move |connection| {
                let names = verified_names
                    .filter(fpr.eq(fingerprint.to_string()))
                    .load::<VerifiedNameEntry>(connection)?
                    .into_iter()
                    .filter(|e: &VerifiedNameEntry| ExpirationConfig::is_valid(e.exp))
                    .map(|vne: VerifiedNameEntry| vne.name)
                    .collect();

                Ok(names)
            })
            .await
    }

    async fn get_approved_emails(&self, fingerprint: Fingerprint) -> Result<Vec<String>, Error> {
        use crate::db::schema::verified_emails::dsl::*;
        self.conn
            .run(move |connection| {
                let emails = verified_emails
                    .filter(fpr.eq(fingerprint.to_string()))
                    .load::<VerifiedEmailEntry>(connection)?
                    .into_iter()
                    .filter(|e: &VerifiedEmailEntry| ExpirationConfig::is_valid(e.exp))
                    .map(|vee: VerifiedEmailEntry| vee.email)
                    .collect();
                // TODO type: ExpiringScopedSignedTypedStringMapEntry { exp: u32, key: String (Fingerprint), value: String (Email, Cert, Name, ...), type: StringEnum (VerifiedName, PendingKey, ...) , signature: String (validated internally)}
                //    signature would cover all other fields
                //    signature system should contain a keyid for key rollover eventually
                //    we could then store everything in a single database table (simplifies deletion, expiration, export, domain-scoping?)
                Ok(emails)
            })
            .await
    }

    async fn get_pending_cert_by_fpr(&self, fingerprint: Fingerprint) -> Result<Option<Cert>, Error> {
        self.conn
            .run(move |connection| {
                let mut certs = DieselSQliteDB::get_pending_uids_by_fpr(connection, fingerprint.clone())?;
                if let Some(c) = DieselSQliteDB::get_pending_cert_without_uid(connection, fingerprint)? {
                    certs.push(c.into())
                }
                Ok(merge_certs(certs).into_iter().next())
            })
            .await
    }

    async fn get_pending_cert_by_email(&self, search_email: Email) -> Result<Vec<Cert>, Error> {
        use crate::db::schema::pending_uids::dsl::*;
        self.conn
            .run(move |connection| {
                let certs: Vec<Cert> = pending_uids
                    .filter(email.eq(search_email.to_string()))
                    .load::<UIDPendingVerificationEntry>(connection)?
                    .into_iter()
                    .map(UIDPendingVerification::from)
                    .filter(|vn: &UIDPendingVerification| ExpirationConfig::is_valid(vn.exp))
                    .map(|e| e.into())
                    .collect();

                let mut results = vec![];
                for cert in merge_certs(certs) {
                    match DieselSQliteDB::get_pending_cert_by_fpr(connection, cert.fingerprint())? {
                        None => {}
                        Some(c) => results.push(c),
                    }
                    results.push(cert)
                }
                // NOTE: we don't need the other UIDs for the cert
                Ok(merge_certs(results))
            })
            .await
    }

    async fn get_stored_revocations(&self, fingerprint: Fingerprint) -> Result<Vec<Signature>, Error> {
        use crate::db::schema::pending_revocations::dsl::*;
        self.conn
            .run(move |connection| {
                let result = pending_revocations
                    .filter(fpr.eq(fingerprint.to_string()))
                    .load::<PendingRevocation>(connection)?
                    .into_iter()
                    .filter(|pr: &PendingRevocation| ExpirationConfig::is_valid(pr.exp))
                    .filter_map(|pr| revocations_from_string(pr.revocation).ok())
                    .flatten()
                    .collect();
                Ok(result)
            })
            .await
    }

    async fn store_approved_name(
        &self,
        approved_name: String,
        fingerprint: Fingerprint,
        expiration: u64,
    ) -> Result<(), Error> {
        use crate::db::schema::verified_names::dsl::*;
        self.conn
            .run(move |connection| {
                let entry = VerifiedNameEntry {
                    fpr: fingerprint.to_string(),
                    name: approved_name.to_string(),
                    exp: NaiveDateTime::from_timestamp(expiration as i64, 0),
                };
                diesel::insert_into(verified_names).values(entry).execute(connection)?;
                Ok(())
            })
            .await
    }

    async fn store_approved_email(&self, mail: Email, fingerprint: Fingerprint, expiration: u64) -> Result<(), Error> {
        use crate::db::schema::verified_emails::dsl::*;
        self.conn
            .run(move |connection| {
                let entry = VerifiedEmailEntry {
                    fpr: fingerprint.to_string(),
                    email: mail.to_string(),
                    exp: NaiveDateTime::from_timestamp(expiration as i64, 0),
                };
                diesel::insert_into(verified_emails).values(entry).execute(connection)?;
                Ok(())
            })
            .await
    }

    async fn store_pending_revocation(
        &self,
        revocation_signature: Signature,
        fingerprint: Fingerprint,
        expiration: u64,
    ) -> Result<(), anyhow::Error> {
        use crate::db::schema::pending_revocations::dsl::*;
        self.conn
            .run(move |connection| {
                diesel::insert_into(pending_revocations)
                    .values(PendingRevocation {
                        fpr: fingerprint.to_hex(),
                        revocation: armor_signature(revocation_signature.clone()).unwrap(), // TODO remove unwrap
                        exp: NaiveDateTime::from_timestamp(expiration as i64, 0),
                    })
                    .execute(connection)?;
                Ok(())
            })
            .await
    }

    async fn store_pending_key(&self, new_cert: Cert, expiration: u64) -> Result<(), Error> {
        use crate::db::schema::pending_keys::dsl::*;
        self.conn
            .run(move |connection| {
                diesel::insert_into(pending_keys)
                    .values(PendingCertWithoutUIDsEntry {
                        fpr: new_cert.fingerprint().to_hex(),
                        cert: export_armored_cert(&new_cert),
                        exp: NaiveDateTime::from_timestamp(expiration as i64, 0),
                    })
                    .execute(connection)?;
                Ok(())
            })
            .await
    }

    async fn store_pending_uid(&self, cert_holder: CertWithSingleUID, expiration: u64) -> Result<(), Error> {
        use crate::db::schema::pending_uids::dsl::*;
        self.conn
            .run(move |connection| {
                diesel::insert_into(pending_uids)
                    .values(UIDPendingVerificationEntry {
                        fpr: cert_holder.cert().fingerprint().to_hex(),
                        name: cert_holder.userid().name().unwrap_or_default().unwrap_or_default(),
                        email: cert_holder
                            .userid()
                            .email_normalized()
                            .unwrap_or_default()
                            .unwrap_or_default(),
                        comment: cert_holder.userid().comment().unwrap_or_default().unwrap_or_default(),
                        uid_packets: export_armored_cert(cert_holder.cert()),
                        exp: NaiveDateTime::from_timestamp(expiration as i64, 0),
                    })
                    .execute(connection)?;
                Ok(())
            })
            .await
    }

    async fn delete_data_for_fpr(&self, fingerprint: Fingerprint) -> Result<(), Error> {
        self.conn
            .run(move |connection| {
                let fingerprint = fingerprint.to_hex();

                use crate::db::schema::pending_keys::columns::fpr as pending_keys_fpr;
                diesel::delete(pending_keys.filter(pending_keys_fpr.eq(&fingerprint))).execute(connection)?;

                use crate::db::schema::pending_uids::columns::fpr as pending_uids_fpr;
                diesel::delete(pending_uids.filter(pending_uids_fpr.eq(&fingerprint))).execute(connection)?;

                use crate::db::schema::verified_names::columns::fpr as verified_names_fpr;
                diesel::delete(verified_names.filter(verified_names_fpr.eq(&fingerprint))).execute(connection)?;

                use crate::db::schema::verified_emails::columns::fpr as verified_emails_fpr;
                diesel::delete(verified_emails.filter(verified_emails_fpr.eq(&fingerprint))).execute(connection)?;

                Ok(())
            })
            .await
    }
}
