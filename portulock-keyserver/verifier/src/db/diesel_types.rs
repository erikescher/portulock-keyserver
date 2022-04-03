use std::str::FromStr;

use chrono::NaiveDateTime;
use sequoia_openpgp::Cert;
use shared::utils::armor::export_armored_cert;

use crate::db::schema::*;

#[derive(Queryable, Insertable, Debug)]
#[table_name = "verified_names"]
pub struct VerifiedNameEntry {
    pub(crate) fpr: String,
    pub(crate) name: String,
    pub(crate) exp: NaiveDateTime,
}

#[derive(Queryable, Insertable, Debug)]
#[table_name = "verified_emails"]
pub struct VerifiedEmailEntry {
    pub(crate) fpr: String,
    pub(crate) email: String,
    pub(crate) exp: NaiveDateTime,
}

#[derive(Queryable, Insertable, Debug)]
#[table_name = "pending_revocations"]
pub struct PendingRevocation {
    pub(crate) fpr: String,
    pub(crate) revocation: String,
    pub(crate) exp: NaiveDateTime,
}

#[derive(Debug)]
pub struct PendingCertWithoutUIDs {
    pub(crate) fpr: String,
    pub(crate) pending_cert: Cert,
    pub(crate) exp: NaiveDateTime,
}

#[derive(Queryable, Insertable, Debug)]
#[table_name = "pending_keys"]
pub(crate) struct PendingCertWithoutUIDsEntry {
    pub(crate) fpr: String,
    pub(crate) cert: String,
    pub(crate) exp: NaiveDateTime,
}

impl From<PendingCertWithoutUIDsEntry> for PendingCertWithoutUIDs {
    fn from(entry: PendingCertWithoutUIDsEntry) -> Self {
        PendingCertWithoutUIDs {
            fpr: entry.fpr,
            pending_cert: Cert::from_str(entry.cert.as_str()).expect("Failed to parse Cert from DB!"),
            exp: entry.exp,
        }
    }
}

impl From<PendingCertWithoutUIDs> for PendingCertWithoutUIDsEntry {
    fn from(value: PendingCertWithoutUIDs) -> Self {
        PendingCertWithoutUIDsEntry {
            fpr: value.fpr,
            cert: export_armored_cert(&value.pending_cert),
            exp: value.exp,
        }
    }
}

impl From<PendingCertWithoutUIDs> for Cert {
    fn from(pending: PendingCertWithoutUIDs) -> Self {
        pending.pending_cert
    }
}

#[derive(Queryable, Insertable)]
#[table_name = "pending_uids"]
pub(crate) struct UIDPendingVerificationEntry {
    pub(crate) fpr: String,
    pub(crate) name: String,
    pub(crate) email: String,
    pub(crate) comment: String,
    pub(crate) uid_packets: String,
    pub(crate) exp: NaiveDateTime,
}

impl From<UIDPendingVerificationEntry> for UIDPendingVerification {
    fn from(entry: UIDPendingVerificationEntry) -> Self {
        UIDPendingVerification {
            fpr: entry.fpr,
            name: entry.name,
            mail: entry.email,
            comment: entry.comment,
            cert_with_this_uid: Cert::from_str(entry.uid_packets.as_str()).expect("Failed to parse Cert from DB!"),
            exp: entry.exp,
        }
    }
}

impl From<UIDPendingVerification> for UIDPendingVerificationEntry {
    fn from(value: UIDPendingVerification) -> Self {
        UIDPendingVerificationEntry {
            fpr: value.fpr,
            name: value.name,
            email: value.mail,
            comment: value.comment,
            uid_packets: export_armored_cert(&value.cert_with_this_uid),
            exp: value.exp,
        }
    }
}

pub struct UIDPendingVerification {
    pub(crate) fpr: String,
    pub(crate) name: String,
    pub(crate) mail: String,
    pub(crate) comment: String,
    pub(crate) cert_with_this_uid: Cert,
    pub(crate) exp: NaiveDateTime,
}

impl From<UIDPendingVerification> for Cert {
    fn from(pending: UIDPendingVerification) -> Self {
        pending.cert_with_this_uid
    }
}
