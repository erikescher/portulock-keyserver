/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

table! {
    pending_keys (fpr) {
        fpr -> Text,
        cert -> Text,
        exp -> Timestamp,
    }
}

table! {
    pending_uids (fpr) {
        fpr -> Text,
        name -> Text,
        email -> Text,
        comment -> Text,
        uid_packets -> Text,
        exp -> Timestamp,
    }
}

table! {
    verified_emails (fpr) {
        fpr -> Text,
        email -> Text,
        exp -> Timestamp,
    }
}

table! {
    verified_names (fpr) {
        fpr -> Text,
        name -> Text,
        exp -> Timestamp,
    }
}

table! {
    pending_revocations (fpr) {
        fpr -> Text,
        revocation -> Text,
        exp -> Timestamp,
    }
}

allow_tables_to_appear_in_same_query!(pending_keys, pending_uids, verified_emails, verified_names,);
