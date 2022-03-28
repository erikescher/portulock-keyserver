/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

CREATE TABLE pending_keys (
    fpr TEXT NOT NULL,
    cert TEXT NOT NULL,
    exp TEXT NOT NULL
);

CREATE TABLE pending_uids (
    fpr TEXT NOT NULL,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    comment TEXT NOT NULL,
    uid_packets TEXT NOT NULL,
    exp TEXT NOT NULL
);

CREATE TABLE verified_emails (
    fpr TEXT NOT NULL,
    email TEXT NOT NULL,
    exp TEXT NOT NULL
);

CREATE TABLE verified_names (
    fpr TEXT NOT NULL,
    name TEXT NOT NULL,
    exp TEXT NOT NULL
);
