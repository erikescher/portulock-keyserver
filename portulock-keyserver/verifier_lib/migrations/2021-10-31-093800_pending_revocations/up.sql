/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

CREATE TABLE pending_revocations (
    fpr TEXT NOT NULL,
    revocation TEXT NOT NULL,
    exp TEXT NOT NULL
);