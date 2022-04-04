/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::io::Read;

use anyhow::anyhow;
use rocket::data::{FromDataSimple, Outcome};
use rocket::http::Status;
use rocket::outcome::Outcome::{Failure, Success};
use rocket::{Data, Request};

const LIMIT: u64 = 1024 * 256;

#[derive(Debug)]
pub struct LimitedString {
    string: String,
}

impl From<LimitedString> for String {
    fn from(e: LimitedString) -> Self {
        e.string
    }
}

impl FromDataSimple for LimitedString {
    type Error = anyhow::Error;

    fn from_data(_request: &Request, data: Data) -> Outcome<Self, Self::Error> {
        let mut string = String::new();
        if let Err(e) = data.open().take(LIMIT).read_to_string(&mut string) {
            return Failure((Status::InternalServerError, anyhow!(e)));
        }

        Success(LimitedString { string })
    }
}
