/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::io::Read;

use rocket::data::{FromDataSimple, Outcome};
use rocket::http::Status;
use rocket::outcome::Outcome::{Failure, Success};
use rocket::{Data, Request};

use crate::errors::CustomError;

const LIMIT: u64 = 1024 * 256;

pub struct LimitedString {
    string: String,
}

impl From<LimitedString> for String {
    fn from(e: LimitedString) -> Self {
        e.string
    }
}

impl FromDataSimple for LimitedString {
    type Error = CustomError;

    fn from_data(_request: &Request, data: Data) -> Outcome<Self, Self::Error> {
        let mut string = String::new();
        if let Err(e) = data.open().take(LIMIT).read_to_string(&mut string) {
            return Failure((Status::InternalServerError, CustomError::from(e)));
        }

        Success(LimitedString { string })
    }
}
