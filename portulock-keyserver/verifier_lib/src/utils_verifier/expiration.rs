/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::ops::Not;

use chrono::{Duration, NaiveDateTime, Utc};
use num_traits::cast::ToPrimitive;

#[derive(Debug)]
pub struct ExpirationConfig {
    offset: Duration,
}

impl ExpirationConfig {
    pub fn new(offset: Duration) -> Self {
        Self { offset }
    }

    pub fn current_time() -> NaiveDateTime {
        Utc::now().naive_utc()
    }

    pub fn current_time_u64() -> u64 {
        Utc::now()
            .naive_utc()
            .timestamp()
            .to_u64()
            .expect("This should not be negative.")
    }

    pub fn expiration(&self) -> NaiveDateTime {
        Self::current_time()
            .checked_add_signed(self.offset)
            .expect("This should not overflow.")
    }

    pub fn expiration_u64(&self) -> u64 {
        self.expiration()
            .timestamp()
            .to_u64()
            .expect("This should not be negative.")
    }

    pub fn is_expired(timestamp: NaiveDateTime) -> bool {
        Self::current_time().timestamp() > timestamp.timestamp()
    }

    pub fn is_valid(timestamp: NaiveDateTime) -> bool {
        Self::is_expired(timestamp).not()
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Not;

    use chrono::Duration;

    use crate::utils_verifier::expiration::ExpirationConfig;

    #[test]
    fn new_timestamp_not_expired() {
        let config = ExpirationConfig::new(Duration::seconds(15));
        let expiration = config.expiration();
        assert!(ExpirationConfig::is_expired(expiration).not());
    }

    #[test]
    fn expired() {
        let expiration = ExpirationConfig::current_time() - Duration::seconds(20);
        assert!(ExpirationConfig::is_expired(expiration));
    }
}
