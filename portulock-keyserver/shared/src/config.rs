/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::collections::HashMap;

use rocket::config::{Array, Table, Value};

use crate::certification::local::LocalCertifier;
use crate::certification::CertifierConfig;
use crate::lookup::keyserver::Keyserver;
use crate::lookup::{LookupConfig, LookupDomainConfig};
use crate::utils::armor;

pub fn lookup_config_from_config_table(lookup_config_table: &Table) -> LookupConfig {
    let special_domains: HashMap<String, LookupDomainConfig> = lookup_config_table
        .get("special_domains")
        .unwrap_or(&Value::Table(Table::new()))
        .as_table()
        .unwrap()
        .iter()
        .map(|(k, v)| {
            let ldc = lookup_domain_config_from_config_table(v.as_table().unwrap());
            (k.to_string(), ldc)
        })
        .collect();

    let fallbacks: Vec<LookupDomainConfig> = lookup_config_table
        .get("fallbacks")
        .unwrap_or(&Value::Table(Table::new()))
        .as_table()
        .unwrap()
        .iter()
        .map(|(_k, v)| lookup_domain_config_from_config_table(v.as_table().unwrap()))
        .collect();

    if special_domains.len() + fallbacks.len() == 0 {
        panic!("Empty LookupConfig is not allowed!")
    }

    LookupConfig {
        special_domains,
        fallbacks,
    }
}

fn lookup_domain_config_from_config_table(table: &Table) -> LookupDomainConfig {
    LookupDomainConfig {
        keyservers: table
            .get("keyservers")
            .unwrap_or(&Value::Array(Array::new()))
            .as_array()
            .unwrap()
            .iter()
            .map(|v: &Value| Keyserver {
                url: v.as_str().unwrap().to_string(),
            })
            .collect(),
        expect_one_certification_from: table
            .get("expect_one_certification_from")
            .unwrap_or(&Value::Array(Array::new()))
            .as_array()
            .unwrap()
            .iter()
            .map(|v: &Value| armor::certification_key_from_str(v.as_str().unwrap()))
            .collect(),
        email_certifiers: table
            .get("certifier")
            .map(|v| {
                CertifierConfig::Local(LocalCertifier::new(armor::certification_key_from_str(
                    v.as_str().unwrap(),
                )))
            })
            .map(|c| vec![c])
            .unwrap_or_else(Vec::new),
        use_wkd: table
            .get("use_wkd")
            .unwrap_or(&Value::Boolean(false))
            .as_bool()
            .unwrap(),
        use_for_keyhandle_query: table
            .get("use_for_keyhandle_query")
            .unwrap_or(&Value::Boolean(false))
            .as_bool()
            .unwrap(),
    }
}
