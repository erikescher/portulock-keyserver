/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::collections::HashMap;

pub fn map2vec_v<K, V>(mut map: HashMap<K, V>) -> Vec<V> {
    map.drain().map(|(_k, v)| v).collect()
}

pub fn map2vec_k<K, V>(mut map: HashMap<K, V>) -> Vec<K> {
    map.drain().map(|(k, _v)| k).collect()
}
