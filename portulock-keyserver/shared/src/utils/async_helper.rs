/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::future::Future;
use std::io::Error;

use tokio::runtime::Runtime;

pub fn block_on_async_function<F: Future>(future: F) -> F::Output {
    let mut runtime = Runtime::new().expect("Failed to create tokio runtime.");
    runtime.block_on(future)
}

pub struct AsyncHelper {
    runtime: Runtime,
}

impl AsyncHelper {
    pub fn new() -> Result<Self, Error> {
        let runtime = Runtime::new()?;
        Ok(AsyncHelper { runtime })
    }

    pub fn wait_for<F: Future>(&mut self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }
}
