/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

const backend_url = 'http://localhost:8083'

const backend_proxy_config = {
    target: backend_url,
    changeOrigin: true,
    secure: false
};

module.exports = {
    runtimeCompiler: true,
    lintOnSave: true,
    integrity: true,
    devServer:{
      proxy: {
        "/pks": backend_proxy_config,
        "/manage": backend_proxy_config,
        "/verify": backend_proxy_config
      }
    },
    configureWebpack: {
        experiments: {
            asyncWebAssembly: true
        }
    }
}