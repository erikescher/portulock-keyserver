/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

export default class KeyLocator {
    constructor(http_library){
        this.$http = http_library
    }

    fetchKey(locator) {
        return this.$http
            .get("/pks/lookup", {
                params: {
                    op: "get",
                    search: locator,
                    options: "mr", // machine-readable
                    exact: "on",
                },
                responseType: "text",
                timeout: 5000,
                withCredentials: false,
                validateStatus: (status) => {
                    return (status >= 200 && status < 300) || status === 404
                },
            })
            .then((response) => {
                status = response.status;
                if (status >= 200 && status < 300) {
                    return Promise.resolve(response.data)
                } else if (status === 404) {
                    console.log("no key found")
                    return Promise.resolve(undefined)
                }
                console.log(response)
                return Promise.reject("unexpected response")
            })
    }
}