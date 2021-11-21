/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

import * as wasm from "openpgp-trustsign-wasm";
import {readKey} from "openpgp";

export default class TrustSigner {
    constructor(private_key){
        this.private_key = private_key.armor()
    }

    async sign(ca_key_armored, domain_scope) {
        console.log("TrustSigner.sign - parameters: ", ca_key_armored, domain_scope)
        let encoded_result = wasm.trust_sign(this.private_key, ca_key_armored, domain_scope)
        let binary_result = Buffer.from(encoded_result, 'base64');
        let parsed_result = await readKey({binaryKey: binary_result})
        console.log("TrustSigner.sign - result: ", parsed_result)
        return parsed_result
    }
}