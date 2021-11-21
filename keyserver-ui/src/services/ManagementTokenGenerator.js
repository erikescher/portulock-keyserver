/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

import {decrypt, readKey, readMessage} from "openpgp";

export default class ManagementTokenGenerator {
    constructor(http_library){
        this.$http = http_library
    }

    async obtainToken(private_key) {
        let public_key = private_key.toPublic().armor()
        let response = await this.$http
            .post("/manage/challenge_decrypt", public_key, {
                headers: {
                    "Content-Type": "text/plain"
                },
                responseType: "text",
                timeout: 5000,
                withCredentials: false,
            })
        console.log("CHALLENGE_DECRYPT - response: ",response)
        let message = await readMessage({ armoredMessage: response.data})
        let decrypted_message = await decrypt({ message, decryptionKeys: private_key})
        console.log("CHALLENGE_DECRYPT - decrypted_message: ", decrypted_message)
        let message_object = JSON.parse(decrypted_message.data)
        console.log("CHALLENGE_DECRYPT - message_object: ", message_object)
        if (message_object.reason === "GPG Keyserver Management Challenge") {
            let token = message_object.token
            console.log("CHALLENGE_DECRYPT - token: ", token)
            return token
        }
    }
}