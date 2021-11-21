/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

import { readKey } from "openpgp";

function flags2string(flags) {
    const certify = flags & 1
    const sign = flags & 2
    const encrypt = flags & 4 || flags & 8 // 4: encrypt communications OR 8: encrypt storage
    const authenticate = flags & 32
    return (certify ? "C":"" ) + (sign ? "S":"" ) + (encrypt ? "E":"" ) + (authenticate ? + "A":"")
}

function extract_usage(key) {
    const signatures = key.bindingSignatures
    if (signatures.length >= 1) {
        const current_signature = signatures[0]
        return flags2string(current_signature.keyFlags[0])
    }
    // TODO use the most recent valid self-signature instead
    return ""
}

function extract_usage_primary(key) {
    if (key.users.length >= 1 && key.users[0].selfCertifications.length >= 1){
        return flags2string(key.users[0].selfCertifications[0].keyFlags[0])
    }
    // TODO handle multiple UserIDs with multiple selfCertifications and use the most recent valid one
    return ""
}

function extract_algo_size(key) {
    const algo_info = key.getAlgorithmInfo()
    let algorithm = algo_info.algorithm
        .replace("Encrypt", "")
        .replace("Sign", "")
        .toUpperCase();
    if (algorithm === "ECDH"){
        algorithm = algo_info.curve
    }
    // TODO properly parse the algorithm
    const size = algo_info.bits ? algo_info.bits : ""
    return algorithm + size
}


export default class KeyParser {
    parse_key(rawkey) {      
        return readKey({ armoredKey: rawkey }).then(key => {
            let promises = []

            let result = {
                fingerprint: key.getFingerprint().toUpperCase(),
                algo_size: extract_algo_size(key),
                usage: extract_usage_primary(key),
                userids: [],
                subkeys: []
            }
            
            key.getUserIDs().forEach(u => {
                result.userids.push({
                    full: u,
                })
            })

            key.subkeys.forEach(s => {
                result.subkeys.push({
                    keyid: s.getKeyID().toHex().toUpperCase(),
                    algo_size: extract_algo_size(s),
                    usage: extract_usage(s)
                });
            });
            promises.push(Promise.resolve(result))

            promises.push(
                key.getPrimaryUser().then(
                (user) => {
                    return Promise.resolve({
                        primary_name: user.user.userID.name,
                        primary_email: user.user.userID.email
                    })
                })
                .catch(_ => {
                    console.log("No primary userid found")
                    return Promise.resolve({})
                })
            )

            return Promise.all(promises).then(results => {
                let result = {}
                results.forEach(r => {
                    Object.assign(result, r)
                })
                return Promise.resolve(result)
            })
        })
    }
}