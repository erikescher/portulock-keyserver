<!--
  - Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
  - SPDX-License-Identifier: GPL-3.0-only
  -->

<template>
    <div>
        <h1>{{ this.primary_name }}</h1>
        <div>
            UserIDs:
            <ul>
                <li v-for="uid in userids" :key="JSON.stringify(uid)">{{ uid.full }}</li>
            </ul>
        </div>
        <div>Fingerprint: {{ fingerprint }}</div>
        <div>Algorithm: {{ algo_size }}</div>
        <div>Usage: {{ usage }}</div>
        <div>
            Subkeys:
            <ul>
                <li v-for="subkey in subkeys" :key="subkey.keyid">
                    {{ subkey.keyid }} - {{ subkey.algo_size }} - {{ subkey.usage }}
                </li>
            </ul>
        </div>
        <div v-if="!disable_download_button">
          <TextFileDownloadButton
              label="Download Key"
              :fileContent="rawkey"
              :fileName="fingerprint + '.asc'"
          />
        </div>
    </div>
</template>

<script>
import TextFileDownloadButton from "./TextFileDownloadButton.vue";
import KeyParser from '../services/KeyParser'

export default {
    components: { TextFileDownloadButton },
    props: {
        rawkey: {
            type: String,
            required: true,
        },
        disable_download_button: {
          type: Boolean,
          required: false,
        }
    },
    data: () => {
        return {
            primary_name: "John Doe",
            algo_size: "curve25519",
            usage: "BDEF",
            fingerprint: "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
            userids: [
                {
                    full:"John Doe <jdoe@example.com>",
                    name_validated: false,
                    email_validated: true
                },
            ],
            subkeys: [
                {
                    keyid: "12345678",
                    algo_size: "RSA2048",
                    usage: "E",
                },
                {
                    keyid: "DEADBEEF",
                    algo_size: "Ed25519",
                    usage: "A",
                },
            ],
        };
    },
    created() {
        if (this.rawkey) this.parse_key(this.rawkey);
    },
    watch: {
        rawkey(new_key) {
            this.parse_key(new_key);
        },
    },
    methods: {
        parse_key(rawkey) {
            new KeyParser().parse_key(rawkey).then(result =>  Object.assign(this, result))
        },
    },
};
</script>
