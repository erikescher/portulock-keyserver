<!--
  - Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
  - SPDX-License-Identifier: GPL-3.0-only
  -->

<template>
    <div>
        <h1>{{ this.ca_name }}</h1>
        <div>
            UserIDs:
            <ul>
                <li v-for="uid in userids" :key="JSON.stringify(uid)">{{ uid.full }}</li>
            </ul>
        </div>
        <div>Fingerprint: {{ fingerprint }}</div>
        <TextFileDownloadButton
            label="Download Certificate Authority"
            :fileContent="rawkey"
            :fileName="fingerprint + '.asc'"
        />
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
        name: {
          type: String
        }
    },
    computed: {
      ca_name() {
        return this.name ? this.name : "CA for " + this.domain
      }
    },
    data: () => {
        return {
            primary_name: "John Doe",
            domain: "<unknown domain>",
            fingerprint: "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
            userids: [
                {
                    full:"John Doe <jdoe@example.com>"
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
            new KeyParser().parse_key(rawkey).then(result =>  {
              Object.assign(this, result)
              if (result.primary_email) {
                this.domain = result.primary_email.split("@")[1]
              }
            })
        },
    },
};
</script>
