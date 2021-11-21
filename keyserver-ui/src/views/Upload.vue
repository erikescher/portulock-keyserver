<!--
  - Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
  - SPDX-License-Identifier: GPL-3.0-only
  -->

<template>
  <div>
    <h1> Key Generation </h1>
    <div v-if="stage_form">
      <FormulateForm @submit="submit">
        <FormulateInput type="textarea" v-model="armoredKey" label="Public Key to Upload"/>
        <FormulateInput type="submit" name="Upload"/>
      </FormulateForm>
    </div>
    <div v-if="stage_submitted">
      <p>
        You will now receive a set of emails asking you to prove access to any emails on your key
        and log in using single-sign-on-accounts that confirm the names used above.
        When verifying your identity using the provided links make sure to compare your fingerprint when asked to do so.
      </p>

      <p>
        You can follow the status of your keys certification on the Management Page. A link to this page has been emailed to all email addresses on the key.

        Once that page shows all UserIDs and key components as published, you should update your copy from the keyserver to obtain the certifications.
      </p>
    </div>
  </div>
</template>

<script>
import DisplayKeyComponents from '../components/DisplayKeyComponents.vue';
import TextFileDownloadButton from '../components/TextFileDownloadButton.vue';
import { mapState } from 'vuex'
import HKP from '@openpgp/hkp-client';
import {readKey} from "openpgp";

export default {
  components: { DisplayKeyComponents, TextFileDownloadButton },
  data() {
    return {
      armoredKey: undefined,
      revocationCertificate: undefined,
      stage: "form",
    };
  },
  computed: {
    stage_form() {
      return this.stage === "form"
    },
    stage_submitted() {
      return this.stage === "submitted"
    },
    ...mapState([
      'config'
    ])
  },
  methods: {
    async submit() {
      let publicKey = await readKey({armoredKey: this.armoredKey})
      publicKey = publicKey.toPublic()
      let fpr = publicKey.getFingerprint()

      const hkp = new HKP(window.location.origin)
      hkp.upload(publicKey.armor()).then(() => {
        console.log("Key submitted successfully")
        this.stage = "submitted"
      })
      this.$http.get("/manage/challenge_email", {
        params: {
          fpr: fpr
        },
        timeout: 5000,
        withCredentials: false,
      }).then(response => {
        console.log("REQUEST_MANAGEMENT_LINKS - response", response)
      })
    },
  }
}
</script>
<style>
  textarea {
    height: 20em;
  }
</style>