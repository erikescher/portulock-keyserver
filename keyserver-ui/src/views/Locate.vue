<!--
  - Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
  - SPDX-License-Identifier: GPL-3.0-only
  -->

<template>
    <div class="about">
        <h1>Search for keys</h1>
        <p>
          This page can be used to locate keys from this keyserver and others using their email address.
        </p>
        <p>
            From this keyserver only keys configured for publication will be shown.
        </p>
        <p>
            To check if your key is stored on this server use the
            <router-link to="/manage">manage</router-link> page and enter your
            mail address.
        </p>
        <FormulateForm v-model="formValues" @submit="search">
          <FormulateInput type="email" name="email" label="Email address"/>
          <FormulateInput type="submit" name="Search"/>
        </FormulateForm>
        <div v-if="certs">
          <div v-for="cert in certs" :key="cert.getFingerprint()">
            <display-key-components :rawkey="cert.armor()"/>
          </div>
        </div>
    </div>
</template>

<script>
import HKP from "@openpgp/hkp-client";
import {readKeys} from "openpgp";
import DisplayKeyComponents from "@/components/DisplayKeyComponents";

export default {
  components: {DisplayKeyComponents},
  data() {
        return {
            formValues: undefined,
            certs: undefined,
            armored_certs: undefined
        };
    },
    methods: {
        async search() {
          const hkp = new HKP(window.location.origin)
          this.armored_certs = await hkp.lookup({
            query: this.formValues.email
          })
          this.certs = await readKeys({armoredKeys: this.armored_certs});
        },
    },
};
</script>