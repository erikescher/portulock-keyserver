<!--
  - Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
  - SPDX-License-Identifier: GPL-3.0-only
  -->

<template>
  <div class="about">
    <h1>CA-List</h1>
    <p>The following Certificate Authorities are operated by this keyserver:</p>
    <div style="display: flex; flex-direction: row;">
      <span style="padding-right: 50px">You can download them all in one file:</span>
      <text-file-download-button style="" label="All CAs in one file" :file-content="combined_file" file-name="ca-bundle.asc"/>
    </div>
    <div v-if="config.trust_sign">
      <div v-for="cert in config.trust_sign" :key="cert.ca">
        <display-certificate-authority :rawkey="cert.ca" :name="cert.name"/>
      </div>
    </div>
  </div>
</template>

<script>
import DisplayCertificateAuthority from "@/components/DisplayCertificateAuthority";
import {mapState} from "vuex";
import ZipFileDownloadButton from "@/components/ZipFileDownloadButton";
import TextFileDownloadButton from "@/components/TextFileDownloadButton";

export default {
  components: {TextFileDownloadButton, ZipFileDownloadButton, DisplayCertificateAuthority},
  computed: {
    ...mapState([
      'config'
    ]),
    combined_file() {
      let cas = ""
      for (let ca of this.config.trust_sign) {
        let described_armored_cert  = (ca.name ? ca.name + "\n" : "") +
            "\n\n" + ca.ca + "\n\n"
        cas = cas + described_armored_cert
      }
      return cas
    }
  }
};
</script>