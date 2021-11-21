<!--
  - Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
  - SPDX-License-Identifier: GPL-3.0-only
  -->

<template>
  <div class="about">
    <h1>Request Management Links</h1>
    <p>
      After submitting the form below, the keyserver will send management links for any associated certificate to the email address.
    </p>

    <FormulateForm v-model="formValues" @submit="send_links">
      <FormulateInput type="email" name="email" label="Email address"/>
      <FormulateInput type="submit" name="Send management links"/>
    </FormulateForm>

  </div>
</template>

<script>

export default {
    data() {
        return {
            formValues: undefined,
        };
    },
    methods: {
        send_links() {
          this.$http.get("/manage/challenge_email_all", {
            params: this.formValues,
            timeout: 5000,
            withCredentials: false,
          }).then(response => {
            console.log("REQUEST_MANAGEMENT_LINKS - response", response)
          })
        }
    },
};
</script>