<!--
  - Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
  - SPDX-License-Identifier: GPL-3.0-only
  -->

<template>
  <div class="error">
    <h1>Error: {{ error.heading }}</h1>
    <p>
      Sorry, {{ messageLowercased }} <br>
      {{ error.callToAction }}
    </p>
    <p>
      You can find out more about this tool by visiting its
      <router-link to="/">
        home page.
      </router-link>
    </p>
  </div>
</template>

<script>
export default {
  props: {
    error: {
      type: Object,
      required: true
    }
  }, 
  computed: {
    messageLowercased(){
      return this.error.message.charAt(0).toLowerCase() + this.error.message.slice(1)
    }
  }
}
</script>


<style scoped>
  h1 {
    color: red;
    font-size: 4em;
  }
  p {
    font-size: 2em;
  }
</style>
