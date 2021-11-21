<!--
  - Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
  - SPDX-License-Identifier: GPL-3.0-only
  -->

<template>
  <div>
    <h1>Welcome to the PortuLock Keyserver UI</h1>
    <p>
      PortuLock is a  privacy preserving keyserver and certificate authority for organizations
      that solves the problems associated with privacy considerations around key distribution
      as well as the verification of keys for internal and external communication partners.
    </p>
    <p>
      It allows users to generate keys, have them certified and published as well as manage their
      lifecycle on their own by authenticating with the organization’s existing single-sign-on
      infrastructure to verify their name and prove membership in the organization.
      Keys remain in the sole control of the user, while PortuLock’s web generator takes care
      of complex processes such as creating trust signatures over certificate authority keys,
      that are not exposed by all clients.
    </p>
    <p>
      On the privacy front it gives users full control over what information can be distributed
      with their certificate to protect against denial of service, distribution of problematic
      materials and to prevent leaking the social graph of certifications. It also ensures that
      data can only be published with approval from the subjects to which it pertains.
      When it comes to identity validation, PortuLock leverages the network of trusted certificates
      spanned by the OpenPGP-CA project and library while making it accessible and
      usable for organizations of all sized due to the scalable and easy self-service approach to
      certification.
    </p>
    <p>
      It extends this network by providing an aggregation feature that requests keys for email
      addresses directly from the target domain using established protocols and without leaking
      personally identifiable information such as email addresses and fingerprints to third-parties
      as is common with centralized keyservers. This aggregation feature allows administrators
      to configure trust based on the origin of a key and in turn issue certifications
      on the fly, extending this trust to clients and lifting the burden of verification from the
      users.
    </p>
    <p>
      In summary, PortuLock makes OpenPGP usable for organizations by providing a scalable trust
      system, that users can easily join while also protecting their privacy and the privacy of
      communication partners by requesting information about certificates directly from the
      respective domains.
    </p>
  </div>
</template>

<script>

export default {
  name: 'Home'
}
</script>

<style scoped>
label {
  margin: 0 0.5em;
  font-weight: bold;
}
</style>