<!--
  - Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
  - SPDX-License-Identifier: GPL-3.0-only
  -->

<template>
    <div>
        <div id="nav">
            <router-link to="/">Home</router-link> |
            <router-link to="/generate">Generate</router-link> |
            <router-link to="/upload">Upload</router-link> |
            <router-link to="/manage">Manage</router-link> |
            <router-link to="/locate">Locate</router-link> |
            <router-link to="/ca">Certificate Authorities</router-link>
        </div>

      <div id="content">
        <router-view />
      </div>
    </div>
</template>

<style>
#app {
    font-family: Avenir, Helvetica, Arial, sans-serif;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    text-align: center;
    color: #2c3e50;
}

#nav {
    padding: 30px;
}

#content {
  padding: 0 30px 30px;
}

#nav a {
    font-weight: bold;
    color: #2c3e50;
}

#nav a.router-link-exact-active {
    color: #42b983;
}
</style>
