/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

import Vue from 'vue'
import App from './App.vue'
import VuePageTitle from "vue-page-title";

import './plugins/bootstrap'
import './plugins/http'
import './plugins/formulate'

import store from './plugins/vuex'
import router from './plugins/router'

import './styles/global-styles.css'

Vue.config.productionTip = false;

Vue.use(VuePageTitle, {
    suffix: ' - PortuLock Keyserver ',
    router
})

new Vue({
    router,
    store,
    render: h => h(App),
}).$mount('#app')

store.dispatch("INITIALIZE_CONFIG")