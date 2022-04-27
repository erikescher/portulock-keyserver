/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

import axios from 'axios'
import Vue from 'vue'
import Vuex from 'vuex'

Vue.use(Vuex)

const config = {
    state: () => ({
        key_generation: {
            type: 'rsa',
            rsaBits: '4096',
            keyExpirationTime: 3 * 365 * 24 * 60 * 60
        },
        validation: {
            name: {
                providers: []
            }
        },
        store_revocation: false,
        trust_sign: [],
        dummy: true
    }),
    mutations: {
        SET_CONFIG(state, payload){
            state.key_generation = payload.key_generation
            state.validation = payload.validation
            state.trust_sign = payload.trust_sign

            state.dummy = false
            console.log("config updated")
        }
    },
    actions: {
        FETCH_CONFIG(context){
            axios.get("/config/ui.json", {
                timeout: 5000
            })
            .then(response => {
                context.commit("SET_CONFIG", response.data)
            })
        },
        INITIALIZE_CONFIG(context){
            if (context.state.dummy){
                context.dispatch("FETCH_CONFIG")
            }
        }
    }
}

const credentials = {
    state: () => ({
        credentials: []
    }),
    mutations: {
        ADD_CREDENTIAL(state, payload){
            state.credentials.push(payload)
            console.log("OIDC Credential added", payload)
        }
    }
}

export default new Vuex.Store({
    modules: {
        config,
        credentials
    }
})
