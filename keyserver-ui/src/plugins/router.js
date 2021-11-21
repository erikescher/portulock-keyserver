/*
 * Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
 * SPDX-License-Identifier: GPL-3.0-only
 */

import Vue from "vue";
import Router from 'vue-router'

// Lazy Loaded Routes
const Generate = () => { return import(/* webpackChunkName: "about" */ '../views/Generate.vue') }
const Upload = () => { return import(/* webpackChunkName: "upload" */ '../views/Upload.vue')}
const Locate = () => { return import(/* webpackChunkName: "locate" */ '../views/Locate.vue')}
const Manage = () => { return import(/* webpackChunkName: "manage" */ '../views/Manage.vue')}
const CAList = () => { return import(/* webpackChunkName: "ca_list" */ '../views/CAList.vue')}
const Home = () => { return import(/* webpackChunkName: "home" */ '../views/Home.vue')}
const ErrorDisplay = () => { return import(/* webpackChunkName: "error_display" */ '../components/ErrorDisplay.vue')}


const routes = [
    {
        path: '/',
        name: 'Home',
        component: Home,
        meta: {
            title: 'Home'
        }
    },
    {
        path: '/generate',
        name: 'Generate',
        component: Generate,
        meta: {
            title: 'Key Generation'
        }
    },
    {
        path: '/ca',
        name: 'CAList',
        component: CAList,
        meta: {
            title: 'CA List'
        }
    },
    {
        path: '/upload',
        name: 'Upload',
        component: Upload,
        meta: {
            title: 'Upload Key'
        }
    },
    {
        path: '/locate',
        name: 'Locate',
        component: Locate,
        meta: {
            title: 'Locate Key'
        }
    },
    {
        path: '/manage',
        name: 'Manage',
        component: Manage,
        meta: {
            title: 'Manage'
        }
    },
    {
        // must be the last route
        path: "*",
        component: ErrorDisplay,
        props: {
            error: {
                heading: "404 Page not found",
                message: "the page you were looking for could not be found.",
                callToAction: "Please check that you entered or clicked the correct URL."
            }
        },
        meta: {
            title: 'Error Page'
        }
    }
]

Vue.use(Router)

export default new Router({
    mode: 'history',
    routes
})
