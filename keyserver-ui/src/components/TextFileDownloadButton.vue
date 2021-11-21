<!--
  - Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
  - SPDX-License-Identifier: GPL-3.0-only
  -->

<template>
    <div>
        <button v-on:click="download">{{ label }}</button>
    </div>
</template>

<script>
import FileSaver from "file-saver";

export default {
    props: {
        fileContent: {
            type: String,
            required: true,
        },
        fileName: {
            type: String,
            required: true,
        },
        label: {
            type: String,
            default: "Download",
        },
    },
    methods: {
        download() {
            const blob = new Blob([this.fileContent], {
                type: "text/plain;charset=utf-8",
            });
            FileSaver.saveAs(blob, this.fileName);
        },
    },
};
</script>