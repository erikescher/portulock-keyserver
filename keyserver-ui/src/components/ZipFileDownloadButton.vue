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
import JSZip from "jszip";

export default {
    props: {
        files: {
            type: Array,
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
        async download() {
            let zip = new JSZip()
            for (let file of this.files) {
              zip.file(file.name, file.content)
            }
            const file = await zip.generateAsync({
              type: "uint8array",
              compression: "STORE"
            })
            const blob = new Blob([file], {type: "application/zip"})
            FileSaver.saveAs(blob, this.fileName);
        },
    },
};
</script>