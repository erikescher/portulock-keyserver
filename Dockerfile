# Copyright (c) 2021. Erik Escher. PortuLock Keyserver. GPL-3.0-only.
# SPDX-License-Identifier: GPL-3.0-only

FROM rustlang/rust:nightly as rust_builder_base
RUN apt update && apt install --yes clang libclang-dev llvm llvm-dev librust-clang-sys*
WORKDIR /build

FROM rust_builder_base as rust_builder
COPY ./portulock-keyserver .
RUN cargo build --release

FROM debian:buster as rust_runner
ENV DEBIAN_FRONTEND="noninteractive"
ENV ROCKET_ADDRESS="0.0.0.0"
ENV RUST_BACKTRACE="full"
RUN apt update && apt install -y libssl1.1 libsqlite3-0 nettle-bin libmariadb3 git rustc cargo clang libclang-dev make pkg-config nettle-dev libssl-dev capnproto libsqlite3-dev
WORKDIR /app

FROM rust_runner as verifier
COPY ./portulock-keyserver/verifier/templates ./templates
COPY --from=rust_builder /build/target/release/verifier /usr/local/bin
ENV ROCKET_PORT="8084"
ENV ROCKET_DATABASES="{sqlite={url=\"/app/state/verifier.sqlite\"}}"
EXPOSE 8084
ENTRYPOINT ["verifier"]

FROM rust_runner as aggregator
COPY --from=rust_builder /build/target/release/aggregator /usr/local/bin
ENV ROCKET_PORT="8083"
EXPOSE 8083
ENTRYPOINT ["aggregator"]



FROM rust_builder_base as wasm_builder
RUN cargo install wasm-pack --vers 0.9.1
COPY ./openpgp-trustsign-wasm .
RUN wasm-pack build

FROM node:lts as npm_builder
WORKDIR /build
COPY --from=wasm_builder /build/pkg/ /openpgp-trustsign-wasm/pkg/
COPY keyserver-ui/package*.json ./
RUN npm install
COPY keyserver-ui .
RUN npm run build


FROM nginx as reverse_proxy
RUN rm /etc/nginx/conf.d/default.conf
COPY reverse-proxy/combined.conf /etc/nginx/conf.d/
COPY --from=npm_builder /build/dist /var/www/html/
RUN rm /var/www/html/config/ui.json || true
EXPOSE 80
