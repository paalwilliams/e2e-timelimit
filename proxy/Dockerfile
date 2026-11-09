ARG BUILD_FROM

# --- build the Rust proxy natively on the HA host (musl, matches the Alpine base)
FROM rust:1-alpine3.20 AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY sni/Cargo.toml sni/Cargo.lock ./
COPY sni/src ./src
# thin LTO keeps on-device build times reasonable
ENV CARGO_PROFILE_RELEASE_LTO=thin CARGO_PROFILE_RELEASE_CODEGEN_UNITS=4
RUN cargo build --release --locked && cp target/release/leechproxy-sni /leechproxy-sni

# --- add-on image
FROM $BUILD_FROM
RUN apk add --no-cache python3 iptables ip6tables iproute2
COPY --from=build /leechproxy-sni /usr/bin/leechproxy-sni
COPY leechproxy /opt/leechproxy/leechproxy
COPY run.sh /run.sh
RUN chmod a+x /run.sh
CMD ["/run.sh"]
