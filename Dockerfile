FROM rust:1.98-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends libkrb5-dev libclang-dev libssl-dev pkg-config && rm -r /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release --locked --all-features

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libgssapi-krb5-2 libssl3 && rm -r /var/lib/apt/lists/*
COPY --from=build /build/target/release/evil-winrm-rs /usr/local/bin/evil-winrm-rs
WORKDIR /data
ENTRYPOINT ["evil-winrm-rs"]
