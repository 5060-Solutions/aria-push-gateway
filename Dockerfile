FROM rust:1.94-alpine AS builder

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig

WORKDIR /build
COPY . .
RUN cargo build --release

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM alpine:3.23

RUN apk add --no-cache ca-certificates

COPY --from=builder /build/target/release/aria-gateway /usr/local/bin/aria-gateway

WORKDIR /data
VOLUME /data

EXPOSE 8090

ENTRYPOINT ["aria-gateway"]
CMD ["--config", "/data/gateway.toml"]
