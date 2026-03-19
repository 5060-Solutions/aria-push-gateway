FROM rust:1.83-bookworm AS builder

WORKDIR /build

# Copy shared crate first (dependency)

# Copy gateway source
COPY push-gateway/ /build/push-gateway/

WORKDIR /build/push-gateway
RUN cargo build --release

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/push-gateway/target/release/aria-gateway /usr/local/bin/aria-gateway

# Default config location
WORKDIR /data
VOLUME /data

EXPOSE 8080

ENTRYPOINT ["aria-gateway"]
CMD ["--config", "/data/gateway.toml"]
