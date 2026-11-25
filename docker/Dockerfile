FROM rust:1-bookworm AS builder
WORKDIR /app
ENV CARGO_BUILD_JOBS=2

COPY Cargo.toml ./
COPY crates/nuvi-proto ./crates/nuvi-proto
COPY crates/nuvi-server ./crates/nuvi-server

# Stub workspace members so Cargo workspace manifest resolves without building Windows GUI crates
RUN mkdir -p crates/nuvi-client/src crates/nuvi-host/src && \
    printf '[package]\nname = "nuvi-client"\nversion = "0.1.0"\nedition = "2021"\n' > crates/nuvi-client/Cargo.toml && \
    printf 'fn main() {}\n' > crates/nuvi-client/src/main.rs && \
    printf '[package]\nname = "nuvi-host"\nversion = "0.1.0"\nedition = "2021"\n' > crates/nuvi-host/Cargo.toml && \
    printf 'fn main() {}\n' > crates/nuvi-host/src/main.rs

RUN cargo build -p nuvi-server --release

FROM debian:bookworm-slim
RUN useradd --create-home --shell /bin/false nuvi && \
    mkdir -p /data && chown nuvi:nuvi /data
COPY --from=builder /app/target/release/nuvi-server /usr/local/bin/nuvi-server

USER nuvi
ENV NUVI_BIND_ADDR=0.0.0.0:8765
ENV NUVI_DATA_DIR=/data
EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/8765"]

ENTRYPOINT ["/usr/local/bin/nuvi-server"]
