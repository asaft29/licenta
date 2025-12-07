FROM rust:1.90-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY services/common ./services/common
COPY services/discovery ./services/discovery
COPY services/relay-node ./services/relay-node
COPY services/tor-client ./services/tor-client

RUN cargo build --release -p discovery

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/discovery /usr/local/bin/discovery

RUN mkdir -p /app/data

EXPOSE 8080

ENV RUST_LOG=${RUST_LOG}
ENV CONSENSUS_PATH=${CONSENSUS_PATH}

CMD ["discovery"]
