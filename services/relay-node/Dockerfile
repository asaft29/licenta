# Build stage
FROM rust:1.90-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy workspace files
COPY Cargo.toml Cargo.lock ./

# Copy all services (workspace requires all members to be present)
COPY services ./services

# Build the relay-node in release mode
RUN cargo build --release --package relay-node

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 relay && \
    mkdir -p /app && \
    chown -R relay:relay /app

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/relay-node /app/relay-node

# Change ownership
RUN chown relay:relay /app/relay-node

# Switch to non-root user
USER relay

# Expose relay node port
EXPOSE 9001

# Set default environment variables
ENV RUST_LOG=info

# Default command (can be overridden)
ENTRYPOINT ["/app/relay-node"]
CMD ["--node-type", "entry", "--port", "9001", "--host", "0.0.0.0", "--directory-url", "http://discovery:8080"]
