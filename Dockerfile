FROM rust:latest AS builder

# Install protobuf compiler (needed for tonic-build)
RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source
COPY . .

# Build in release mode
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y libssl3 ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/zcash-enclave /usr/local/bin/zcash-enclave

# Create data directory
RUN mkdir -p /data

# Expose port
EXPOSE 8089

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8089/health || exit 1

# Default command
CMD ["zcash-enclave"]
