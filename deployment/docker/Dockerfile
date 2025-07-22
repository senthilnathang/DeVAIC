# DeVAIC Production Dockerfile
FROM rust:1.75-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Build with release profile and core features
RUN cargo build --release --features "progress,performance,async"

# Runtime image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false devaic

# Copy binary
COPY --from=builder /app/target/release/devaic /usr/local/bin/devaic

# Create directories
RUN mkdir -p /app/reports /app/rules /app/models && \
    chown -R devaic:devaic /app

# Switch to non-root user
USER devaic

# Set working directory
WORKDIR /app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD devaic --version || exit 1

# Default command
ENTRYPOINT ["devaic"]
CMD ["--help"]