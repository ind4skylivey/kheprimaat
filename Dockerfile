# Multi-stage Dockerfile for KhepriMaat
# Stage 1: Builder - Compile Rust application
FROM rust:1.75-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files first for better caching
COPY Cargo.toml Cargo.lock ./

# Create dummy main to cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy actual source code
COPY . .

# Build the application
RUN cargo build --release

# Stage 2: Runtime - Minimal image with tools
FROM debian:bookworm-slim

LABEL maintainer="ind4skylivey"
LABEL description="KhepriMaat - Orchestrated vulnerability scanner"

WORKDIR /app

# Install runtime dependencies and security tools
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    wget \
    unzip \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Install security scanning tools
# Subfinder
RUN curl -sSL https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_2.6.3_linux_amd64.zip -o subfinder.zip && \
    unzip subfinder.zip && \
    mv subfinder /usr/local/bin/ && \
    chmod +x /usr/local/bin/subfinder && \
    rm subfinder.zip README.md LICENSE.md

# Nuclei
RUN curl -sSL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.1.5_linux_amd64.zip -o nuclei.zip && \
    unzip nuclei.zip && \
    mv nuclei /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm nuclei.zip README.md LICENSE.md

# Httpx
RUN curl -sSL https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_1.3.9_linux_amd64.zip -o httpx.zip && \
    unzip httpx.zip && \
    mv httpx /usr/local/bin/ && \
    chmod +x /usr/local/bin/httpx && \
    rm httpx.zip README.md LICENSE.md

# Ffuf
RUN curl -sSL https://github.com/ffuf/ffuf/releases/latest/download/ffuf_2.1.0_linux_amd64.tar.gz -o ffuf.tar.gz && \
    tar xzf ffuf.tar.gz && \
    mv ffuf /usr/local/bin/ && \
    chmod +x /usr/local/bin/ffuf && \
    rm ffuf.tar.gz

# Sqlmap (via git clone - it's Python-based)
RUN apt-get update && apt-get install -y python3 git && \
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap && \
    chmod +x /usr/local/bin/sqlmap && \
    apt-get remove -y git && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Copy compiled binary from builder
COPY --from=builder /app/target/release/kheprimaat /usr/local/bin/kheprimaat

# Copy configuration templates
COPY templates /app/templates
COPY assets /app/assets

# Create data directory for database
RUN mkdir -p /data

# Set environment variables
ENV DATABASE_PATH=/data/kheprimaat.db
ENV RUST_LOG=info

# Expose Control API port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/metrics || exit 1

# Run as non-root user for security
RUN useradd -m -u 1000 khepri && \
    chown -R khepri:khepri /app /data
USER khepri

# Default command: start Control API
CMD ["kheprimaat", "control-api", "--host", "0.0.0.0", "--port", "3000"]
