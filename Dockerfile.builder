FROM rust:1.97-bookworm

RUN apt-get update && \
    apt-get install -y libpam0g-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
