FROM rust:1.86.0-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev build-essential curl && \
    cargo install cargo-watch

WORKDIR /auth-service

COPY . .

EXPOSE 8080

CMD ["cargo", "watch", "-x", "run"]

