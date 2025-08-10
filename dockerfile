FROM rust:1.85-slim AS builder
WORKDIR /usr/src/rusticauth
COPY Cargo.toml Cargo.toml
COPY src src
COPY migrations migrations
COPY templates templates
COPY static static

# build-time deps
RUN apt-get update \
    && apt-get install -y libpq-dev pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# compile the release binary
RUN cargo build --release

FROM debian:bookworm-slim
# runtime deps
RUN apt-get update \
    && apt-get install -y libssl-dev libpq5 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/rusticauth/migrations ./migrations
COPY --from=builder /usr/src/rusticauth/templates ./templates
COPY --from=builder /usr/src/rusticauth/static ./static


# pull in the compiled binary
COPY --from=builder /usr/src/rusticauth/target/release/rusticauth ./rusticauth

EXPOSE 8080
ENTRYPOINT ["./rusticauth"]
