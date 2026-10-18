# syntax=docker/dockerfile:1
#
# Multi-stage build for the Best Bank demo.
#
#   docker build -t bestbank .
#   docker run --rm -p 8000:8000 -v bestbank-data:/data \
#       -e ROCKET_SECRET_KEY="$(openssl rand -base64 32)" bestbank
#
# or use docker-compose.yml. The image ships no secret key: the container
# refuses to start without ROCKET_SECRET_KEY.

ARG RUST_VERSION=1
ARG DEBIAN_RELEASE=trixie

# ---- build ---------------------------------------------------------------
FROM rust:${RUST_VERSION}-slim-${DEBIAN_RELEASE} AS build
WORKDIR /src
ENV CARGO_PROFILE_RELEASE_STRIP=true

# Build dependencies first so they're cached across source-only changes.
COPY Cargo.toml Cargo.lock build.rs ./
COPY migrations ./migrations
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src target/release/deps/bestbank-* target/release/bestbank*

COPY src ./src
RUN cargo build --release --locked

# The runtime image has no shell, so prepare the data directory here; a new
# named volume mounted at /data inherits this ownership.
RUN mkdir -p /out/data

# ---- runtime -------------------------------------------------------------
# Distroless: glibc + libgcc + CA certs, no shell or package manager, runs as
# the unprivileged "nonroot" user (uid 65532).
FROM gcr.io/distroless/cc-debian13:nonroot

WORKDIR /app
COPY --from=build /src/target/release/bestbank /app/bestbank
COPY Rocket.toml ./
COPY templates ./templates
COPY static ./static
COPY --from=build --chown=65532:65532 /out/data /data

ENV ROCKET_PROFILE=container \
    ROCKET_ADDRESS=0.0.0.0 \
    ROCKET_PORT=8000
USER nonroot:nonroot
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app/bestbank", "healthcheck"]

ENTRYPOINT ["/app/bestbank"]
