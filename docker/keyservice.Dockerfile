# syntax=docker/dockerfile:1.7
# The key service and the witness, for the staging smoke profile only (compose.staging.yaml).
# Build from the repository root: docker build -f docker/keyservice.Dockerfile -t orbyn-keyservice:smoke .
#
# This image holds SoftHSM, a software token, so that a smoke test needs no hardware. A real
# deployment mounts its HSM's PKCS#11 module and does not use this image as it is.

FROM rust:1-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p orbyn-keyservice-daemon -p orbyn-witness \
 && cp target/release/orbyn-keyservice target/release/orbyn-witness /

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl openssl softhsm2 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin orbyn \
 && mkdir -p /pki /hsm /witness-keys /witness-state \
 && chown orbyn /pki /hsm /witness-keys /witness-state
COPY --from=build /orbyn-keyservice /orbyn-witness /usr/local/bin/
COPY --chmod=755 docker/smoke-entry.sh /usr/local/bin/smoke-entry.sh
USER orbyn
ENTRYPOINT ["/usr/local/bin/smoke-entry.sh"]
