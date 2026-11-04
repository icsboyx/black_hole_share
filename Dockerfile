FROM docker.io/library/rust:1.98-slim-bookworm AS builder

WORKDIR /opt/bhs
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM docker.io/library/debian:bookworm-slim

COPY --from=builder /opt/bhs/target/release/black_hole_share /usr/local/bin/black_hole_share

# The mounted data/ directory must be writable by this UID.
USER 1000:1000
WORKDIR /
CMD [ "black_hole_share" ]
