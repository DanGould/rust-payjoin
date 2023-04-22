# x86_64-unknown-linux-musl

## Initial build Stage
FROM rustlang/rust:nightly AS builder
WORKDIR /usr/src/payjoin-client
COPY Cargo.toml Cargo.lock ./
COPY payjoin/Cargo.toml ./payjoin/
COPY payjoin/src ./payjoin/src/
COPY payjoin-client/Cargo.toml ./payjoin-client/
COPY payjoin-client/src ./payjoin-client/src/

RUN apt-get update && apt-get install -y musl-tools musl-dev libssl-dev
RUN rustup target add x86_64-unknown-linux-musl
RUN cargo build --release --bin=payjoin-client --target x86_64-unknown-linux-musl --features=native-tls-vendored
RUN ls .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /usr/src/payjoin-client/target/x86_64-unknown-linux-musl/release/payjoin-client .
RUN ls .
# Run
ENTRYPOINT [ "./payjoin-client" ]
