# Build stage
FROM rust:1.80 AS builder
WORKDIR /app
# 1) Build deps layer
COPY Cargo.toml .
RUN mkdir -p src && echo 'fn main(){}' > src/main.rs && cargo generate-lockfile
RUN cargo build --release

# 2) Copy sources and build
COPY src ./src
COPY templates ./templates
COPY static ./static
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/acho-site ./acho-site
# Copy runtime assets (templates, static)
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static
# Create runtime dirs
RUN mkdir -p ./uploads ./data
VOLUME ["/app/uploads", "/app/data"]
EXPOSE 3000
ENV RUST_LOG=info
CMD ["./acho-site"]
