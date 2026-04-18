FROM rust:1.82-slim
WORKDIR /app
COPY Cargo.toml ./
COPY src/ src/
COPY tests/ tests/
RUN cargo build --tests
CMD ["cargo", "test"]
