FROM --platform=$TARGETOS/$TARGETARCH rust:1.100.0-slim-trixie AS build-image
LABEL org.opencontainers.image.description="PostgreSQL connection benchmark"
LABEL authors="Bixority SIA"

ARG TARGETARCH=amd64
ARG TARGETOS=linux

WORKDIR /build

RUN apt update && apt install -y --no-install-recommends make xz-utils musl-tools musl-dev && \
  rm -rf /var/lib/apt/lists/*

COPY ./ /build/

# Map container architecture to Rust target
RUN echo "Target architecture is: ${TARGETARCH}" && \
    if [ "${TARGETARCH}" = "amd64" ]; then \
        RUST_TARGETARCH=x86_64 make release; \
    elif [ "${TARGETARCH}" = "arm64" ]; then \
        RUST_TARGETARCH=aarch64 make release; \
    else \
        echo "Unsupported architecture: ${TARGETARCH}"; exit 1; \
    fi

FROM --platform=$TARGETOS/$TARGETARCH gcr.io/distroless/static-debian13:nonroot

LABEL org.opencontainers.image.description="PostgreSQL connection benchmark"
LABEL authors="Bixority SIA"

ARG TARGETARCH
ARG TARGETOS

WORKDIR /
COPY --from=build-image /build/target/pg-conn-bench /build/LICENSE /

USER nonroot:nonroot

EXPOSE 8080
ENTRYPOINT ["/pg-conn-bench"]
