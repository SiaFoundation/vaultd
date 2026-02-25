FROM docker.io/library/golang:1.26 AS builder

WORKDIR /vaultd

# Install dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Enable CGO for sqlite3 support
ENV CGO_ENABLED=1

RUN go generate ./...
RUN go build -o bin/ -tags='netgo timetzdata' -trimpath -a -ldflags '-s -w -linkmode external -extldflags "-static"'  ./cmd/vaultd

FROM debian:bookworm-slim
LABEL maintainer="The Sia Foundation <info@sia.tech>" \
    org.opencontainers.image.description.vendor="The Sia Foundation" \
    org.opencontainers.image.description="A vaultd container - sign Siacoin transactions offline using a seed" \
    org.opencontainers.image.source="https://github.com/SiaFoundation/vaultd" \
    org.opencontainers.image.licenses=MIT


# copy binary and prepare data dir.
COPY --from=builder /vaultd/bin/* /usr/bin/
VOLUME [ "/data" ]

# API port
EXPOSE 9980/tcp

ENV vaultd_DATA_DIR=/data
ENV vaultd_CONFIG_FILE=/data/vaultd.yml

RUN apt update && apt install -y ca-certificates

ENTRYPOINT [ "vaultd", "--http.addr", ":9980" ]
