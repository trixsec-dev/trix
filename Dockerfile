# Build stage
FROM docker.io/library/golang:1.24-alpine AS builder

WORKDIR /src

# Install ca-certificates and tzdata for runtime
RUN apk add --no-cache ca-certificates tzdata

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build statically linked binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} \
    go build -ldflags="-s -w -extldflags '-static'" -o /trix .

# Runtime stage - distroless for minimal attack surface
FROM gcr.io/distroless/static-debian12:nonroot

# Labels following OCI image spec
LABEL org.opencontainers.image.source="https://github.com/davealtena/trix"
LABEL org.opencontainers.image.description="Kubernetes Security Scanner with AI-Powered Triage"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Copy timezone data and ca-certs from builder
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary
COPY --from=builder /trix /trix

# Run as non-root user (65532 = nonroot in distroless)
USER 65532:65532

ENTRYPOINT ["/trix"]
