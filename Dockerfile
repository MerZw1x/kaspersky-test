FROM golang:1.26.5-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
COPY db ./db
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/threatintel ./cmd/threatintel

FROM alpine:3.23

RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /out/threatintel /app/threatintel
COPY config/docker/config.yaml /app/config.yaml

USER 65532:65532
EXPOSE 8000
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=5 \
    CMD wget -q -T 2 -O /dev/null http://127.0.0.1:8000/health || exit 1
ENTRYPOINT ["/app/threatintel"]
CMD ["-config", "/app/config.yaml"]
