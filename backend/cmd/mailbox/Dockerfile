# Build the standalone Molepipe mailbox server.
#
# Build context is the backend/ module root:
#     docker build -f cmd/mailbox/Dockerfile -t molepipe/mailbox .
#
# This image runs the mailbox in CLEARNET mode (binds a TCP port; clients still
# reach it via Tor). For ONION mode (MAILBOX_ONION=1) the container also needs an
# `arti` binary on PATH — add it in a derived image or bind-mount it, then set
# MAILBOX_ARTI to its path.

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/mailbox ./cmd/mailbox

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mailbox /mailbox
# /data must be writable by the nonroot user (uid 65532). Mount a volume you own:
#   docker run -v mailbox-data:/data ...
VOLUME ["/data"]
ENV MAILBOX_DATA_DIR=/data \
    MAILBOX_ADDR=:8443
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/mailbox", "--help"] || exit 1
USER nonroot:nonroot
ENTRYPOINT ["/mailbox"]
