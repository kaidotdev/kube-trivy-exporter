# syntax=docker/dockerfile:experimental

FROM golang:1.13-alpine AS builder

ENV deps "git curl"

RUN apk update && apk upgrade

RUN apk add --no-cache $deps

ENV CGO_ENABLED 0

ENV TRIVY_VERSION 0.15.0

RUN curl -sSL https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz | tar -zx -C /tmp

WORKDIR /build/

COPY go.mod go.sum /build/
RUN --mount=type=cache,target=/root/go/pkg/mod go mod download

RUN apk del --purge $deps

COPY cmd /build/cmd
COPY pkg /build/pkg
RUN --mount=type=cache,target=/root/.cache/go-build go build -trimpath -o /usr/local/bin/main -ldflags="-s -w" /build/cmd/main.go

FROM alpine:3.13
COPY --from=builder /usr/local/bin/main /usr/local/bin/main
COPY --from=builder /tmp/trivy /usr/local/bin/trivy

RUN apk add --no-cache git && \
    addgroup -S -g 10001 kube-trivy-exporter && \
    adduser -S -u 10001 kube-trivy-exporter -G kube-trivy-exporter

USER 10001:10001
ENTRYPOINT ["/usr/local/bin/main"]
CMD ["server"]
