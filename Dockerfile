FROM golang:1.26-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/regauth ./cmd/regauth \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/reguser ./cmd/reguser

FROM alpine:latest
RUN apk add --no-cache ca-certificates && \
    addgroup -S -g 1000 regauth && adduser -S -u 1000 -G regauth regauth
COPY --from=builder /out/regauth /usr/local/bin/regauth
COPY --from=builder /out/reguser /usr/local/bin/reguser
RUN mkdir -p /var/lib/regauth && \
    chown -R regauth:regauth /var/lib/regauth
USER regauth
WORKDIR /var/lib/regauth
ENTRYPOINT ["/usr/local/bin/regauth"]
CMD ["server", "-c", "/etc/regauth/config.yaml"]
