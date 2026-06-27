FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY . .
RUN go mod download && \
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /domains-exporter

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /domains-exporter /domains-exporter

EXPOSE 9222

ENTRYPOINT ["/domains-exporter"]
