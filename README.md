# domains-exporter

A Prometheus exporter for monitoring domain registration expiration dates using WHOIS queries.

## Overview

`domains-exporter` is a multi-target Prometheus exporter that periodically queries WHOIS servers to extract domain expiration dates and exposes them as Prometheus metrics. It follows the classic [blackbox_exporter](https://github.com/prometheus/blackbox_exporter) pattern where Prometheus owns the list of targets and the exporter performs queries on demand.

## Features

- **Multi-target probe model**: Domains are specified in Prometheus scrape config, exporter probes each on request
- **TTL caching**: Protects WHOIS servers from hammering (default 3h cache)
- **Wide TLD support**: Uses `likexian/whois` + `likexian/whois-parser` for most TLDs, with fallback parsing for edge cases
- **Metrics**: Expiration timestamp, seconds remaining, probe success, and cache status
- **Per-request custom WHOIS server**: Override the default WHOIS server for specific domains

## Installation

### Build from source

```bash
go build -o domains-exporter .
```

### Run

```bash
./domains-exporter --web.listen-address=:9222 --cache-ttl=3h --whois-timeout=10s
```

### Docker

```bash
docker build -t domains-exporter .
docker run -p 9222:9222 domains-exporter
```

## Usage

### Prometheus Configuration

Add a scrape job to your `prometheus.yml`:

```yaml
- job_name: 'domains-exporter'
  metrics_path: /probe
  static_configs:
    - targets:
        - example.com
        - example.ua
  relabel_configs:
    - source_labels: [__address__]
      target_label: __param_target
    - source_labels: [__param_target]
      target_label: instance
    - target_label: __address__
      replacement: 'localhost:9222'
  scrape_interval: 60s
  scrape_timeout: 30s
```

### Probing a domain manually

```bash
curl 'http://localhost:9222/probe?target=example.com'
```

With optional custom WHOIS server:

```bash
curl 'http://localhost:9222/probe?target=example.ua&server=whois.ua'
```

## Flags

- `--web.listen-address` (default: `:9222`) - Address to listen on for HTTP requests
- `--cache-ttl` (default: `3h`) - Time-to-live for cached WHOIS results
- `--whois-timeout` (default: `10s`) - Timeout for WHOIS queries
- `--log-level` (default: `info`) - Log level: debug, info, warn, error

## Metrics

All probe metrics are returned on-demand from the `/probe` endpoint:

| Metric | Type | Description |
|--------|------|-------------|
| `domain_probe_success` | Gauge | 1 if the WHOIS lookup succeeded, 0 otherwise |
| `domain_expiration_timestamp_seconds` | Gauge | Unix timestamp when the domain expires |
| `domain_expiration_seconds_remaining` | Gauge | Seconds until expiration (negative if expired) |
| `domain_probe_duration_seconds` | Gauge | Duration of the WHOIS lookup |
| `domain_probe_cached` | Gauge | 1 if the result was served from cache, 0 otherwise |

Exporter internal metrics (available on `/metrics`):

| Metric | Type | Description |
|--------|------|-------------|
| `domain_exporter_probes_total` | Counter | Total number of probes performed |
| `domain_exporter_probes_failed_total` | Counter | Total number of failed probes |
| `domain_exporter_probes_cached_total` | Counter | Total number of probes served from cache |

## Example Queries

Days remaining (PromQL):
```promql
(domain_expiration_seconds_remaining / 86400)
```

Domains expiring within 30 days:
```promql
domain_expiration_seconds_remaining < 86400 * 30
```

Domains with successful probes:
```promql
domain_probe_success == 1
```

## Example Alerting Rules

```yaml
groups:
  - name: domains
    rules:
      - alert: DomainExpirationWarning
        expr: domain_expiration_seconds_remaining < 86400 * 30
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Domain {{ $labels.instance }} expires in 30 days"

      - alert: DomainExpirationCritical
        expr: domain_expiration_seconds_remaining < 86400 * 7
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Domain {{ $labels.instance }} expires in 7 days"

      - alert: DomainExpired
        expr: domain_expiration_seconds_remaining < 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Domain {{ $labels.instance }} has expired"
```

## Supported TLDs

The exporter supports WHOIS queries for most TLDs via the `likexian/whois` and `likexian/whois-parser` libraries, with fallback parsing for:

- `.ua`, `.pp.ua`, `.biz.ua`, `.co.ua`, `.com.ua`, `.net.ua`, `.org.ua`, `.gov.ua`, `.edu.ua`, `.in.ua`
- `.cz`
- `.sk`
- `.se`, `.nu`
- `.pl`
- `.it`
- `.br`
- `.do`
- `.id`
- `.mx`
- `.fm`

For unsupported TLDs, you can specify a custom WHOIS server:

```bash
curl 'http://localhost:9222/probe?target=example.custom&server=whois.custom.registry'
```

## Endpoints

- `GET /probe?target=<domain>` - Probe a domain
- `GET /probe?target=<domain>&server=<whois_server>` - Probe with custom WHOIS server
- `GET /metrics` - Exporter internal metrics
- `GET /healthz` - Health check (JSON response)
- `GET /` - Landing page with documentation

## Kubernetes Deployment

Example Kubernetes manifests are provided in the `deploy/` directory:

```bash
kubectl apply -f deploy/kubernetes.yaml
```

This deploys:
- Namespace: `domains-exporter`
- ServiceAccount, Service, Deployment
- ServiceMonitor for Prometheus Operator

Adjust the image name in the Deployment manifest to point to your registry.

## Development

### Run tests

```bash
go test -v ./...
```

### Run linter

```bash
golangci-lint run
```

### Local testing

```bash
go run . --log-level=debug
# In another terminal:
curl 'http://localhost:9222/probe?target=example.com'
```

## License

MIT

## Contributing

Contributions welcome! Please open issues or PRs.
