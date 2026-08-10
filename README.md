# Rapid Reset Check

`rapid-reset-check` is a small Go CLI for quickly inventorying HTTPS endpoints that expose HTTP/2 and therefore need a CVE-2023-44487 mitigation review.

The scanner is deliberately non-exploitative. It resolves each target, opens a certificate-verified TLS connection, offers `h2` and `http/1.1` through ALPN, records what the peer selects, and closes the connection. It sends no HTTP request, HTTP/2 connection preface, stream, `RST_STREAM` frame, or flood traffic.

> [!IMPORTANT]
> Negotiating `h2` is an exposure observation, not proof that a service is vulnerable or unpatched. A remote handshake cannot verify an HTTP/2 implementation's Rapid Reset limits, patch level, upstream origin, or DDoS controls.

## Why this approach?

[CVE-2023-44487](https://nvd.nist.gov/vuln/detail/CVE-2023-44487) is a denial-of-service technique that abuses rapid HTTP/2 stream creation and cancellation. Attempting to prove the condition against a live service would itself require potentially disruptive traffic. This tool instead answers the safe first question: **which tested TLS endpoints currently negotiate HTTP/2 and therefore require an operator to verify mitigation?**

HTTP/2 over TLS is advertised using the `h2` ALPN identifier defined by [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113.html#section-3.1). Google recommends verifying or patching every HTTP/2-capable server, proxy, and load balancer in the request path; see its [CVE-2023-44487 guidance](https://cloud.google.com/blog/products/identity-security/google-cloud-mitigated-largest-ddos-attack-peaking-above-398-million-rps/).

## Requirements and build

- Go 1.22 or newer
- Authorization to connect to every target you scan

No Node.js, cURL, nghttp2, or WHOIS installation is required.

```bash
go test ./...
go build -o rapid-reset-check ./cmd/rapid-reset-check
```

## Quick start

Scan one or more public endpoints:

```bash
./rapid-reset-check example.com api.example.com:8443
```

Bare hostnames are normalized to HTTPS on port 443. Authority-only HTTPS URLs are also accepted:

```bash
./rapid-reset-check https://example.com https://api.example.com:8443
```

Scan the repository's JSON target list:

```bash
./rapid-reset-check --input json/urls.json
```

Use standard input for automation:

```bash
printf '["example.com", "api.example.com"]' | ./rapid-reset-check --input -
```

Run `./rapid-reset-check --help` for all limits and output options.

## Input

`--input` accepts the original JSON array format:

```json
[
  "example.com",
  "api.example.com:8443",
  "https://www.example.net"
]
```

The object forms `{"urls": [...]}` and `{"targets": [...]}` are also supported. Positional targets and `--input` are intentionally mutually exclusive. Duplicate normalized endpoints are scanned once, and each run is limited to 4,096 input targets.

Only HTTPS endpoints are in scope. Credentials, non-root paths, queries, fragments, unsupported schemes, malformed ports, and ambiguous hostnames are rejected instead of silently rewritten.

## Assessments

| Assessment | Meaning |
| --- | --- |
| `h2_observed_review_required` | At least one verified TLS peer selected `h2`. Review every HTTP/2 component in that path; this is not a vulnerability verdict. |
| `h2_not_observed_on_tested_path` | Every selected address completed a verified handshake without selecting `h2`. This is a point-in-time path observation, not a safety guarantee. |
| `indeterminate` | A DNS, connection, timeout, TLS, certificate, or address-limit issue prevented a complete observation. |
| `not_scanned_policy` | The resolved addresses were excluded by the scanner's network safety policy. |
| `invalid_target` | The input was malformed or outside the supported HTTPS authority scope. |

The report includes each resolved address attempted, negotiated ALPN, TLS version and cipher, limited certificate identity/validity data, timing, policy decisions, omitted-address counts, an explicit completeness flag, and a summary. It does not collect response bodies, response headers, cookies, or raw certificates.

## Safe defaults

- TLS certificates and hostnames are verified. Use `--ca-file` to add a private CA; there is no insecure verification mode.
- Loopback, private, link-local, multicast, unspecified, CGNAT, documentation, benchmark, and other reserved addresses are blocked by default. Use `--allow-private` only for internal endpoints you are authorized to assess.
- DNS results are pinned for each connection while the original hostname is retained for SNI and certificate verification.
- Connection concurrency, per-address timeouts, and addresses per target are bounded.
- The scanner does not retry automatically and does not follow redirects because it never sends an HTTP request. Submit each HTTPS authority you need to assess.

Example options:

```bash
./rapid-reset-check \
  --format json \
  --timeout 5s \
  --concurrency 4 \
  --max-addresses 8 \
  example.com > report.json
```

For an authorized private-PKI endpoint:

```bash
./rapid-reset-check \
  --allow-private \
  --ca-file ./internal-root-ca.pem \
  service.internal:8443
```

Exit code `0` means every target produced a complete ALPN observation. Exit code `1` means at least one target was invalid, blocked by policy, or indeterminate; the report is still written. CLI usage and configuration errors return `2`. Observing `h2` does not by itself change the exit code because it is an inventory signal, not a vulnerability verdict.

## Interpreting and acting on results

For every `h2_observed_review_required` result:

1. Identify the externally visible TLS terminator and all HTTP/2-capable proxies, load balancers, gateways, and origin servers behind it.
2. Check each product and version against its vendor's CVE-2023-44487 advisory.
3. Apply current patches and the vendor's reset/rate-limiting guidance.
4. Confirm that edge DDoS controls protect the origin and cannot be bypassed through an alternate hostname, address, or port.
5. Validate configuration and patch state from trusted inventory or telemetry. Do not use this scanner's ALPN result as evidence of remediation.

## Limitations

Results are specific to the hostname, DNS answers, network path, TLS endpoint, and scan time. CDNs, anycast, split-horizon DNS, load balancing, alternate ports, and untested addresses can produce different results. The scanner does not:

- determine whether a server is vulnerable, patched, mitigated, or safe;
- test Rapid Reset behavior or send any reset frames;
- inspect cleartext HTTP/2 (`h2c`), QUIC/HTTP/3, redirects, origins hidden behind an edge, or non-HTTPS services;
- infer patch status from spoofable `Server` headers or CDN fingerprints;
- replace configuration review, asset inventory, vendor guidance, or authorized load testing in an isolated environment.

## Development

```bash
gofmt -w ./cmd ./internal
go vet ./...
go test ./...
go test -race ./...
go build ./...
```

The test suite uses local TLS fixtures and does not scan public services.
