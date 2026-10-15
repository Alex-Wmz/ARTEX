# Local TLS fix

Source: `github.com/lqqyt2423/go-mitmproxy v1.9.2`, from the Go module proxy.
The original ZIP's Go directory hash was verified against ARTEX's go.sum:
`h1:+QTbDyUUaVRmEavPq0/eWzJ2K+K4JdL4ff91s/adnxk=`.

Only `proxy/`, `cert/`, `internal/`, module metadata, the upstream guidelines,
and the MIT license are included; unrelated standalone CLI and web UI are
omitted. All copied source is unchanged except `proxy/attacker.go`.

The patch falls back to the CONNECT destination when a client omits TLS SNI.
This supplies both the upstream verification name and the generated MITM
certificate name for IP-address URLs. Existing SNI is preserved. Certificate
verification remains enabled by ARTEX (`SslInsecure: false`).

The parent module uses a local `replace` directive. ARTEX's loopback integration
test exercises trusted HTTPS plus a separate untrusted CA and repeated rejection.
Keep this patch and the MIT license when updating the dependency; do not replace
it with an upstream binary or silently remove the `replace` directive.
