# Contributing

Keep changes small, documentation in English, and environment-specific settings
in ignored local files. Never commit provider profiles, private keys, kubeconfigs,
actual egress addresses, personal filesystem paths or cluster names.

Run `go test -race ./...`, `go vet ./...`, `gofmt`, and Helm lint/render checks.
Routing/firewall changes also need packet-based tests under faults: a failed HTTP
request alone does not prove there was no bypass. Test application init containers
and pre-existing connections, not just freshly opened TCP sockets.

The runtime image is an allow-listed build context containing only Go source and
module checksums. CI has no VPN credentials and publishes only after checks pass.
Use a separate controlled lab for provider integration; do not use production
workloads as fault-injection targets. Update the verification record with the
exact tests executed and clearly label tests that remain unrun.
