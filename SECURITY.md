# Security reporting

This project is experimental and has no production security support commitment.
Report suspected vulnerabilities through the repository's private vulnerability
reporting feature when available. Do not include VPN profiles, private keys,
kubeconfigs, Secret manifests, packet payloads or personal endpoint information
in public issues. If private reporting is unavailable, request a private reporting
channel without disclosing exploit details publicly.

The protection boundary and remaining limits are documented in
[the security model](docs/security.md). No release should be treated as proven
leak-free without the fault matrix on the exact CNI, runtime and image versions.
