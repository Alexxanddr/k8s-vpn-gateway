# Verification record

Status: experimental. This is an evidence log, not a claim that every acceptance
criterion has passed. Never include private provider configuration, actual egress
addresses or personal cluster identifiers in public results.

## Automated checks

Unit tests cover annotation precedence, synchronous Deployment template mutation,
idempotence with Kubernetes defaulting, Pod update rejection, root/capability/
namespace restrictions, forged guard fields, ephemeral containers, and DNS suffix
classification. CI runs race detection, vet, formatting, Helm lint/render, image
builds and an allow-list check for secret-like tracked files.

## Real integration testing

`tests/local.sh` builds a mutually authenticated overlay with a real provider
profile mounted read-only into disposable Docker containers. It compares ordinary
and protected egress, checks DNS and direct-interface blocking, stops Gluetun and
the gateway, and continuously captures the ordinary client interface. Generated
TLS material is ephemeral and deleted on exit. This script does not exercise
Kubernetes admission or prove multi-node networking.

The first integration run found that Gluetun WireGuard policy routing intercepted
return traffic to overlay clients. An overlay-only main-table rule at priority 50
fixed it. A subsequent capture run also identified a Docker test harness ordering
issue: application exec had to wait for the startup marker, just as Kubernetes
native-sidecar startup probes do. The harness now waits explicitly.

The corrected local real-provider run passed: protected and ordinary egress IPs
differed, public DNS worked, direct-interface requests failed, Gluetun stop blocked
egress, gateway stop retained protection, and the continuous ordinary-interface
egress capture contained **zero bypass packets**. This is Docker evidence, not
a claim that all Kubernetes failure cases have passed. Go tests and vet passed;
vulnerability analysis reported no reachable vulnerabilities after updating the
HTTP/2 dependency. Two non-reachable module advisories remain reported by the tool.

## Cluster suite

Install the chart in `vpn-gateway-test`, list `vpn-client-test` as its client
namespace, and provision the provider Secret separately. Neither namespace should
contain production workloads. Then run:

```sh
TEST_IMAGE=ghcr.io/alexxanddr/k8s-vpn-gateway:test-sha-COMMIT \
  tests/cluster.sh
RUN_FAULTS=1 TEST_IMAGE=ghcr.io/alexxanddr/k8s-vpn-gateway:test-sha-COMMIT \
  tests/cluster.sh
```

The suite exercises actual Deployment -> ReplicaSet -> Pod inheritance, user init
ordering, public UDP/TCP DNS, internal DNS, direct DNS/IPv6/interface blocking,
controller outage and gateway replacement. It observes the ordinary postrouting
path with nftables counters throughout faults and starts a persistent HTTP client
that reuses connections across requests. Local evidence is ignored under
`artifacts/`; inspect it, including connection-reuse markers, before interpreting
a result. A public diagnostic endpoint is used by default. Set `TEST_URL` to an
endpoint you control that exposes `ip=SOURCE_ADDRESS` for controlled attribution.

For a multi-node test, schedule the gateway with `gatewayNodeSelector` and place
the test client on another node. The suite reports the actual placements; it must
not label a single-node run as cross-node proof.

## Acceptance matrix

| Criterion | Evidence required |
| --- | --- |
| Selected VPN IP; ordinary IP unchanged | Different observed IPs and provider confirmation |
| TCP and UDP | HTTP plus UDP DNS and TCP DNS through the overlay |
| IPv4/IPv6/DNS leak resistance | Ordinary-path counters/capture, IPv6 drop increments, direct CoreDNS blocked |
| User init ordering | Guard first; init direct-interface attempt fails |
| Tunnel/Gluetun down | Independent forward guard retained while tunnel/process is stopped |
| Gateway removed and recreated | No bypass during outage; connection recovers; actual Pod IP change recorded |
| Provider endpoint unreachable | Drop the endpoint only inside gateway netns, continuously monitor, then remove the test drop |
| Controller offline | Existing connections continue; selected creates fail; unrelated creates succeed |
| Multi-node | Distinct actual gateway/client node names and successful traffic |
| Admission conflicts | Dry-run incompatible root/caps/guard tampering rejected; final state validates |

Limits requiring additional lab evidence include arbitrary UDP echo to a
controlled public receiver, pathological MTUs, provider endpoint blackholing and
long-lived traffic observation across every failure type, certificate/root
rotation, upgrade/uninstall behavior and an independently controlled external DNS
observer. A failed curl alone is never recorded as proof of no bypass.
