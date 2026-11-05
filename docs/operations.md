# Operations and troubleshooting

## Preflight

Inspect your nodes, CNI, DNS configuration and PSA constraints before installation.
The chart never configures another CNI or modifies kubelet/node settings. Example
commands explicitly select the intended kubeconfig:

```sh
KUBECONFIG=~/.kube/talos kubectl get nodes -o wide
KUBECONFIG=~/.kube/talos kubectl get daemonsets -A
KUBECONFIG=~/.kube/talos kubectl -n kube-system get service kube-dns
KUBECONFIG=~/.kube/talos kubectl -n kube-system get configmap coredns -o yaml
KUBECONFIG=~/.kube/talos kubectl get namespaces --show-labels
```

Check TUN availability and network-namespace forwarding in a disposable Pod.
The guard refuses missing forwarding or reverse-path-filter prerequisites after
installing its firewall. It does not attempt privileged proc mounts or host writes.
If your runtime does not supply these prerequisites, this release cannot run
there unchanged; do not resolve it by granting host access to the controller.

## Status and counters

```sh
KUBECONFIG=~/.kube/talos kubectl -n vpn-gateway logs deployment/vpn-admission
KUBECONFIG=~/.kube/talos kubectl -n vpn-gateway logs deployment/vpn-gateway -c gluetun
KUBECONFIG=~/.kube/talos kubectl -n vpn-gateway logs deployment/vpn-gateway -c overlay
KUBECONFIG=~/.kube/talos kubectl -n vpn-gateway exec deployment/vpn-gateway -c overlay -- cat /run/vpn/status
KUBECONFIG=~/.kube/talos kubectl -n vpn-gateway exec deployment/vpn-gateway -c overlay -- nft list table inet vpn_guard
KUBECONFIG=~/.kube/talos kubectl -n vpn-apps exec POD -c vpn-guard -- nft list table inet vpn_guard
KUBECONFIG=~/.kube/talos kubectl -n vpn-apps exec POD -c vpn-guard -- ip route
```

OpenVPN status contains virtual clients and byte counts, never private keys.
nftables counters distinguish tunnel traffic, explicit exceptions, IPv6 drops
and other blocked output/forwarding. They reset on guard reinstallation. Gluetun
readiness reflects its own VPN health. A healthy application exec probe alone is
not proof of VPN availability; inspect Gluetun and the actual egress IP as well.

- Pod admission error: check exact string annotation values, per-container UID,
  capabilities and exec-only probes. No application container may use the reserved
  guard name, mount, or annotation.
- Stuck at startup: inspect `vpn-guard`, transport Secret availability, and namespace
  PSA events. A missing Secret or failed firewall installation is intentionally fatal.
- Tunnel up but no replies: inspect `ip rule` in the gateway. Priority 50 must
  select main for `198.18.0.0/24`; main must have `vpnlink` connected. Inspect
  Gluetun post-rules and the independent SNAT counters.
- Gateway replacement: keep its Service. Allow the OpenVPN heartbeat/reconnection
  interval plus CNI/Service convergence. No direct fallback is permitted.
- DNS: only the local relay can use CoreDNS, and only for `cluster.local`.
  Access to internal service addresses is deliberately blocked.

## Certificates and rotation

cert-manager owns a namespaced CA Issuer and three separate leaf Certificates:
webhook server, overlay server and overlay client. Leaf certificates last 90 days
and renew 30 days before expiry. The webhook loads its key pair for each TLS
handshake; CA injection updates the webhook configurations. The controller copies
the client leaf bundle every 30 seconds to pre-created named Secrets. Projected
Secret updates reach the sidecar without subPath mounts; it restarts only OpenVPN
after detecting changed bytes. An offline controller delays client certificate
sync but never removes protection; prolonged expiry causes a safe outage.

The root CA lasts ten years. CA rotation is an explicit maintenance operation:
cert-manager CA Issuers do not automatically reissue every leaf when their signing
Secret changes. Before the root renewal window, schedule renewal of all leaf
Certificates using cert-manager's supported tooling, verify CA injection and
client Secret propagation, and accept a fail-closed reconnection outage. Back up
CA material through your existing Secret backup policy. Do not delete signing
Secrets to troubleshoot a leaf issue. A zero-downtime root migration with dual
trust is not implemented in this first version.

## Updates and rollback

Pin the application and Gluetun images by digest. Change one component at a time,
run the acceptance matrix, and keep the previous chart/image configuration for
rollback. The gateway uses Recreate to avoid simultaneous active instances.
Provider Secret changes require a planned gateway recreation: Gluetun reads the
configuration at startup. Changing its endpoint must never create a client
FORWARD exception. A client image/config change applies to new Pods; schedule
application rollouts explicitly. Existing old injected guards may be rejected
for Pod updates after a configuration/image change until they are recreated.

Do not set the same provider WireGuard identity in simultaneously running test
and production gateways unless the provider explicitly supports that use.

## Removal

Do not remove client nftables rules, add direct routes or delete running clients'
network sidecars. An offline or removed controller leaves their rules in place.
The chart annotates both webhook configurations and copied client Secrets with
`helm.sh/resource-policy: keep`. A Helm uninstall therefore blocks creation of
selected workloads while already running clients remain protected (and may lose
VPN access). Restoring the release restores admission and transport.

For deliberate decommission: stop/recreate selected workloads according to their
owners' rollout policy, explicitly remove selection from their Deployment/Pod
manifests, and confirm there are no protected Pods left before manually deleting
the retained webhook configurations. Then remove the copied transport Secrets
and cert-manager CA/leaf Secrets through your normal secret retention procedure.
GitOps pruning tools may interpret retention annotations differently: configure
them to preserve both webhook objects. Removing them while selected workloads
still exist permits future replacement Pods to start without this protection.
