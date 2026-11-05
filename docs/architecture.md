# Packet path, routing and DNS

## Outbound and return traffic

1. The application opens an IPv4 socket. OpenVPN installs two `/1` routes through
   `vpnlink` and uses an assigned address from `198.18.0.0/24`.
2. OpenVPN authenticates the gateway certificate and encapsulates IP packets in
   encrypted UDP to the gateway Service at port 1194. A pinned `/32` CNI route
   keeps the transport outside its own tunnel. Only the root-owned transport
   socket can use the ordinary-interface firewall exception.
3. kube-proxy sends UDP to the active gateway Pod. CNI networking carries it
   across nodes in exactly the same way as ordinary Pod traffic. There is no
   multicast, L2 adjacency assumption or new node-level overlay.
4. The gateway OpenVPN server validates the client certificate and client virtual
   source address, decapsulates and writes into its `vpnlink` TUN.
5. Kernel forwarding must traverse the independent `inet vpn_guard` table:
   only `vpnlink -> tun0` is accepted, with the fixed overlay source range and
   special/private destination ranges blocked. Gluetun's own iptables FORWARD
   chain additionally needs the mounted post-rules; the chart supplies them.
6. POSTROUTING masquerades the overlay source on `tun0`. Gluetun's WireGuard
   encrypts and sends the provider traffic using its own endpoint/bootstrap rules.
7. VPN replies are reverse-NATed by conntrack. Policy rule priority **50**, limited
   to the overlay destination subnet, looks up the main table's connected
   `vpnlink` route before Gluetun's WireGuard policy table. OpenVPN maps the
   assigned destination to its client session and sends encrypted UDP back.

The independent nftables table uses filter priority 10 and NAT priority 110,
separate from Gluetun's iptables-managed tables. An iptables ACCEPT cannot override
an nftables DROP in a subsequent hook. Gluetun reloads may temporarily block
forwarding; they must never delete `inet vpn_guard`. A malicious NET_ADMIN
process in the trusted network components can change this table and is outside
the application's protection boundary.

No client rule accepts ordinary OUTPUT merely because conntrack says ESTABLISHED.
There is no automatic route/firewall rollback. Gateway FORWARD accepts VPN return
states only for `tun0 -> vpnlink`; existing client sessions cannot fail over to
`eth0` if the VPN route disappears.

## MTU

Both overlay TUNs use MTU 1280 and OpenVPN MSS adjustment 1240. This leaves space
for authenticated UDP over a typical 1450-byte Flannel path and for a typical
provider WireGuard path. OpenVPN handles overlay fragmentation when necessary;
IPv4 packets larger than the inner MTU are fragmented or receive local
fragmentation-needed errors according to DF. Related ICMP can return through the
client input guard. There is no IPv6 PMTU promise: IPv6 is dropped. Networks with
smaller path MTUs require independent testing; do not silently raise the MTU.

## Discovery and replacement

Admission reads one named gateway Service once at startup and injects its IPv4
ClusterIP. A client needs neither a Kubernetes API token nor CoreDNS to establish
the transport. Service endpoint changes are handled by the dataplane and OpenVPN
heartbeat/reconnection (5-second ping, 20-second restart). OpenVPN uses `nobind`,
so a new UDP source port avoids an old Service conntrack entry. Certificate file
changes are detected every 10 seconds and restart only OpenVPN, retaining the
firewall. The Service **must not** be deleted/recreated with a different ClusterIP
without recreating clients. Controller downtime does not affect existing clients.

## DNS exception

The injected DNS policy uses only `127.0.0.1`, with namespace and cluster search
suffixes and `ndots:1`. The Go resolver handles UDP and TCP and retries truncated
UDP replies over TCP. It has no host-resolver fallback:

- `cluster.local.` and its subdomains go to the configured CoreDNS Service over
  the ordinary interface, on port 53, from a root-owned socket.
- All other questions, including reverse DNS, go to the configured public resolver
  through `vpnlink`. Application attempts to contact CoreDNS directly are dropped.
- Other cluster domains and arbitrary internal DNS forwarding are not supported.

CoreDNS must be authoritative for `cluster.local` and must not forward that zone
to public resolvers. Verify the actual Corefile. Search expansion of a short name
can send its `*.cluster.local` forms to CoreDNS; this is the explicit exception,
not a claim that internal query names are hidden from the cluster DNS operator.
The resolver does not log queried names. Application DoH or explicit public DNS
connections use the same VPN-only routing as every other external socket.

## Internal traffic, ingress and probes

There are no generic pod, service, node, RFC1918 or Kubernetes API bypasses. Only
the transport and resolver exceptions above exist. IPv4 loopback and VPN traffic
are allowed; IPv6 is dropped even on loopback. The gateway rejects overlay access
to its own services and does not enable OpenVPN client-to-client forwarding.
Ordinary application ingress and responses are blocked, avoiding asymmetric
routing and a broad established-connection bypass. Use exec health probes and
run this version only for egress-oriented workloads. HTTP/TCP/gRPC application
probes are rejected. Local UNIX sockets continue to work normally.
