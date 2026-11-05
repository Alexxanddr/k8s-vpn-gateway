#!/bin/sh
# Real overlay and provider tests; all routing/firewall changes stay in containers.
set -eu
: "${VPN_PROFILE:?set VPN_PROFILE to an absolute local WireGuard profile path}"
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
prefix="vpn-test-$$"
cleanup() {
  result=$?
  if [ "$result" -ne 0 ]; then
    docker logs --tail 30 "$prefix-gateway" 2>/dev/null || true
    docker logs --tail 30 "$prefix-client" 2>/dev/null || true
  fi
  docker rm -f "$prefix-client" "$prefix-gluetun" "$prefix-gateway" "$prefix-plain" >/dev/null 2>&1 || true
  docker network rm "$prefix" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT INT TERM
platform=linux/amd64
tools=k8s-vpn-gateway:test-tools
mkdir -p "$work/certificates" "$work/post"
docker run --rm --platform "$platform" -v "$work/certificates:/certificates" -v "$root/tests/certificates.sh:/certificates.sh:ro" "$tools" sh /certificates.sh >/dev/null 2>&1
cat > "$work/post/post-rules.txt" <<'RULES'
iptables -I FORWARD 1 -i vpnlink -o tun0 -j ACCEPT
iptables -I FORWARD 1 -i tun0 -o vpnlink -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
RULES
docker network create "$prefix" >/dev/null
docker run -d --platform "$platform" --name "$prefix-gateway" --network "$prefix" --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun --sysctl net.ipv4.conf.all.rp_filter=0 --sysctl net.ipv4.conf.default.rp_filter=0 --tmpfs /run/vpn -v "$work/certificates/server:/transport:ro" "$tools" sh -c 'gateway guard && gateway overlay' >/dev/null
gateway_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$prefix-gateway")
docker run -d --platform "$platform" --name "$prefix-gluetun" --network "container:$prefix-gateway" --cap-drop ALL --cap-add NET_ADMIN --device /dev/net/tun -v "$VPN_PROFILE:/gluetun/wireguard/wg0.conf:ro" -v "$work/post:/iptables:ro" -e VPN_SERVICE_PROVIDER=custom -e VPN_TYPE=wireguard -e WIREGUARD_IMPLEMENTATION=kernelspace -e VPN_INTERFACE=tun0 -e FIREWALL_INPUT_PORTS=1194 qmcgaw/gluetun:v3.41.3@sha256:fa19cc76b2af13d57a8d3dc3066f2ada061b1c761b8aecf989b3877c0486e027 >/dev/null
docker run -d --platform "$platform" --name "$prefix-client" --network "$prefix" --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE --cap-add NET_RAW --device /dev/net/tun --tmpfs /run/vpn -v "$work/certificates/client:/transport:ro" -e GATEWAY_IP="$gateway_ip" -e CLUSTER_DNS=192.0.2.53 -e PUBLIC_DNS=1.1.1.1 "$tools" gateway client >/dev/null
docker run -d --platform "$platform" --name "$prefix-plain" --network "$prefix" --cap-drop ALL "$tools" sleep 600 >/dev/null
printf 'Test containers: %s\n' "$prefix"
for i in $(seq 1 30); do
  if docker exec "$prefix-client" test -f /run/vpn/ready; then break;fi
  sleep 1
done
docker exec "$prefix-client" test -f /run/vpn/ready
# Capture the ordinary client path, not merely whether curl returns an error.
docker exec -d "$prefix-client" sh -c "tcpdump -p -U -Q out -ni eth0 -w /run/vpn/ordinary.pcap '(ip or ip6) and not (host $gateway_ip and udp port 1194) and not (host 192.0.2.53 and port 53)' 2>/run/vpn/capture.log"
ready=false
for i in $(seq 1 40); do
  if docker exec --user 1000 "$prefix-client" curl -fsS --max-time 3 https://1.1.1.1/cdn-cgi/trace > "$work/vpn-trace" 2>/dev/null; then ready=true;break;fi
  sleep 2
done
if [ "$ready" != true ]; then
  docker logs --tail 35 "$prefix-client"
  docker logs --tail 35 "$prefix-gluetun"
  exit 1
fi
docker exec --user 1000 "$prefix-plain" curl -fsS --max-time 15 https://1.1.1.1/cdn-cgi/trace > "$work/plain-trace"
vpn_ip=$(sed -n 's/^ip=//p' "$work/vpn-trace")
plain_ip=$(sed -n 's/^ip=//p' "$work/plain-trace")
[ -n "$vpn_ip" ] && [ "$vpn_ip" != "$plain_ip" ]
printf 'VPN and ordinary egress IPs differ: PASS\n'
docker exec --user 1000 "$prefix-client" dig @127.0.0.1 example.com +short +tries=1 +time=5
# Binding the ordinary interface must fail even while the overlay is healthy.
if docker exec --user 1000 "$prefix-client" curl --interface eth0 -fsS --max-time 3 https://1.1.1.1/cdn-cgi/trace >/dev/null 2>&1; then exit 1;fi
docker exec -d --user 1000 "$prefix-client" sh -c 'for i in $(seq 1 100); do curl -fsS --max-time 1 https://1.1.1.1/cdn-cgi/trace >/dev/null 2>&1 || true; done'
# Existing sessions, peer loss, and controller-independent client process failure.
docker stop "$prefix-gluetun" >/dev/null
for i in $(seq 1 5); do
  if docker exec --user 1000 "$prefix-client" curl -fsS --max-time 2 https://1.1.1.1/cdn-cgi/trace >/dev/null 2>&1; then exit 1;fi
done
printf 'Gluetun process stopped, external traffic blocked: PASS\n'
docker exec "$prefix-client" nft list table inet vpn_guard > "$work/client-rules"
docker stop "$prefix-gateway" >/dev/null
if docker exec --user 1000 "$prefix-client" curl -fsS --max-time 2 https://1.1.1.1/cdn-cgi/trace >/dev/null 2>&1; then exit 1;fi
# Read the continuously captured ordinary path after the fault window.
sleep 2
count=$(docker exec "$prefix-client" sh -c 'tcpdump -nr /run/vpn/ordinary.pcap 2>/dev/null | wc -l')
if [ "$count" -ne 0 ]; then
  docker exec "$prefix-client" tcpdump -nr /run/vpn/ordinary.pcap
  exit 1
fi
printf 'Ordinary path IPv4 bypass packets: 0; persistent firewall: PASS\n'
