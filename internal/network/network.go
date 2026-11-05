// Package network configures only the current pod network namespace.
package network

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

const common = `dev vpnlink
dev-type tun
proto udp4
tun-mtu 1280
mssfix 1240
ca /transport/ca.crt
cert /transport/tls.crt
key /transport/tls.key
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM
ping 5
ping-restart 20
persist-tun
disable-dco
tmp-dir /run/vpn
verb 3
`

func run(name string, args ...string) error {
	c := exec.Command(name, args...)
	b, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, b)
	}
	return nil
}

func nft(rules string) error {
	c := exec.Command("nft", "-f", "-")
	c.Stdin = strings.NewReader(rules)
	b, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("install firewall: %w: %s", err, b)
	}
	return nil
}

func ipv4(name string) (string, error) {
	v := os.Getenv(name)
	a, err := netip.ParseAddr(v)
	if err != nil || !a.Is4() || !a.IsGlobalUnicast() {
		return "", fmt.Errorf("%s must be a unicast IPv4 address", name)
	}
	return a.String(), nil
}

// There is deliberately no established/related OUTPUT bypass on the client.
func ClientRules(gateway, clusterDNS string) string {
	return fmt.Sprintf(`add table inet vpn_guard
flush table inet vpn_guard
add chain inet vpn_guard output { type filter hook output priority 10; policy drop; }
add rule inet vpn_guard output meta nfproto ipv6 counter drop
add rule inet vpn_guard output oifname "lo" counter accept
add rule inet vpn_guard output oifname "vpnlink" counter accept
add rule inet vpn_guard output oifname "eth0" meta skuid 0 ip daddr %s udp dport 1194 counter accept
add rule inet vpn_guard output oifname "eth0" meta skuid 0 ip daddr %s udp dport 53 counter accept
add rule inet vpn_guard output oifname "eth0" meta skuid 0 ip daddr %s tcp dport 53 counter accept
add rule inet vpn_guard output counter drop
add chain inet vpn_guard forward { type filter hook forward priority 10; policy drop; }
add chain inet vpn_guard input { type filter hook input priority 10; policy drop; }
add rule inet vpn_guard input meta nfproto ipv6 counter drop
add rule inet vpn_guard input iifname "lo" accept
add rule inet vpn_guard input iifname "vpnlink" accept
add rule inet vpn_guard input ct state established,related accept
`, gateway, clusterDNS, clusterDNS)
}

func GatewayRules() string {
	return `add table inet vpn_guard
flush table inet vpn_guard
add chain inet vpn_guard forward { type filter hook forward priority 10; policy drop; }
add rule inet vpn_guard forward meta nfproto ipv6 counter drop
add rule inet vpn_guard forward iifname "vpnlink" ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/3 } counter drop
add rule inet vpn_guard forward iifname "vpnlink" oifname "tun0" ip saddr 198.18.0.0/24 counter accept
add rule inet vpn_guard forward iifname "tun0" oifname "vpnlink" ct state established,related counter accept
add rule inet vpn_guard forward counter drop
add chain inet vpn_guard input { type filter hook input priority 10; policy accept; }
add rule inet vpn_guard input iifname "vpnlink" counter drop
add chain inet vpn_guard postrouting { type nat hook postrouting priority 110; policy accept; }
add rule inet vpn_guard postrouting oifname "tun0" ip saddr 198.18.0.0/24 counter masquerade
`
}

// Reserve the tunnel names for interfaces created by trusted processes.
func checkUnderlay() error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	if len(interfaces) != 2 {
		return fmt.Errorf("expected only lo and eth0 before tunnel setup")
	}
	for _, iface := range interfaces {
		if iface.Name != "lo" && iface.Name != "eth0" {
			return fmt.Errorf("unexpected interface before tunnel setup: %s", iface.Name)
		}
	}
	return nil
}

func GatewayGuard() error {
	if err := checkUnderlay(); err != nil {
		return err
	}
	if err := nft(GatewayRules()); err != nil {
		return err
	}
	for path, value := range map[string]string{
		"/proc/sys/net/ipv4/ip_forward":             "1",
		"/proc/sys/net/ipv4/conf/all/rp_filter":     "0",
		"/proc/sys/net/ipv4/conf/default/rp_filter": "0",
	} {
		current, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(current)) != value {
			return fmt.Errorf("namespace prerequisite %s must be %s; refusing to modify host or request privileges", path, value)
		}
	}
	// Gluetun WireGuard policy routing otherwise catches replies to overlay clients.
	return run("ip", "rule", "add", "pref", "50", "to", "198.18.0.0/24", "lookup", "main")
}

// Preserve the CNI route to the transport and the one allowed DNS endpoint.
func localRoute(ip string) error {
	b, err := exec.Command("ip", "-j", "route", "get", ip).Output()
	if err != nil {
		return err
	}
	var routes []struct {
		Gateway string `json:"gateway"`
		Dev     string `json:"dev"`
	}
	if err := json.Unmarshal(b, &routes); err != nil || len(routes) != 1 {
		return fmt.Errorf("cannot determine CNI route")
	}
	r := routes[0]
	if r.Dev == "vpnlink" {
		return fmt.Errorf("missing pinned CNI route")
	}
	args := []string{"route", "replace", ip + "/32"}
	if r.Gateway != "" {
		args = append(args, "via", r.Gateway)
	}
	args = append(args, "dev", r.Dev)
	return run("ip", args...)
}

func ClusterName(name string) bool {
	s := strings.ToLower(dns.Fqdn(name))
	return s == "cluster.local." || strings.HasSuffix(s, ".cluster.local.")
}

func DNSHandler(cluster, public string) dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		fail := func() { m := new(dns.Msg); m.SetRcode(r, dns.RcodeServerFailure); _ = w.WriteMsg(m) }
		if len(r.Question) != 1 {
			fail()
			return
		}
		upstream := public
		if ClusterName(r.Question[0].Name) {
			upstream = cluster
		}
		protocol := "udp"
		if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
			protocol = "tcp"
		}
		c := &dns.Client{Net: protocol, Timeout: 3 * time.Second}
		m, _, err := c.Exchange(r, upstream)
		if err == nil && m.Truncated && protocol == "udp" {
			c.Net = "tcp"
			m, _, err = c.Exchange(r, upstream)
		}
		if err != nil {
			fail()
			return
		}
		_ = w.WriteMsg(m)
	})
}

func Client() error {
	// Remove stale startup state before any potentially failing operation.
	_ = os.Remove("/run/vpn/ready")
	if err := checkUnderlay(); err != nil {
		return err
	}
	gateway, err := ipv4("GATEWAY_IP")
	if err != nil {
		return err
	}
	cluster, err := ipv4("CLUSTER_DNS")
	if err != nil {
		return err
	}
	public, err := ipv4("PUBLIC_DNS")
	if err != nil {
		return err
	}
	if err := nft(ClientRules(gateway, cluster)); err != nil {
		return err
	}
	for _, ip := range []string{gateway, cluster} {
		if err := localRoute(ip); err != nil {
			return err
		}
	}
	handler := DNSHandler(net.JoinHostPort(cluster, "53"), net.JoinHostPort(public, "53"))
	udp, err := net.ListenPacket("udp4", "127.0.0.1:53")
	if err != nil {
		return err
	}
	tcp, err := net.Listen("tcp4", "127.0.0.1:53")
	if err != nil {
		udp.Close()
		return err
	}
	failures := make(chan error, 2)
	go func() { failures <- (&dns.Server{PacketConn: udp, Handler: handler}).ActivateAndServe() }()
	go func() { failures <- (&dns.Server{Listener: tcp, Handler: handler}).ActivateAndServe() }()
	config := common + fmt.Sprintf(`client
remote %s 1194
nobind
remote-cert-tls server
verify-x509-name vpn-gateway name
route-nopull
redirect-gateway def1 local
`, gateway)
	if err := os.WriteFile("/run/vpn/openvpn.conf", []byte(config), 0600); err != nil {
		return err
	}
	if err := os.WriteFile("/run/vpn/ready", []byte("firewall installed; DNS bound\n"), 0600); err != nil {
		return err
	}
	go func() { log.Fatal(<-failures) }()
	return openvpn()
}

func Overlay() error {
	config := common + `server 198.18.0.0 255.255.255.0
topology subnet
port 1194
remote-cert-tls client
dh none
duplicate-cn
max-clients 200
status /run/vpn/status 10
status-version 3
`
	if err := os.WriteFile("/run/vpn/openvpn.conf", []byte(config), 0600); err != nil {
		return err
	}
	return openvpn()
}

func certificateHash() ([32]byte, error) {
	var data []byte
	for _, name := range []string{"ca.crt", "tls.crt", "tls.key"} {
		b, err := os.ReadFile("/transport/" + name)
		if err != nil {
			return [32]byte{}, err
		}
		data = append(data, b...)
	}
	return sha256.Sum256(data), nil
}

// Reload projected certificates without touching the persistent firewall.
func openvpn() error {
	for {
		hash, err := certificateHash()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithCancel(context.Background())
		cmd := exec.CommandContext(ctx, "openvpn", "--config", "/run/vpn/openvpn.conf")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			cancel()
			return err
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		tick := time.NewTicker(10 * time.Second)
		rotated := false
		for !rotated {
			select {
			case err := <-done:
				tick.Stop()
				cancel()
				return fmt.Errorf("openvpn stopped: %v", err)
			case <-tick.C:
				next, err := certificateHash()
				if err == nil && next != hash {
					rotated = true
				}
			}
		}
		tick.Stop()
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			cancel()
			<-done
		}
		cancel()
		log.Print("transport certificates rotated; reconnecting")
	}
}
