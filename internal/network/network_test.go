package network

import (
	"github.com/miekg/dns"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSplitDNS(t *testing.T) {
	for name, want := range map[string]bool{"CLUSTER.local.": true, "api.ns.svc.cluster.local": true, "evilcluster.local": false, "cluster.local.attacker.test.": false, "example.org.": false} {
		if got := ClusterName(name); got != want {
			t.Errorf("%s = %v", name, got)
		}
	}
}
func TestKillSwitchHasNoStateBypass(t *testing.T) {
	rules := ClientRules("10.96.0.2", "10.96.0.10", nil, "")
	output := strings.Split(rules, "add chain inet vpn_guard forward")[0]
	if strings.Contains(output, "established") || !strings.Contains(output, "meta nfproto ipv6 counter drop") || !strings.Contains(output, "meta skuid 0") {
		t.Fatal(output)
	}
	g := GatewayRules()
	if !strings.Contains(g, `iifname "vpnlink" oifname "tun0"`) || !strings.Contains(g, "policy drop") {
		t.Fatal(g)
	}
}

func TestDNSRelaySplitAndTCPFallback(t *testing.T) {
	serve := func(answer string, truncate bool) string {
		t.Helper()
		udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			_, isUDP := w.RemoteAddr().(*net.UDPAddr)
			if truncate && isUDP {
				m.Truncated = true
			} else {
				rr, _ := dns.NewRR(r.Question[0].Name + " 60 IN A " + answer)
				m.Answer = []dns.RR{rr}
			}
			_ = w.WriteMsg(m)
		})
		us := &dns.Server{PacketConn: udp, Handler: h}
		ts := &dns.Server{Listener: tcp, Handler: h}
		go func() { _ = us.ActivateAndServe() }()
		go func() { _ = ts.ActivateAndServe() }()
		t.Cleanup(func() { _ = us.Shutdown(); _ = ts.Shutdown(); _ = udp.Close(); _ = tcp.Close() })
		return udp.LocalAddr().String()
	}
	internal := serve("10.96.0.1", false)
	public := serve("1.1.1.1", true)
	relay, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: relay, Handler: DNSHandler(internal, public)}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown(); _ = relay.Close() })
	for name, want := range map[string]string{"kubernetes.default.svc.cluster.local.": "10.96.0.1", "example.com.": "1.1.1.1"} {
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeA)
		m, _, err := (&dns.Client{Timeout: time.Second}).Exchange(q, relay.LocalAddr().String())
		if err != nil || m == nil || len(m.Answer) != 1 {
			t.Fatalf("%s: %v %#v", name, err, m)
		}
		if got := m.Answer[0].(*dns.A).A.String(); got != want {
			t.Fatalf("%s: %s", name, got)
		}
	}
}

func TestIngressRepliesAreScopedToMarkedConnections(t *testing.T) {
	rules := ClientRules("10.96.0.2", "10.96.0.10", []string{"10.244.0.0/16"}, "8000")
	for _, rule := range []string{
		`input iifname "eth0" ip saddr 10.244.0.0/16 tcp dport { 8000 } ct direction original ct state new tcp flags & (fin | syn | rst | ack) == syn ct mark set 0x56504e counter accept`,
		`output oifname "eth0" meta l4proto tcp ct direction reply ct mark 0x56504e counter accept`,
		`output ct direction reply ct mark 0x56504e counter drop`,
	} {
		if !strings.Contains(rules, rule) {
			t.Fatalf("missing scoped rule %s", rule)
		}
	}
}
