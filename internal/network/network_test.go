package network

import (
	"strings"
	"testing"
)

func TestSplitDNS(t *testing.T) {
	for name, want := range map[string]bool{"CLUSTER.local.": true, "api.ns.svc.cluster.local": true, "evilcluster.local": false, "cluster.local.attacker.test.": false, "example.org.": false} {
		if got := ClusterName(name); got != want {
			t.Errorf("%s = %v", name, got)
		}
	}
}
func TestKillSwitchHasNoStateBypass(t *testing.T) {
	rules := ClientRules("10.96.0.2", "10.96.0.10")
	output := strings.Split(rules, "add chain inet vpn_guard forward")[0]
	if strings.Contains(output, "established") || !strings.Contains(output, "meta nfproto ipv6 counter drop") || !strings.Contains(output, "meta skuid 0") {
		t.Fatal(output)
	}
	g := GatewayRules()
	if !strings.Contains(g, `iifname "vpnlink" oifname "tun0"`) || !strings.Contains(g, "policy drop") {
		t.Fatal(g)
	}
}
