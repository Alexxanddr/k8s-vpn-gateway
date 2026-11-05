#!/usr/bin/env python3
"""Acceptance tests against a preinstalled, dedicated test release; no node access."""
import json
import os
import subprocess
import time
from pathlib import Path

NS = os.environ.get("TEST_NAMESPACE", "vpn-client-test")
GW = os.environ.get("GATEWAY_NAMESPACE", "vpn-gateway-test")
TOOLS = os.environ["TEST_IMAGE"]
FAULTS = os.environ.get("RUN_FAULTS") == "1"
URL = os.environ.get("TEST_URL", "https://1.1.1.1/cdn-cgi/trace")
ARTIFACTS = Path(os.environ.get("ARTIFACTS", "artifacts/cluster"))
ARTIFACTS.mkdir(parents=True, exist_ok=True)


def k(*args, data=None, check=True):
    result = subprocess.run(
        ["env", f"KUBECONFIG={os.environ['KUBECONFIG']}", "kubectl", *args],
        input=json.dumps(data) if data is not None else None,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=65,
    )
    if check and result.returncode:
        raise RuntimeError(result.stderr)
    return result


def obj(*args):
    return json.loads(k(*args, "-o", "json").stdout)


def apply(body, dry=False):
    return k("apply", *( ["--dry-run=server"] if dry else []), "-f", "-", data=body)


def exec_app(name, *args, check=True):
    return k("-n", NS, "exec", name, "-c", "app", "--", *args, check=check)


def guard(name, *args):
    return k("-n", NS, "exec", name, "-c", "vpn-guard", "--", *args)


def gw_exec(container, *args, check=True):
    return k("-n", GW, "exec", "deployment/vpn-gateway", "-c", container, "--", *args, check=check)


def ip(text):
    return next(line[3:] for line in text.splitlines() if line.startswith("ip="))


def curl(name):
    return exec_app(name, "curl", "-fsS", "--max-time", "4", URL, check=False)


def pod(name, selected=True):
    security = {"runAsUser": 1000, "runAsNonRoot": True,
                "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                "seccompProfile": {"type": "RuntimeDefault"}}
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NS,
                     "annotations": {"pass-to-vpn": "true"} if selected else {}},
        "spec": {"automountServiceAccountToken": False,
                 "containers": [{"name": "app", "image": TOOLS,
                                 "command": ["sleep", "86400"], "securityContext": security,
                                 "resources": {"requests": {"cpu": "5m", "memory": "16Mi"},
                                               "limits": {"memory": "96Mi"}}}]},
    }


def ready(name):
    k("-n", NS, "wait", "--for=condition=Ready", f"pod/{name}", "--timeout=60s")


def wait_vpn(name):
    for _ in range(30):
        result = curl(name)
        if result.returncode == 0:
            return ip(result.stdout)
        time.sleep(2)
    raise AssertionError("VPN did not recover")


def drop_observer(name, gateway, cluster):
    # Postrouting observes actual packets after the output guard, excluding only
    # the two explicitly allowed transports; a curl error alone is insufficient.
    rules = f'''add table inet vpn_observe
add chain inet vpn_observe ordinary {{ type filter hook postrouting priority 300; policy accept; }}
add rule inet vpn_observe ordinary oifname "eth0" ip daddr {gateway} udp dport 1194 return
add rule inet vpn_observe ordinary oifname "eth0" ip daddr {cluster} udp dport 53 return
add rule inet vpn_observe ordinary oifname "eth0" ip daddr {cluster} tcp dport 53 return
add rule inet vpn_observe ordinary oifname "eth0" counter
'''
    # Rules contain only validated IPs obtained from cluster resources.
    guard(name, "sh", "-c", "nft -f - <<'RULES'\n" + rules + "RULES\n")


def assert_no_bypass(name):
    rules = json.loads(guard(name, "nft", "-j", "list", "table", "inet", "vpn_observe").stdout)
    counters = [expr["counter"]["packets"] for item in rules["nftables"]
                for expr in item.get("rule", {}).get("expr", []) if "counter" in expr]
    assert counters == [0], f"ordinary-path bypass packets: {counters}"
    (ARTIFACTS / f"{name}-ordinary.json").write_text(json.dumps(rules, indent=2))
    (ARTIFACTS / f"{name}-guard.txt").write_text(guard(name, "nft", "list", "table", "inet", "vpn_guard").stdout)


def assert_no_gateway_bypass():
    text = gw_exec("overlay", "nft", "-j", "list", "table", "inet", "vpn_observe").stdout
    counters = [e["counter"]["packets"] for i in json.loads(text)["nftables"]
                for e in i.get("rule", {}).get("expr", []) if "counter" in e]
    assert counters == [0], f"gateway forwarded outside the VPN: {counters}"
    (ARTIFACTS / "gateway-ordinary.json").write_text(text)


def blocked_window(name, seconds=12):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        assert curl(name).returncode != 0, "unexpected successful egress during fault"
        assert_no_bypass(name)


# Refuse to fault a production release accidentally.
assert NS.endswith("-test") and GW.endswith("-test"), "dedicated *-test namespaces required"
gateway_deploy = obj("-n", GW, "get", "deployment", "vpn-gateway")
assert gateway_deploy["spec"]["replicas"] == 1
config = obj("-n", GW, "get", "deployment", "vpn-admission")
env = {v["name"]: v.get("value", "") for v in config["spec"]["template"]["spec"]["containers"][0]["env"]}
cluster_dns = env["CLUSTER_DNS"]
gateway_ip = obj("-n", GW, "get", "service", "vpn-gateway")["spec"]["clusterIP"]

for name in ["vpn-selected", "vpn-ordinary", "vpn-init", "vpn-inherited"]:
    k("-n", NS, "delete", "pod", name, "--ignore-not-found", "--wait=true")
apply(pod("vpn-selected"))
apply(pod("vpn-ordinary", False))
ready("vpn-selected")
ready("vpn-ordinary")
vpn_ip = wait_vpn("vpn-selected")
plain_ip = ip(curl("vpn-ordinary").stdout)
assert vpn_ip != plain_ip, "VPN and ordinary egress addresses are identical"
print("Selected and unselected IP behavior: PASS", flush=True)

# A user init proves the ordinary path is blocked before that init executes.
p = pod("vpn-init")
p["spec"]["initContainers"] = [{**p["spec"]["containers"][0], "name": "user-init",
    "command": ["sh", "-c", 'if dig @"$1" example.com +tries=1 +time=1 >/dev/null 2>&1; then exit 1; fi; if curl --interface eth0 -fsS --max-time 2 "$2" >/dev/null 2>&1; then exit 1; fi', "init-test", cluster_dns, URL]}]
apply(p)
ready("vpn-init")
assert obj("-n", NS, "get", "pod", "vpn-init")["spec"]["initContainers"][0]["name"] == "vpn-guard"
init_rules = json.loads(guard("vpn-init", "nft", "-j", "list", "chain", "inet", "vpn_guard", "output").stdout)
last_rule = [r["rule"] for r in init_rules["nftables"] if "rule" in r][-1]
assert last_rule["expr"][0]["counter"]["packets"] >= 1, "user init did not exercise the ordinary drop rule"

bad = pod("vpn-bad-capability")
bad["spec"]["containers"][0]["securityContext"]["capabilities"]["add"] = ["NET_ADMIN"]
assert k("create", "--dry-run=server", "-f", "-", data=bad, check=False).returncode != 0
legacy = obj("-n", NS, "get", "replicasets", "-l", "test=legacy-vpn-owner")["items"]
if legacy:
    old = legacy[0]["metadata"]
    old_pod = pod("vpn-legacy-dry", False)
    old_pod["metadata"]["ownerReferences"] = [{"apiVersion": "apps/v1", "kind": "ReplicaSet",
        "name": old["name"], "uid": old["uid"], "controller": True}]
    patched = json.loads(k("create", "--dry-run=server", "-f", "-", "-o", "json", data=old_pod).stdout)
    assert patched["spec"]["initContainers"][0]["name"] == "vpn-guard"
    print("Legacy Deployment -> ReplicaSet owner lookup: PASS", flush=True)

# Deployment metadata travels through a real ReplicaSet, with no owner API lookup.
p = pod("unused")
deployment = {"apiVersion": "apps/v1", "kind": "Deployment",
    "metadata": {"name": "vpn-inherited", "namespace": NS, "annotations": {"pass-to-vpn": "true"}},
    "spec": {"replicas": 1, "selector": {"matchLabels": {"test": "inherited"}},
             "template": {"metadata": {"labels": {"test": "inherited"}}, "spec": p["spec"]}}}
apply(deployment)
k("-n", NS, "rollout", "status", "deployment/vpn-inherited", "--timeout=60s")
child = obj("-n", NS, "get", "pods", "-l", "test=inherited")["items"][0]
assert child["metadata"]["annotations"]["vpn-gateway.io/injected"] == "v1"
assert child["metadata"]["ownerReferences"][0]["kind"] == "ReplicaSet"
print("User init ordering and synchronous Deployment inheritance: PASS", flush=True)

drop_observer("vpn-selected", gateway_ip, cluster_dns)
gateway_observer = '''add table inet vpn_observe
flush table inet vpn_observe
add chain inet vpn_observe ordinary { type filter hook postrouting priority 300; policy accept; }
add rule inet vpn_observe ordinary iifname "vpnlink" oifname != "tun0" counter
'''
gw_exec("overlay", "sh", "-c", "nft -f - <<'RULES'\n" + gateway_observer + "RULES\n")
assert_no_gateway_bypass()
assert exec_app("vpn-selected", "dig", "@127.0.0.1", "example.com", "+short", "+tries=1", "+time=4").stdout.strip()
assert exec_app("vpn-selected", "dig", "@127.0.0.1", "example.com", "+tcp", "+short", "+tries=1", "+time=4").stdout.strip()
assert "10." in exec_app("vpn-selected", "dig", "@127.0.0.1", "kubernetes.default.svc.cluster.local", "+short").stdout
assert exec_app("vpn-selected", "dig", f"@{cluster_dns}", "example.com", "+short", "+tries=1", "+time=1", check=False).returncode != 0
assert exec_app("vpn-selected", "curl", "--interface", "eth0", "-fsS", "--max-time", "2", URL, check=False).returncode != 0
# Give IPv6 a candidate ordinary route, so the IPv6 test exercises a real guard drop.
guard("vpn-selected", "ip", "-6", "addr", "add", "2001:db8::2/64", "dev", "eth0", "nodad")
guard("vpn-selected", "ip", "-6", "route", "add", "default", "dev", "eth0")
assert exec_app("vpn-selected", "curl", "-g", "-6", "-fsS", "--max-time", "2", "http://[2606:4700:4700::1111]", check=False).returncode != 0
assert_no_bypass("vpn-selected")
print("TCP, UDP/TCP DNS, split DNS, direct DNS/interface and IPv6 blocks: PASS", flush=True)

# Keep a real HTTP connection across fault injection; curl reuses connections.
urls = [URL] * 120
stream = subprocess.Popen(["env", f"KUBECONFIG={os.environ['KUBECONFIG']}", "kubectl", "-n", NS,
    "exec", "vpn-selected", "-c", "app", "--", "curl", "-sS", "--rate", "1/s", "--max-time", "2",
    "--write-out", "\nconnection-reuse=%{num_connects}\n", *urls],
    stdout=(ARTIFACTS / "continuous-traffic.log").open("w"), stderr=subprocess.DEVNULL)
try:
    time.sleep(4)
    if FAULTS:
        # Controller outage: protected traffic continues; new selected Pods fail closed.
        k("-n", GW, "scale", "deployment/vpn-admission", "--replicas=0")
        time.sleep(3)
        assert curl("vpn-selected").returncode == 0
        denied = pod("vpn-denied")
        result = k("create", "--dry-run=server", "-f", "-", data=denied, check=False)
        assert result.returncode != 0, "unprotected admission succeeded"
        ordinary = pod("vpn-ordinary-dry", False)
        apply(ordinary, dry=True)
        k("-n", GW, "scale", "deployment/vpn-admission", "--replicas=1")
        k("-n", GW, "rollout", "status", "deployment/vpn-admission", "--timeout=60s")
        print("Controller outage and selective fail-closed admission: PASS", flush=True)
        # Blackhole provider UDP only inside the gateway; overlay replies remain allowed.
        fault = "add table inet vpn_fault\nadd chain inet vpn_fault output { type filter hook output priority 20; policy accept; }\nadd rule inet vpn_fault output meta l4proto udp udp sport != 1194 counter drop\n"
        gw_exec("overlay", "sh", "-c", "nft -f - <<'RULES'\n" + fault + "RULES\n")
        try:
            blocked_window("vpn-selected", 6)
            print("Provider UDP blackhole, ordinary counters zero: PASS", flush=True)
            gw_exec("overlay", "ip", "link", "set", "tun0", "down")
            blocked_window("vpn-selected", 6)
            print("VPN interface down, ordinary counters zero: PASS", flush=True)
            gw_exec("gluetun", "sh", "-c", "kill -TERM 1", check=False)
            blocked_window("vpn-selected", 8)
            print("Gluetun process termination under provider fault, ordinary counters zero: PASS", flush=True)
        finally:
            gw_exec("overlay", "nft", "delete", "table", "inet", "vpn_fault", check=False)
        assert wait_vpn("vpn-selected") != plain_ip
        # Native sidecar restart must leave the dataplane guard in place.
        guard("vpn-selected", "sh", "-c", "kill -TERM 1")
        for _ in range(20):
            time.sleep(1)
            try:
                assert_no_bypass("vpn-selected")
                break
            except RuntimeError:
                continue
        else:
            raise AssertionError("network sidecar did not restart")
        assert wait_vpn("vpn-selected") != plain_ip
        print("Client network process termination/recovery, ordinary counters zero: PASS", flush=True)
        assert_no_gateway_bypass()
        # Destroy only this test gateway; deletion changes its Pod IP on common CNIs.
        old = obj("-n", GW, "get", "pods", "-l", "app=vpn-gateway")["items"][0]
        k("-n", GW, "scale", "deployment/vpn-gateway", "--replicas=0")
        k("-n", GW, "wait", "--for=delete", "pod/" + old["metadata"]["name"], "--timeout=60s")
        blocked_window("vpn-selected")
        k("-n", GW, "scale", "deployment/vpn-gateway", "--replicas=1")
        k("-n", GW, "rollout", "status", "deployment/vpn-gateway", "--timeout=60s")
        assert wait_vpn("vpn-selected") != plain_ip
        new = obj("-n", GW, "get", "pods", "-l", "app=vpn-gateway")["items"][0]
        print("Gateway replacement/recovery: PASS; Pod IP changed:", old["status"]["podIP"] != new["status"]["podIP"], flush=True)
    else:
        print("Fault injection PREPARED, NOT RUN (set RUN_FAULTS=1 on a dedicated release)", flush=True)
finally:
    # Restore only the two dedicated test Deployments, even if an assertion fails.
    if FAULTS:
        k("-n", GW, "scale", "deployment/vpn-admission", "deployment/vpn-gateway", "--replicas=1", check=False)
    stream.terminate()
    stream.wait(timeout=5)

assert_no_bypass("vpn-selected")
continuous=(ARTIFACTS / "continuous-traffic.log").read_text()
assert "connection-reuse=0" in continuous, "no pre-existing HTTP connection was observed"
observed=[line[3:] for line in continuous.splitlines() if line.startswith("ip=")]
assert all(value != plain_ip for value in observed), "ordinary source address observed during faults"
nodes = obj("get", "nodes")["items"]
client_node = obj("-n", NS, "get", "pod", "vpn-selected")["spec"]["nodeName"]
gateway_node = obj("-n", GW, "get", "pods", "-l", "app=vpn-gateway")["items"][0]["spec"]["nodeName"]
print("Cross-node:", "PASS" if client_node != gateway_node else "NOT DEMONSTRATED (schedule client/gateway on different nodes)", flush=True)
assert len(nodes) > 0
print("Ordinary path bypass counters: zero. See ignored artifacts/cluster for evidence.", flush=True)
