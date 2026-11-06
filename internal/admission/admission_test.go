package admission

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	av1 "k8s.io/api/admission/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var config = Config{Image: "vpn:test", GatewayIP: "10.96.0.2", ClusterDNS: "10.96.0.10", PublicDNS: "1.1.1.1", ClientSecret: "transport", Namespaces: []string{"test"}}

func request(kind string, o any) *av1.AdmissionRequest {
	b, _ := json.Marshal(o)
	return &av1.AdmissionRequest{Kind: meta.GroupVersionKind{Kind: kind}, Namespace: "test", Operation: av1.Create, Object: runtime.RawExtension{Raw: b}}
}
func safePod() core.Pod {
	return core.Pod{ObjectMeta: meta.ObjectMeta{Annotations: map[string]string{Annotation: "true"}}, Spec: core.PodSpec{Containers: []core.Container{{Name: "app", Image: "example", SecurityContext: &core.SecurityContext{RunAsUser: ptr(int64(1000)), AllowPrivilegeEscalation: ptr(false), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}}}}}
}
func inject(t *testing.T, p core.Pod) core.Pod {
	t.Helper()
	patches, err := config.Mutate(request("Pod", p))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(p)
	var o map[string]any
	_ = json.Unmarshal(raw, &o)
	for _, patch := range patches {
		path := strings.Split(strings.TrimPrefix(patch.Path, "/"), "/")
		target := o
		for _, key := range path[:len(path)-1] {
			target = target[key].(map[string]any)
		}
		target[path[len(path)-1]] = patch.Value
	}
	raw, _ = json.Marshal(o)
	p = core.Pod{}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestInjectionBeforeUserInitAndIdempotence(t *testing.T) {
	p := safePod()
	p.Spec.InitContainers = append(p.Spec.InitContainers, p.Spec.Containers[0])
	p.Spec.InitContainers[0].Name = "init-app"
	p = inject(t, p)
	if p.Spec.InitContainers[0].Name != "vpn-guard" || p.Spec.InitContainers[0].RestartPolicy == nil {
		t.Fatal("startup ordering lost")
	}
	patches, err := config.Mutate(request("Pod", p))
	if err != nil || len(patches) != 0 {
		t.Fatalf("idempotence: %v %#v", err, patches)
	}
	p.Spec.InitContainers[0].TerminationMessagePath = "/dev/termination-log"
	p.Spec.InitContainers[0].TerminationMessagePolicy = core.TerminationMessageReadFile
	p.Spec.InitContainers[0].StartupProbe.TimeoutSeconds = 1
	p.Spec.InitContainers[0].StartupProbe.SuccessThreshold = 1
	if _, err = config.Mutate(request("Pod", p)); err != nil {
		t.Fatal(err)
	}
}
func TestThreatModel(t *testing.T) {
	tests := map[string]func(*core.Pod){"host network": func(p *core.Pod) { p.Spec.HostNetwork = true }, "root": func(p *core.Pod) { p.Spec.Containers[0].SecurityContext.RunAsUser = ptr(int64(0)) }, "net admin": func(p *core.Pod) {
		p.Spec.Containers[0].SecurityContext.Capabilities.Add = []core.Capability{"NET_ADMIN"}
	}, "privileged": func(p *core.Pod) { p.Spec.Containers[0].SecurityContext.Privileged = ptr(true) }, "host path": func(p *core.Pod) {
		p.Spec.Volumes = []core.Volume{{Name: "host", VolumeSource: core.VolumeSource{HostPath: &core.HostPathVolumeSource{Path: "/"}}}}
	}, "forged marker": func(p *core.Pod) { p.Annotations[Injected] = "v1" }, "bad annotation": func(p *core.Pod) { p.Annotations[Annotation] = "True" }, "shared process": func(p *core.Pod) { p.Spec.ShareProcessNamespace = ptr(true) }}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			p := safePod()
			change(&p)
			if _, err := config.Mutate(request("Pod", p)); err == nil {
				t.Fatal("accepted unsafe Pod")
			}
		})
	}
}
func TestPrecedenceAndDeploymentInheritance(t *testing.T) {
	for _, v := range []string{"true", "false"} {
		o := map[string]any{"metadata": map[string]any{"annotations": map[string]string{Annotation: "true"}}, "spec": map[string]any{"template": map[string]any{"metadata": map[string]any{"annotations": map[string]string{Annotation: v}}}}}
		patches, err := config.Mutate(request("Deployment", o))
		if err != nil {
			t.Fatal(err)
		}
		a := patches[0].Value.(map[string]string)
		if a[Selection] != v {
			t.Fatal(a)
		}
		o["spec"].(map[string]any)["template"].(map[string]any)["metadata"].(map[string]any)["annotations"] = a
		again, err := config.Mutate(request("Deployment", o))
		if err != nil || len(again) != 0 {
			t.Fatalf("deployment not idempotent: %v", err)
		}
	}
	p := safePod()
	p.Annotations[Selection] = "false"
	if _, err := config.Mutate(request("Pod", p)); err != nil {
		t.Fatal(err)
	}
	delete(p.Annotations, Annotation)
	patches, err := config.Mutate(request("Pod", p))
	if err != nil || len(patches) != 0 {
		t.Fatal("inherited false ignored")
	}
}
func TestPodUpdateAndTampering(t *testing.T) {
	p := inject(t, safePod())
	old, _ := json.Marshal(p)
	p.Annotations[Annotation] = "false"
	r := request("Pod", p)
	r.Operation = av1.Update
	r.OldObject.Raw = old
	if _, err := config.Mutate(r); err == nil {
		t.Fatal("allowed hot opt out")
	}
	p = inject(t, safePod())
	p.Spec.InitContainers[0].Env[0].Value = "evil"
	if _, err := config.Mutate(request("Pod", p)); err == nil {
		t.Fatal("allowed guard modification")
	}
	p = inject(t, safePod())
	p.Spec.EphemeralContainers = []core.EphemeralContainer{{EphemeralContainerCommon: core.EphemeralContainerCommon{Name: "debug", SecurityContext: &core.SecurityContext{RunAsUser: ptr(int64(0))}}}}
	if _, err := config.Mutate(request("Pod", p)); err == nil {
		t.Fatal("allowed privileged debugging")
	}
}

func TestLegacyReplicaSetOwnerLookup(t *testing.T) {
	p := safePod()
	p.Annotations = map[string]string{}
	p.OwnerReferences = []meta.OwnerReference{{Kind: "ReplicaSet", Name: "old-rs", UID: "rs-uid", Controller: ptr(true)}}
	c := config
	called := false
	c.OwnerSelection = func(namespace string, owner meta.OwnerReference) (bool, error) { called = true; return true, nil }
	changes, err := c.Mutate(request("Pod", p))
	if err != nil || !called || len(changes) == 0 {
		t.Fatalf("legacy lookup: %v", err)
	}
	a := changes[0].Value.(map[string]string)
	if a[Selection] != "true" {
		t.Fatal(a)
	}
	c.OwnerSelection = func(string, meta.OwnerReference) (bool, error) { return false, fmt.Errorf("API unavailable") }
	if _, err := c.Mutate(request("Pod", p)); err == nil {
		t.Fatal("owner lookup failed open")
	}
	p.Annotations[Annotation] = "false"
	if changes, err := c.Mutate(request("Pod", p)); err != nil || len(changes) != 0 {
		t.Fatal("explicit opt-out did not win")
	}
}

func TestUnsafeNetworkAttachments(t *testing.T) {
	for _, key := range []string{"k8s.v1.cni.cncf.io/networks", "v1.multus-cni.io/default-network"} {
		p := safePod()
		p.Annotations[key] = "extra@vpnlink"
		if _, err := config.Mutate(request("Pod", p)); err == nil {
			t.Fatalf("accepted %s", key)
		}
	}
	p := safePod()
	p.Spec.ResourceClaims = []core.PodResourceClaim{{Name: "network-device"}}
	if _, err := config.Mutate(request("Pod", p)); err == nil {
		t.Fatal("accepted device claim")
	}
}

func TestAutomaticEnrollmentUsesPodNamespace(t *testing.T) {
	c := config
	c.AutoEnroll = true
	c.GatewayNamespace = "vpn-gateway"
	for _, ns := range []string{"app-one", "app-two"} {
		r := request("Pod", safePod())
		r.Namespace = ns
		r.DryRun = ptr(true)
		changes, err := c.Mutate(r)
		if err != nil {
			t.Fatal(err)
		}
		labels := changes[len(changes)-1]
		if labels.Path != "/metadata/labels" || labels.Value.(map[string]string)[Injected] != "v1" {
			t.Fatalf("selected Pod in %s is not discoverable", ns)
		}
		if dns := c.dns(ns); dns.Searches[0] != ns+".svc.cluster.local" {
			t.Fatalf("wrong DNS search namespace: %v", dns.Searches)
		}
	}
	for _, ns := range []string{"default", "kube-system", "flux-system", "vpn-gateway"} {
		r := request("Pod", safePod())
		r.Namespace = ns
		if _, err := c.Mutate(r); err == nil {
			t.Fatalf("selected Pod accepted in reserved namespace %s", ns)
		}
	}
	p := safePod()
	p.Annotations = nil
	r := request("Pod", p)
	r.Namespace = "app-one"
	if changes, err := c.Mutate(r); err != nil || len(changes) != 0 {
		t.Fatalf("unselected Pod changed: %v %v", changes, err)
	}
}

func TestAnnotationOnlyServicePod(t *testing.T) {
	ingress := config
	ingress.ClusterIngressCIDRs = "10.244.0.0/16"
	p := safePod()
	p.Spec.SecurityContext = &core.PodSecurityContext{RunAsUser: ptr(int64(1000))}
	app := &p.Spec.Containers[0]
	app.SecurityContext = nil
	app.Ports = []core.ContainerPort{{Name: "http", ContainerPort: 8000}}
	probe := &core.HTTPGetAction{Path: "/health", Port: intstr.FromString("http")}
	app.ReadinessProbe = &core.Probe{ProbeHandler: core.ProbeHandler{HTTPGet: probe}}

	changes, err := ingress.Mutate(request("Pod", p))
	if err != nil || len(changes) == 0 || changes[0].Path != "/spec/containers/0/securityContext" {
		t.Fatalf("container hardening was not added: %v %#v", err, changes)
	}
	sc := changes[0].Value.(*core.SecurityContext)
	if *sc.AllowPrivilegeEscalation || len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" {
		t.Fatalf("unexpected hardening: %#v", sc)
	}
	for _, change := range changes {
		if change.Path == "/spec/initContainers" {
			guard := change.Value.([]core.Container)[0]
			if guard.Env[3].Value != "10.244.0.0/16" || guard.Env[4].Value != "8000" {
				t.Fatalf("wrong ingress rules: %#v", guard.Env)
			}
		}
	}

	if _, err := config.Mutate(request("Pod", p)); err == nil {
		t.Fatal("allowed a network probe without cluster ingress")
	}
	probe.Host = "example.com"
	if _, err := ingress.Mutate(request("Pod", p)); err == nil {
		t.Fatal("allowed a kubelet probe to a different host")
	}
	probe.Host = ""
	probe.Port = intstr.FromInt(9000)
	if _, err := ingress.Mutate(request("Pod", p)); err == nil {
		t.Fatal("allowed a probe on an undeclared port")
	}
}

func TestInstalledGuardSurvivesAdmissionUpgrade(t *testing.T) {
	p := inject(t, safePod())
	upgraded := config
	upgraded.Image = "vpn:updated"
	update := request("Pod", p)
	update.Operation = av1.Update
	update.OldObject = update.Object
	if _, err := upgraded.Mutate(update); err != nil {
		t.Fatal(err)
	}
	p.Spec.InitContainers[0].Image = "vpn:untrusted"
	update.Object = request("Pod", p).Object
	if _, err := upgraded.Mutate(update); err == nil {
		t.Fatal("allowed existing guard image to change")
	}
}
