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
