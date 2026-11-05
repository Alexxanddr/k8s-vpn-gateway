package admission

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"

	av1 "k8s.io/api/admission/v1"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const Annotation = "pass-to-vpn"
const Selection = "vpn-gateway.io/selection"
const Injected = "vpn-gateway.io/injected"

// Config contains no VPN credentials. Transport credentials stay in pod Secrets.
type Config struct {
	OwnerSelection                                        func(string, meta.OwnerReference) (bool, error)
	Image, GatewayIP, ClusterDNS, PublicDNS, ClientSecret string
	Namespaces                                            []string
	AutoEnroll                                            bool
	GatewayNamespace                                      string
}

type object struct {
	Metadata meta.ObjectMeta `json:"metadata"`
	Spec     struct {
		core.PodSpec `json:",inline"`
		Template     struct {
			Metadata meta.ObjectMeta `json:"metadata"`
			Spec     core.PodSpec    `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
}
type patch struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

func annotation(m map[string]string, k string) (string, bool, error) {
	v, ok := m[k]
	if ok && v != "true" && v != "false" {
		return "", ok, fmt.Errorf("%s must be the string true or false", k)
	}
	return v, ok, nil
}
func selected(m map[string]string) (bool, error) {
	v, ok, err := annotation(m, Annotation)
	if err != nil {
		return false, err
	}
	if !ok {
		v, _, err = annotation(m, Selection)
	}
	return v == "true", err
}

func (c Config) sidecar() core.Container {
	yes, no, uid := true, false, int64(0)
	always := core.ContainerRestartPolicyAlways
	return core.Container{
		Name: "vpn-guard", Image: c.Image, ImagePullPolicy: core.PullIfNotPresent,
		Args: []string{"client"}, RestartPolicy: &always,
		Env: []core.EnvVar{{Name: "GATEWAY_IP", Value: c.GatewayIP}, {Name: "CLUSTER_DNS", Value: c.ClusterDNS}, {Name: "PUBLIC_DNS", Value: c.PublicDNS}},
		SecurityContext: &core.SecurityContext{RunAsUser: &uid, RunAsNonRoot: &no, AllowPrivilegeEscalation: &no, ReadOnlyRootFilesystem: &yes,
			Capabilities:   &core.Capabilities{Drop: []core.Capability{"ALL"}, Add: []core.Capability{"NET_ADMIN", "NET_BIND_SERVICE"}},
			SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}},
		VolumeMounts: []core.VolumeMount{{Name: "vpn-tun", MountPath: "/dev/net/tun"}, {Name: "vpn-transport", MountPath: "/transport", ReadOnly: true}, {Name: "vpn-run", MountPath: "/run/vpn"}},
		StartupProbe: &core.Probe{ProbeHandler: core.ProbeHandler{Exec: &core.ExecAction{Command: []string{"test", "-f", "/run/vpn/ready"}}}, PeriodSeconds: 1, FailureThreshold: 120},
		Resources:    core.ResourceRequirements{Requests: core.ResourceList{core.ResourceCPU: resource.MustParse("10m"), core.ResourceMemory: resource.MustParse("32Mi")}, Limits: core.ResourceList{core.ResourceMemory: resource.MustParse("128Mi")}},
	}
}
func (c Config) volumes() []core.Volume {
	char := core.HostPathCharDev
	mode := int32(0400)
	return []core.Volume{
		{Name: "vpn-tun", VolumeSource: core.VolumeSource{HostPath: &core.HostPathVolumeSource{Path: "/dev/net/tun", Type: &char}}},
		{Name: "vpn-transport", VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: c.ClientSecret, DefaultMode: &mode}}},
		{Name: "vpn-run", VolumeSource: core.VolumeSource{EmptyDir: &core.EmptyDirVolumeSource{Medium: core.StorageMediumMemory}}},
	}
}
func appSecurity(s core.PodSpec, containers []core.Container) error {
	for _, c := range containers {
		sc := c.SecurityContext
		if sc == nil {
			return fmt.Errorf("%s: explicit container securityContext is required", c.Name)
		}
		uid := sc.RunAsUser
		if uid == nil && s.SecurityContext != nil {
			uid = s.SecurityContext.RunAsUser
		}
		if uid == nil || *uid <= 0 {
			return fmt.Errorf("%s: explicit nonzero runAsUser required", c.Name)
		}
		if sc.Privileged != nil && *sc.Privileged || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
			return fmt.Errorf("%s: privileged/escalation forbidden", c.Name)
		}
		if sc.ProcMount != nil && *sc.ProcMount != core.DefaultProcMount {
			return fmt.Errorf("%s: unmasked proc forbidden", c.Name)
		}
		if sc.Capabilities == nil || len(sc.Capabilities.Add) != 0 || !reflect.DeepEqual(sc.Capabilities.Drop, []core.Capability{"ALL"}) {
			return fmt.Errorf("%s: capabilities must drop ALL and add none", c.Name)
		}
		for _, m := range c.VolumeMounts {
			if strings.HasPrefix(m.Name, "vpn-") {
				return fmt.Errorf("%s: reserved volume", c.Name)
			}
		}
		for _, probe := range []*core.Probe{c.StartupProbe, c.ReadinessProbe, c.LivenessProbe} {
			if probe != nil && probe.Exec == nil {
				return fmt.Errorf("%s: protected applications require exec probes", c.Name)
			}
		}
		for _, p := range c.Ports {
			if p.HostPort != 0 {
				return fmt.Errorf("host ports forbidden")
			}
		}
		for _, dev := range c.VolumeDevices {
			if dev.DevicePath != "" {
				return fmt.Errorf("raw block devices forbidden")
			}
		}
	}
	return nil
}
func validate(s core.PodSpec, annotations map[string]string) error {
	for _, key := range []string{"k8s.v1.cni.cncf.io/networks", "v1.multus-cni.io/default-network"} {
		if _, present := annotations[key]; present {
			return fmt.Errorf("alternate CNI attachments forbidden")
		}
	}
	if s.RuntimeClassName != nil || len(s.ResourceClaims) != 0 {
		return fmt.Errorf("custom runtime classes and resource claims forbidden")
	}
	if s.HostNetwork || s.HostPID || s.HostIPC || s.ShareProcessNamespace != nil && *s.ShareProcessNamespace {
		return fmt.Errorf("host/shared namespaces forbidden")
	}
	if s.HostUsers != nil && !*s.HostUsers {
		return fmt.Errorf("user namespaces unsupported")
	}
	if s.OS != nil && s.OS.Name != core.Linux {
		return fmt.Errorf("Linux required")
	}
	if s.SecurityContext != nil && len(s.SecurityContext.Sysctls) != 0 {
		return fmt.Errorf("custom sysctls forbidden")
	}
	for _, v := range s.Volumes {
		if v.HostPath != nil || v.CSI != nil {
			return fmt.Errorf("user hostPath/CSI volumes forbidden")
		}
		if strings.HasPrefix(v.Name, "vpn-") {
			return fmt.Errorf("reserved volume %s", v.Name)
		}
	}
	all := append(append([]core.Container{}, s.Containers...), s.InitContainers...)
	for _, ec := range s.EphemeralContainers {
		all = append(all, core.Container{Name: ec.Name, SecurityContext: ec.SecurityContext, VolumeMounts: ec.VolumeMounts, VolumeDevices: ec.VolumeDevices, Ports: ec.Ports})
	}
	for _, container := range all {
		if strings.HasPrefix(container.Name, "vpn-") {
			return fmt.Errorf("reserved container name")
		}
	}
	return appSecurity(s, all)
}

func (c Config) dns(namespace string) *core.PodDNSConfig {
	return &core.PodDNSConfig{Nameservers: []string{"127.0.0.1"}, Searches: []string{namespace + ".svc.cluster.local", "svc.cluster.local", "cluster.local"}, Options: []core.PodDNSConfigOption{{Name: "ndots", Value: ptr("1")}}}
}
func ptr[T any](v T) *T { return &v }

func (c Config) autoNamespace(namespace string) bool {
	return c.AutoEnroll && namespace != c.GatewayNamespace && namespace != "default" && namespace != "flux-system" && !strings.HasPrefix(namespace, "kube-")
}

func (c Config) Mutate(r *av1.AdmissionRequest) ([]patch, error) {
	var o object
	if err := json.Unmarshal(r.Object.Raw, &o); err != nil {
		return nil, err
	}
	a := o.Metadata.Annotations
	if a == nil {
		a = map[string]string{}
	}
	if r.Kind.Kind == "Deployment" {
		// Only this private marker is inherited; an explicit template annotation always wins.
		v, _, err := annotation(a, Annotation)
		if err != nil {
			return nil, err
		}
		t := map[string]string{}
		for key, value := range o.Spec.Template.Metadata.Annotations {
			t[key] = value
		}
		if tv, ok, err := annotation(t, Annotation); err != nil {
			return nil, err
		} else if ok {
			v = tv
		}
		if v == "true" {
			if c.AutoEnroll && !c.autoNamespace(r.Namespace) && !slices.Contains(c.Namespaces, r.Namespace) {
				return nil, fmt.Errorf("VPN enrollment is unavailable in this namespace")
			}
			if err := validate(o.Spec.Template.Spec, t); err != nil {
				return nil, err
			}
		}
		if v == "" {
			delete(t, Selection)
		} else {
			t[Selection] = v
		}
		if reflect.DeepEqual(t, o.Spec.Template.Metadata.Annotations) || len(t) == 0 && len(o.Spec.Template.Metadata.Annotations) == 0 {
			return nil, nil
		}
		return []patch{{"add", "/spec/template/metadata/annotations", t}}, nil
	}
	if r.Kind.Kind != "Pod" {
		return nil, fmt.Errorf("unsupported kind")
	}
	// Legacy ReplicaSets may predate template propagation. Resolve their owner
	// synchronously while admitting a new Pod, never after application startup.
	if r.Operation == av1.Create && a[Annotation] == "" && a[Selection] == "" {
		if slices.Contains(c.Namespaces, r.Namespace) {
			for _, owner := range o.Metadata.OwnerReferences {
				if owner.Kind == "ReplicaSet" && owner.Controller != nil && *owner.Controller {
					if c.OwnerSelection == nil {
						return nil, fmt.Errorf("owner lookup unavailable")
					}
					enabled, err := c.OwnerSelection(r.Namespace, owner)
					if err != nil {
						return nil, err
					}
					if enabled {
						a[Selection] = "true"
					}
				}
			}
		}
	}
	enabled, err := selected(a)
	if err != nil {
		return nil, err
	}
	if r.Operation == av1.Update {
		var old object
		if err := json.Unmarshal(r.OldObject.Raw, &old); err != nil {
			return nil, err
		}
		was, err := selected(old.Metadata.Annotations)
		if err != nil {
			return nil, err
		}
		if enabled != was {
			return nil, fmt.Errorf("selection cannot change on an existing Pod; roll out its owner")
		}
	}
	if enabled && !c.autoNamespace(r.Namespace) && !slices.Contains(c.Namespaces, r.Namespace) {
		return nil, fmt.Errorf("VPN enrollment is unavailable in this namespace")
	}
	if !enabled {
		if a[Injected] != "" {
			return nil, fmt.Errorf("cannot remove protection from a running Pod")
		}
		return nil, nil
	}
	s := o.Spec.PodSpec
	hasGuard := len(s.InitContainers) > 0 && s.InitContainers[0].Name == "vpn-guard"
	if hasGuard {
		if c.autoNamespace(r.Namespace) && !slices.Contains(c.Namespaces, r.Namespace) && o.Metadata.Labels[Injected] != "v1" {
			return nil, fmt.Errorf("automatic enrollment label is missing")
		}
		// Compare trusted fields rather than trusting the annotation as proof of injection.
		if a[Injected] != "v1" || !sameContainer(s.InitContainers[0], c.sidecar()) || len(s.Volumes) < 3 || !reflect.DeepEqual(s.Volumes[len(s.Volumes)-3:], c.volumes()) || s.DNSPolicy != core.DNSNone || !reflect.DeepEqual(s.DNSConfig, c.dns(r.Namespace)) {
			return nil, fmt.Errorf("injected protection was modified")
		}
		s.InitContainers = s.InitContainers[1:]
		s.Volumes = s.Volumes[:len(s.Volumes)-3]
		return nil, validate(s, a)
	}
	if r.Operation != av1.Create || a[Injected] != "" {
		return nil, fmt.Errorf("missing protection; create a new Pod through admission")
	}
	if err := validate(s, a); err != nil {
		return nil, err
	}
	a[Injected] = "v1"
	changes := []patch{
		{"add", "/metadata/annotations", a},
		{"add", "/spec/initContainers", append([]core.Container{c.sidecar()}, s.InitContainers...)},
		{"add", "/spec/volumes", append(s.Volumes, c.volumes()...)},
		{"add", "/spec/dnsPolicy", core.DNSNone},
		{"add", "/spec/dnsConfig", c.dns(r.Namespace)},
	}
	if c.autoNamespace(r.Namespace) {
		labels := o.Metadata.Labels
		if labels == nil {
			labels = map[string]string{}
		}
		labels[Injected] = "v1"
		changes = append(changes, patch{"add", "/metadata/labels", labels})
	}
	return changes, nil
}

// Kubernetes defaults these fields between mutation and validation/reinvocation.
func sameContainer(actual, expected core.Container) bool {
	actual.TerminationMessagePath = ""
	actual.TerminationMessagePolicy = ""
	if actual.StartupProbe != nil {
		p := actual.StartupProbe.DeepCopy()
		p.TimeoutSeconds = 0
		p.SuccessThreshold = 0
		actual.StartupProbe = p
	}
	return reflect.DeepEqual(actual, expected)
}

func (c Config) Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var review av1.AdmissionReview
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&review); err != nil || review.Request == nil {
		http.Error(w, "invalid admission review", 400)
		return
	}
	response := &av1.AdmissionResponse{UID: review.Request.UID, Allowed: true}
	changes, err := c.Mutate(review.Request)
	if err != nil {
		response.Allowed = false
		response.Result = &meta.Status{Message: err.Error()}
		log.Printf("admission denied kind=%s namespace=%s reason=%v", review.Request.Kind.Kind, review.Request.Namespace, err)
	} else if len(changes) > 0 {
		response.Patch, _ = json.Marshal(changes)
		v := av1.PatchTypeJSONPatch
		response.PatchType = &v
	}
	review.Request = nil
	review.Response = response
	_ = json.NewEncoder(w).Encode(review)
}

func serviceIP(namespace, name string) (string, error) {
	var svc core.Service
	err := apiRequest("GET", "/api/v1/namespaces/"+namespace+"/services/"+name, nil, &svc)
	return svc.Spec.ClusterIP, err
}

func Serve() error {
	c := Config{Image: os.Getenv("CLIENT_IMAGE"), ClusterDNS: os.Getenv("CLUSTER_DNS"), PublicDNS: os.Getenv("PUBLIC_DNS"), ClientSecret: os.Getenv("CLIENT_SECRET"), Namespaces: strings.Split(os.Getenv("CLIENT_NAMESPACES"), ","), OwnerSelection: ownerSelection, AutoEnroll: os.Getenv("AUTO_ENROLL") == "true", GatewayNamespace: os.Getenv("POD_NAMESPACE")}
	var err error
	c.GatewayIP, err = serviceIP(os.Getenv("POD_NAMESPACE"), "vpn-gateway")
	if err != nil {
		return err
	}
	for _, ip := range []string{c.GatewayIP, c.ClusterDNS, c.PublicDNS} {
		a, err := netip.ParseAddr(ip)
		if err != nil || !a.Is4() {
			return fmt.Errorf("IPv4 configuration required")
		}
	}
	go c.syncCertificates()
	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", c.Handler)
	mux.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		// Validation recomputes the expected state, closing races with other mutators.
		var review av1.AdmissionReview
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
		if err != nil {
			http.Error(w, "invalid body", 400)
			return
		}
		if json.Unmarshal(b, &review) != nil || review.Request == nil {
			http.Error(w, "invalid review", 400)
			return
		}
		changes, err := c.Mutate(review.Request)
		response := &av1.AdmissionResponse{UID: review.Request.UID, Allowed: err == nil && len(changes) == 0}
		if !response.Allowed {
			response.Result = &meta.Status{Message: fmt.Sprintf("protection validation failed: %v (pending patches: %d)", err, len(changes))}
		}
		review.Request = nil
		review.Response = response
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(review)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	server := http.Server{Addr: ":8443", Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := tls.LoadX509KeyPair("/tls/tls.crt", "/tls/tls.key")
		return &cert, err
	}}}
	return server.ListenAndServeTLS("", "")
}
