# Security model

The intended adversary is an application process that attempts direct IPv4,
IPv6 or DNS egress, including during network failures. The application does not
control its Pod spec after admission, its node, the container runtime, cluster
administrators, cert-manager, admission configuration, or the network sidecar
image. This is not isolation from compromised nodes or cluster administrators.

## Enforcement

The first restartable init container installs a single atomic nftables transaction
before writing its startup-probe marker. No user init container or application
process starts before that marker. On sidecar restart, existing rules remain
installed; flushing/replacing rules is one nftables transaction. On sidecar death,
ordinary traffic remains blocked even if routes vanish. Native sidecars terminate
after application containers during normal shutdown.

The client drops IPv6 and allows ordinary IPv4 output only from UID 0 for the
transport endpoint/port and for the split resolver's DNS endpoint/port.
With optional cluster ingress, the guard also permits TCP replies on connections
whose initial SYN arrived from a configured Pod CIDR or the local node on a
declared application port. The app cannot set the conntrack mark or use this
rule to open new underlay connections. Applications
must have a fixed nonzero UID, drop ALL capabilities, and disable privilege
escalation. They cannot use root-owned socket exceptions, alter routes/firewalls,
create raw packets, enter the network sidecar's process namespace, or mount its
credential volumes. Setuid binaries cannot gain privilege. Validation rejects
host/shared namespaces, privileged containers, added capabilities, unsafe proc,
host paths, CSI devices, raw block device access, device claims, alternate CNI
attachments and custom RuntimeClasses. Startup allows only `eth0` and `lo` as active interfaces and reserves both
tunnel names, so an existing device cannot impersonate a project tunnel. The trusted TUN host device
and NET_ADMIN are limited to injected components.

The gateway has a separate FORWARD guard installed before either tunnel or
Gluetun starts. It does not depend on Gluetun's OUTPUT chain, readiness, controller
polling or a NetworkPolicy implementation. Provider bootstrap traffic is generated
by Gluetun itself; client FORWARD has no equivalent endpoint exception. If an
upstream release ever flushes all nftables tables, that release is incompatible
until this independent guard is preserved and the failure tests pass.

## Admission boundary

Both webhooks use failurePolicy Fail and CEL match conditions for selected
Deployments, selected Pods and previously selected objects. With automatic
enrollment, annotated objects are matched across namespaces. The gateway,
`default`, `flux-system`, and namespaces starting with `kube-` deny automatic
enrollment. Kubernetes Pod Security still evaluates the injected guard.

Explicitly enrolled namespaces also match new ReplicaSet-owned Pods for legacy
owner lookup. Those Pod creates fail closed if owner lookup is unavailable.
Automatic enrollment in other namespaces depends on selection being present in
the Pod or propagated from a Deployment update. Explicit `"false"` values pass
through validation. Confirm the guard was injected before relying on protection.

Template annotations override Deployment metadata; direct Pod annotations override
template-inherited selection. This interface intentionally permits owners to opt
out with `"false"`; it is not an organization-wide mandatory VPN policy. Use
separate admission/RBAC controls if users must not choose ordinary egress.

Mutation is idempotent and side-effect free for dry-run. The final validating
webhook recomputes the expected guard, DNS settings, credential/device mounts and
application security. Forged injection markers and incompatible ephemeral
containers are rejected. Other trusted mutating webhooks must preserve selection
and protection. Removing all project webhooks is an administrative bypass for
future Pods and requires the explicit decommission procedure.

## Secrets and certificates

The provider key exists only in an existing gateway Secret. No admission log,
image build, CI job or checked-in example contains it. The transport uses a
separate cert-manager CA; the client certificate is shared across enrolled
namespaces (one trust domain), with independent OpenVPN virtual IP allocation.
Transport credentials do not authenticate distinct applications and there is no
individual-client certificate revocation in this version. Revoking enrollment
requires removing/replacing the transport credentials and recreating workloads.

Admission reads one source client transport Secret. Static enrollment permits
read and update of the named destination Secret in configured namespaces.
Automatic enrollment adds cluster-wide Pod list access and creates the same named
transport Secret on demand for admitted Pods. It requests Pod metadata and
filters by the injection marker. A ValidatingAdmissionPolicy restricts Secret
writes by the admission service account to its transport Secret and prevents
adopting an existing unrelated Secret. The gateway provider Secret and CA signing
Secret are outside its read permissions. Legacy Deployment and ReplicaSet reads
are scoped to explicitly enrolled namespaces.

A namespace operator able to read the client transport Secret can join the shared
transport trust domain. Automatically created transport Secrets remain when Pods
are removed. The controller refreshes a namespace's credentials while there are
selected Pods to serve. During decommissioning, remove those generated Secrets
and rotate transport credentials as needed.
Network components are trusted root processes; a vulnerability in OpenVPN, the DNS
relay or Gluetun can defeat the protection within their own network namespace.

Do not assume NetworkPolicy enforcement merely because policy objects exist.
Policies are additive and other rules may allow egress; this project makes no
NetworkPolicy guarantee. Use an enforcing CNI and validated policy as additional
defense if desired. Node packet captures, endpoints controlled by the tester,
and established-connection fault tests are needed before claiming broader leak
resistance. Consult the verification record for what was actually exercised.
