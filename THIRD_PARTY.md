# Third-party software

This project's Go source is MIT licensed. No source code from the reference
projects was copied. The references informed the design:

| Component | Role | License / source |
| --- | --- | --- |
| Gluetun | Shared provider VPN container | [MIT](https://github.com/passteque/gluetun/blob/master/LICENSE) |
| pod-gateway | Architectural reference (VXLAN and DHCP alternative) | [Upstream license](https://github.com/angelnu/pod-gateway/blob/main/LICENSE) |
| OpenVPN | Standard TLS authenticated IP transport | [GPL-2.0 with OpenSSL exception](https://github.com/OpenVPN/openvpn/blob/master/COPYRIGHT.GPL) |
| miekg/dns | DNS protocol implementation | [BSD-3-Clause](https://github.com/miekg/dns/blob/master/LICENSE) |
| Kubernetes API types | Admission and Pod types | [Apache-2.0](https://github.com/kubernetes/api/blob/master/LICENSE) |
| Alpine packages | Runtime utilities and libraries | [Package license metadata](https://pkgs.alpinelinux.org/packages) |

OpenVPN is invoked as a separate executable, not linked into the Go program.
Alpine retains package license metadata. Corresponding OpenVPN source is available
from the exact version's [Alpine source package recipe](https://gitlab.alpinelinux.org/alpine/aports/-/tree/3.24-stable/main/openvpn)
and [OpenVPN releases](https://github.com/OpenVPN/openvpn/releases).
Image builds use upstream unmodified distribution packages; redistributors must
also preserve their notices and satisfy the corresponding source obligations.
The CI emits an SBOM for the complete image, including transitive packages.
