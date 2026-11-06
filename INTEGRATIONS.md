# Integrations

Which tools 1cyber Comply can read evidence from, and which are on the way.
All integrations are **read-only**: 1cyber Comply never changes anything on your systems.

**Your tool is not listed?** Every NIS2 control, including the automated ones, can be covered with manual evidence
(document, screenshot or export, with reviewer and expiry date). Custom collectors for other
tools are available as a professional service from [1cyber.eu](https://1cyber.eu).

## Supported now

| Tool | Category | What is checked automatically | NIS2 controls |
|---|---|---|---|
| **Wazuh** 4.8+ | SIEM / XDR | Agents active and up to date, CIS hardening score (SCA), file integrity monitoring, hardware and software inventory, security alerts in the last 30 days, vulnerabilities by host and package | 21(2)(a), (b), (e), (g), (i) |
| **OPNsense** 24.x+ | Firewall / IPS | Firmware currency, active firewall ruleset (default deny, no any-to-any), Suricata IDS/IPS running, WireGuard VPN, HTTPS-only admin interface, VLAN segmentation | 21(2)(e), (g), (h), (i) |
| **Microsoft 365 / Entra ID** *(new in v1.1, beta)* | Identity | MFA enforced (security defaults or Conditional Access) and registered by every account, 2-4 Global Administrators all with MFA, no accounts unused for 90+ days. [Setup guide](docs/microsoft365-setup.md) | 21(2)(i), (j) |
| **1cyber Comply** itself | Monitoring | Compliance is measured continuously (automatic collection is running) | 21(2)(f) |

## Planned

| Tool | Category | What will be checked | Status |
|---|---|---|---|
| **Zenarmor** | Next-gen firewall / web filtering | Web filtering active, blocked threat categories, policies per network | next (v1.2) |
| **Microsoft Defender for Endpoint** | Endpoint protection | Protection active and updated on each device, open threats | planned |
| **Fortinet FortiGate** | Firewall / VPN | Firmware, rules, IPS, VPN, admin access | planned |
| **Sophos Firewall** | Firewall / VPN | Firmware, rules, IPS, VPN, admin access | planned |
| **CrowdSec** | Collaborative IPS | Engine running, bouncers active, recent decisions | planned |
| **Proxmox VE** | Virtualisation | Version, backup jobs and their last result | planned |

The order of the planned list follows user demand. Need one of them sooner, or a tool that
is not listed? Open an issue or contact [1cyber.eu](https://1cyber.eu).

## How an integration works

Each integration is a small collector module that queries the tool's API with a dedicated
least-privilege account, turns the answer into pass / fail / unknown results and attaches
them as evidence to the matching NIS2 controls. If a check cannot run (tool offline, missing
privilege), it is reported as *unknown* - never silently counted as compliant.
The exact privileges for each supported tool are documented in the [README](README.md).

*Beta* means the integration is complete and tested against Microsoft's documented API, and is
being validated on the first production tenants. Feedback is welcome.

A control can receive evidence from several sources at once (for example MFA from Microsoft 365
and a manual record for another identity provider). If any source reports a failure, the control
fails; an *unknown* result from one source does not hide a definitive result from another.
