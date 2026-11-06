# Changelog

## v1.0.0 - 2026-11-06

First public release.

- NIS2 catalogue: 41 controls covering Article 21(2)(a)-(j) and Article 23
- Wazuh collector (Server API + Indexer): agents, agent versions, SCA hardening score, file
  integrity monitoring, inventory, alerts, vulnerabilities by host and package
- OPNsense collector: firmware currency, active firewall ruleset analysis, IDS/IPS, WireGuard,
  HTTPS admin interface, VLAN segmentation - read-only with a documented minimal privilege set
- Compliance score with history chart; automatic collection every 24 h
- Manual evidence with files, reviewer and expiry; evidence history per control
- PDF compliance report with findings, evidence and file hashes
- Login, roles (viewer / editor / admin), CSRF protection, lockout, audit log, optional HTTPS
- One-line installer, Debian package, CI and automated releases
- Demo data seeder for evaluation without Wazuh or OPNsense
