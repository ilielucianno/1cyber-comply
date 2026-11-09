# Changelog

## v1.2.0 - 2026-11-09

### Added
- Maturity model support, starting with the Cyprus DSA cybersecurity maturity model
  (K.D.P. 245/2024, Annex E): 70 measures in 17 categories, levels 0-5, unofficial
  English translation in `controls/maturity/dsa-cy-245-2024.yaml`, read through by a
  Cyprus cybersecurity practitioner with no changes requested.
- Maturity scoring engine (`app/maturity.py`). Levels are cumulative: the first unmet
  requirement caps the measure and is reported as the blocking requirement. Unanswered
  requirements count as not met. "Not applicable" is accepted only on requirements the
  catalogue marks for it (DSA: DS1 4.9 and HRS6 5.4, which apply only when cloud services
  are used), needs a justification noted on the requirement and is reported in a Cloud section. The organisation is mature when every measure reaches
  the target level (3 for the DSA model).
- Assessment answers with full history (`maturity_answers`) and a result history
  (`maturity_history`).
- Assessment screens: a Maturity page with the result, the level distribution, every
  measure with its level and blocking requirement (filters: below target, not fully
  assessed) and the Cloud not-applicable section; a page per measure with the
  requirements by level, met / not met / not applicable choices, notes, the blocking
  requirement highlighted, answer history and "Save and go to next measure". Only
  changes are saved; an invalid answer saves nothing. Viewers see a read-only form.
  The dashboard shows a maturity summary card.
- Automated evidence for the DSA model (`controls/maturity/evidence/dsa-cy-245-2024.yaml`):
  23 requirements linked to Wazuh, OPNsense and Microsoft 365 checks, each with a written
  rationale. Evidence never answers by itself. A "full" mapping can suggest "met"; a
  "partial" one (most of them) can only suggest "not met" when its check fails, and a pass
  is shown as supporting evidence. Evidence older than 72 hours gives no signal. Suggestions
  can be applied to unanswered requirements (per measure or all at once) and are saved with
  the evidence reference; answers given by a person are never overwritten. Saved answers
  that the current evidence contradicts are reported as conflicts.
- Automated evidence now records the collector check name (`evidence.check_name`); older
  rows are matched through the control's automation field.
- Maturity PDF report (`/reports/maturity/{id}.pdf`, buttons on the Maturity page and the
  dashboard): summary and verdict, measures per level, maturity by category, result per
  measure with its blocking requirement, a remediation plan to reach the target level
  (lowest level first, P1-P3, every open requirement up to the target with its status and
  note, owner and due date columns), the Cloud not-applicable section, automated evidence
  conflicts, the assessment record and a statement of what the report does not prove.
- API: `GET /api/maturity/{id}/evidence`, `POST /api/maturity/{id}/evidence/apply`.
- API: `GET /api/maturity`, `GET /api/maturity/{id}`,
  `GET /api/maturity/{id}/measures/{measure}`, `POST /api/maturity/{id}/answers`.

## v1.1.0 - 2026-11-06

- **Microsoft 365 / Entra ID collector (beta)**: MFA enforcement (security defaults or Conditional
  Access) and registration coverage, Global Administrator count and admin MFA, accounts unused for
  90+ days. Read-only Graph app registration; works without Entra ID P1 with reduced coverage.
  Setup guide in docs/microsoft365-setup.md
- **Evidence from several sources per control**: the latest result of each source is combined;
  any failure fails the control, *unknown* does not hide a definitive result
- **Manual evidence on every control**, including automated ones (e.g. OpenVPN instead of WireGuard)
- NIS2 controls 21(2)(i) least privilege, joiner/mover/leaver and 21(2)(j) MFA are now automated
  with Microsoft 365 (17 automated controls)
- INTEGRATIONS.md: supported and planned tools

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
