"""Fill an empty 1cyber Comply database with fictional demo data.

Useful to explore the app (and to make the README screenshots) without Wazuh or
OPNsense. All names, hosts and findings are invented.

    COMPLY_DATA_DIR=/tmp/comply-demo python scripts/seed_demo.py
    COMPLY_DATA_DIR=/tmp/comply-demo COLLECT_INTERVAL_HOURS=24 uvicorn app.main:app

Log in as demo / Try-Comply-2026
"""
import json
import random
import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import auth, catalog, evidence, manual  # noqa: E402
from app.collectors.base import CheckResult  # noqa: E402
from app.db import get_conn, init_db  # noqa: E402

init_db()
catalog.load_all()
with get_conn() as conn:
    if conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]:
        sys.exit("Database already has evidence; use an empty COMPLY_DATA_DIR.")

if auth.user_count() == 0:
    auth.create_user("demo", "Try-Comply-2026", "admin")
    auth.create_user("a.ionescu", "Try-Comply-2026", "editor")
    auth.create_user("auditor", "Try-Comply-2026", "viewer")

evidence.save_results("wazuh", [
    CheckResult("agents_active", "pass", "All 14 agents are active."),
    CheckResult("agents_version", "fail", "2 agents differ from manager version v4.14.8: fin-laptop-03 (Wazuh v4.12.0), "
                "print-srv (Wazuh v4.13.1)"),
    CheckResult("sca", "fail", "Average SCA score 61%. below 70%: fin-laptop-03 (48%), print-srv (52%)"),
    CheckResult("fim", "pass", "FIM ran on all 14 active agents in the last 48 hours."),
    CheckResult("syscollector", "pass", "Complete inventory for 14 agents (9,412 packages)."),
    CheckResult("alerts_recent", "pass", "18,240 alerts in the last 30 days (level 12+: 3, 7-11: 512). "
                "Alert review is documented manually."),
    CheckResult("vulnerabilities", "fail", "6 open critical vulnerabilities. On: print-srv (4), fin-laptop-03 (2). "
                "Top packages: openssl (3), Mozilla Firefox (2), sudo (1). Total 87 (Critical: 6, High: 21, Low: 18, Medium: 42)."),
])
evidence.save_results("opnsense", [
    CheckResult("firmware", "pass", "Installed OPNsense 26.7.8-amd64, latest public release is 26.7.8."),
    CheckResult("firewall_rules", "pass", "112 active rules (48 inbound pass, 37 inbound block). Default deny is active "
                "and no unrestricted any-to-any inbound rules."),
    CheckResult("ids", "pass", "Intrusion detection is enabled and running in IPS (blocking) mode."),
    CheckResult("vpn", "pass", "WireGuard is enabled with 1 active instance(s)."),
    CheckResult("webgui_https", "pass", "Web GUI uses HTTPS; plain HTTP redirects to HTTPS."),
    CheckResult("vlans", "pass", "4 VLAN(s) configured (tags: 10, 20, 30, 99)."),
])
evidence.save_results("comply", [CheckResult("score_history", "pass",
                                             "Compliance is measured automatically every 24h (30 score snapshots recorded).")])

year = (date.today() + timedelta(days=330)).isoformat()
for cid, status, note, f in [
    ("nis2-a-01", "pass", "Information Security Policy v3.0, approved by the board on 12 May.", "isms-policy-v3.pdf"),
    ("nis2-a-02", "pass", "Risk register 2026 with 34 risks, owners and treatment plans.", "risk-register-2026.xlsx"),
    ("nis2-b-01", "pass", "Incident response plan with on-call rota and severity matrix.", "incident-response-plan.pdf"),
    ("nis2-b-04", "pass", "CSIRT reporting procedure and templates for 24h / 72h / 1 month reports.", None),
    ("nis2-c-01", "fail", "BCP exists but RTO/RPO not defined for the ERP system.", None),
    ("nis2-d-01", "pass", "Supplier register with 22 ICT suppliers rated by criticality.", "supplier-register.xlsx"),
    ("nis2-g-01", "fail", "Awareness training completed by 41 of 58 employees (71%).", None),
    ("nis2-j-01", "pass", "MFA enforced for VPN, admin accounts and Microsoft 365.", "mfa-coverage.png"),
]:
    manual.add_manual_evidence(cid, status, note, "a.ionescu", year,
                               manual.Upload(f, b"%PDF-1.4 demo evidence") if f else None)

# 30 days of score history, improving over time
random.seed(7)
with get_conn() as conn:
    controls = conn.execute("SELECT COUNT(*) FROM controls WHERE framework_id='nis2'").fetchone()[0]
    for i in range(30):
        day = (date.today() - timedelta(days=29 - i)).isoformat()
        passed = min(19, 6 + i * 13 // 29 + random.choice((0, 0, 1)))
        auto = min(78.6, 42.9 + i * 1.3 + random.uniform(-2, 2))
        conn.execute(
            """INSERT INTO score_history (framework_id, taken_at, score, automated_score, passed, failed, unknown,
                                          missing, total) VALUES ('nis2', ?, ?, ?, ?, ?, 0, ?, ?)""",
            (f"{day} 06:00:00", round(100 * passed / controls, 1), round(auto, 1), passed, 6,
             controls - passed - 6, controls))
    conn.execute("UPDATE evidence SET collected_at = datetime('now', '-2 hours')")
    for u, act, det in [("demo", "login.success", ""), ("a.ionescu", "evidence.added", "nis2-a-01 pass + isms-policy-v3.pdf"),
                        ("demo", "collect.all", ""), ("auditor", "login.success", "")]:
        conn.execute("INSERT INTO audit_log (username, action, detail, ip) VALUES (?, ?, ?, '10.0.20.15')", (u, act, det))
print(json.dumps({"seeded": True, "login": "demo / Try-Comply-2026"}))
