"""Maturity model: catalogue loading, the cumulative scoring rule, answers and API."""
import copy
import re

import pytest
import yaml
from helpers import LoggedInClient

from app import maturity
from app.db import get_conn
from app.main import app

FW = "dsa-cy-245-2024"

MINI = {
    "framework": {
        "id": "mini", "name": "Mini model",
        "scoring": {"type": "maturity", "target_level": 3},
        "common_requirements": {"R1": "Documents are reviewed yearly."},
        "not_applicable": {"cloud": {"title": "Cloud", "condition": "No cloud services are used."}},
    },
    "categories": [{"id": "X", "title": "Example", "measures": [{
        "id": "X1", "title": "Example measure", "level0": "Nothing in place.",
        "levels": {
            1: [{"id": "1.1", "text": "a"}, {"id": "1.2", "text": "b"}, {"id": "1.3", "text": "c"}],
            2: [{"id": "2.1", "text": "d", "na": "cloud"}],
            3: [{"id": "3.1", "text": "e"}, {"id": "3.2", "common": "R1"}],
            4: [{"id": "4.1", "text": "f"}],
            5: [{"id": "5.1", "text": "g"}],
        },
    }]}],
}


def mini():
    return maturity.parse(copy.deepcopy(MINI), "mini.yaml")


def ans(**kw):
    """ans(**{'1.1': 'met'}) -> answers dict in the shape latest_answers() returns."""
    return {("X1", k): {"answer": v, "note": None, "answered_by": "t", "answered_at": "now"} for k, v in kw.items()}


def all_met(upto: int, cat=None):
    cat = cat or mini()
    return {("X1", r.id): {"answer": "met", "note": None, "answered_by": "t", "answered_at": "now"}
            for r in cat.measures[0].requirements if r.level <= upto}


@pytest.fixture
def client():
    with LoggedInClient(app) as c:
        with get_conn() as conn:
            conn.execute("DELETE FROM maturity_answers")
            conn.execute("DELETE FROM maturity_history")
        yield c


# ---------- catalogue ----------

def test_dsa_catalogue_loads_completely():
    maturity.load_all()
    cat = maturity.get(FW)
    assert cat is not None
    assert len(cat.measures) == 70
    assert cat.requirement_count == 1499 - 70     # level 0 statements are states, not requirements
    assert cat.target_level == 3
    assert len({m.category_id for m in cat.measures}) == 17
    for m in cat.measures:
        assert m.level0, m.id
        assert {r.level for r in m.requirements} == {1, 2, 3, 4, 5}, m.id
        assert [r.level for r in m.requirements] == sorted(r.level for r in m.requirements), m.id


def test_original_numbering_and_common_requirements_are_kept():
    maturity.load_all()
    cat = maturity.get(FW)
    rm1 = [r.id for r in cat.measure("RM1").requirements if r.level == 2]
    assert rm1.index("2.4") < rm1.index("2.3")                 # odd order in the original
    assert cat.measure("RM2").requirement("3.2") is None       # gap in the original
    k1 = [r for m in cat.measures for r in m.requirements if r.common == "K1"]
    assert len(k1) == 70 and all(r.text.startswith("The skills") for r in k1)


@pytest.mark.parametrize("mutate, message", [
    (lambda d: d["framework"]["scoring"].update(type="percent"), "scoring.type"),
    (lambda d: d["framework"]["scoring"].update(target_level=7), "target_level"),
    (lambda d: d["categories"][0]["measures"][0]["levels"].pop(4), "level(s) [4]"),
    (lambda d: d["categories"][0]["measures"][0]["levels"][2].append({"id": "2.1", "text": "x"}), "duplicate requirement"),
    (lambda d: d["categories"][0]["measures"][0]["levels"][2].append({"id": "3.9", "text": "x"}), "listed under level 2"),
    (lambda d: d["categories"][0]["measures"][0]["levels"][3].append({"id": "3.3", "common": "K9"}), "unknown common"),
    (lambda d: d["categories"][0]["measures"][0]["levels"][4].append({"id": "4.2", "text": "x", "na": "onprem"}), "unknown not_applicable"),
    (lambda d: d["categories"][0]["measures"].append(copy.deepcopy(d["categories"][0]["measures"][0])), "duplicate measure"),
])
def test_invalid_catalogue_is_rejected(mutate, message):
    data = copy.deepcopy(MINI)
    mutate(data)
    with pytest.raises(maturity.MaturityCatalogError, match=re.escape(message)):
        maturity.parse(data, "bad.yaml")


def test_load_all_rejects_duplicate_framework_ids(tmp_path):
    for name in ("a.yaml", "b.yaml"):
        (tmp_path / name).write_text(yaml.safe_dump(MINI), encoding="utf-8")
    with pytest.raises(maturity.MaturityCatalogError, match="already loaded"):
        maturity.load_all(tmp_path)
    maturity.load_all()


# ---------- scoring rule ----------

def test_nothing_answered_is_level_0_not_assessed():
    m = mini().measures[0]
    s = maturity.score_measure(m, {}, 3)
    assert s["level"] == 0 and s["blocking"]["id"] == "1.1" and s["blocking"]["reason"] == "not_assessed"
    assert not s["meets_target"]


def test_failing_1_3_caps_at_level_0_even_if_higher_levels_are_met():
    """The rule confirmed for the DSA model: the first failure caps the level."""
    cat = mini()
    a = all_met(5, cat)
    a[("X1", "1.3")]["answer"] = "not_met"
    s = maturity.score_measure(cat.measures[0], a, 3)
    assert s["level"] == 0
    assert s["blocking"]["id"] == "1.3" and s["blocking"]["reason"] == "not_met"
    assert [g["id"] for g in s["gaps_to_target"]] == ["1.3"]


@pytest.mark.parametrize("upto, expected", [(1, 1), (2, 2), (3, 3), (4, 4), (5, 5)])
def test_level_is_last_fully_met_level(upto, expected):
    cat = mini()
    s = maturity.score_measure(cat.measures[0], all_met(upto, cat), 3)
    assert s["level"] == expected
    assert s["meets_target"] == (expected >= 3)
    assert (s["blocking"] is None) == (expected == 5)


def test_common_requirement_blocks_like_any_other():
    cat = mini()
    a = all_met(5, cat)
    del a[("X1", "3.2")]                 # R1 not assessed
    s = maturity.score_measure(cat.measures[0], a, 3)
    assert s["level"] == 2 and s["blocking"]["id"] == "3.2" and s["blocking"]["common"] == "R1"


def test_not_applicable_counts_as_met_but_is_listed():
    cat = mini()
    a = all_met(3, cat)
    a[("X1", "2.1")] = {"answer": "na", "note": "No such system", "answered_by": "t", "answered_at": "now"}
    s = maturity.score_measure(cat.measures[0], a, 3)
    assert s["level"] == 3
    assert [r["id"] for r in s["not_applicable"]] == ["2.1"]


def test_gaps_list_everything_open_up_to_target():
    cat = mini()
    a = ans(**{"1.1": "met", "1.2": "not_met", "1.3": "met", "2.1": "met"})
    s = maturity.score_measure(cat.measures[0], a, 3)
    assert s["level"] == 0
    assert [g["id"] for g in s["gaps_to_target"]] == ["1.2", "3.1", "3.2"]
    assert s["per_level"][1] == {"total": 3, "met": 2}


# ---------- answers, framework result and API ----------

def test_save_answer_validation(client):
    with pytest.raises(KeyError):
        maturity.save_answer(FW, "NOPE1", "1.1", "met")
    with pytest.raises(KeyError):
        maturity.save_answer(FW, "RM2", "3.2", "met")          # gap in the original numbering
    with pytest.raises(ValueError):
        maturity.save_answer(FW, "STR1", "1.1", "yes")
    with pytest.raises(ValueError, match="cannot be marked not applicable"):
        maturity.save_answer(FW, "STR1", "1.1", "na", note="We think so")
    with pytest.raises(ValueError, match="justification"):
        maturity.save_answer(FW, "HRS6", "5.4", "na")


def test_only_cloud_conditional_requirements_accept_na():
    maturity.load_all()
    cat = maturity.get(FW)
    allowed = {(m.id, r.id) for m in cat.measures for r in m.requirements if r.na}
    assert allowed == {("DS1", "4.9"), ("HRS6", "5.4")}
    assert cat.na_sections["cloud"]["title"] == "Cloud"


def test_na_is_reported_under_the_cloud_section(client):
    maturity.save_answer(FW, "HRS6", "5.4", "na", note="No cloud services are used (checked 2026-11-09)")
    s = maturity.compute(FW)
    cloud = next(sec for sec in s["not_applicable_sections"] if sec["id"] == "cloud")
    assert [(i["measure_id"], i["id"]) for i in cloud["items"]] == [("HRS6", "5.4")]
    assert cloud["items"][0]["note"].startswith("No cloud")
    assert s["not_applicable_total"] == 1


def test_latest_answer_wins_and_history_is_kept(client):
    maturity.save_answer(FW, "STR1", "1.1", "not_met", answered_by="a")
    maturity.save_answer(FW, "STR1", "1.1", "met", answered_by="b")
    latest = maturity.latest_answers(FW)
    assert latest[("STR1", "1.1")]["answer"] == "met"
    assert len(maturity.answer_history(FW, "STR1")) == 2


def test_framework_result_and_maturity_flag(client):
    cat = maturity.get(FW)
    s = maturity.compute(FW)
    assert s["mature"] is False and s["measures_at_target"] == 0 and s["distribution"][0] == 70
    for m in cat.measures:
        for r in m.requirements:
            if r.level <= 3:
                maturity.save_answer(FW, m.id, r.id, "met")
    s = maturity.compute(FW)
    assert s["mature"] is True and s["min_level"] == 3 and s["distribution"][3] == 70
    first = cat.measures[0]
    maturity.save_answer(FW, first.id, first.requirements[0].id, "not_met")
    s = maturity.compute(FW)
    assert s["mature"] is False and s["below_target"] == 1 and s["min_level"] == 0


def test_api_answers_score_and_snapshot(client):
    r = client.get("/api/maturity")
    assert r.status_code == 200 and r.json()[0]["id"] == FW
    r = client.post(f"/api/maturity/{FW}/answers", json=[
        {"measure_id": "STR1", "requirement_id": "1.1", "answer": "met"},
        {"measure_id": "STR1", "requirement_id": "1.2", "answer": "met"},
        {"measure_id": "DS1", "requirement_id": "4.9", "answer": "na", "note": "No data stored with third parties"},
    ])
    assert r.status_code == 200, r.text
    assert r.json()["saved"] == 3
    r = client.post(f"/api/maturity/{FW}/answers",
                    json={"measure_id": "STR1", "requirement_id": "1.3", "answer": "not_met"})
    assert r.status_code == 200
    d = client.get(f"/api/maturity/{FW}/measures/STR1").json()
    assert d["level"] == 0 and d["blocking"]["id"] == "1.3"
    assert len(d["requirements"]) == len(maturity.get(FW).measure("STR1").requirements)
    score = client.get(f"/api/maturity/{FW}").json()
    assert score["requirements_answered"] == 4
    assert len(score["history"]) == 1           # saves within the hour update one history point


@pytest.mark.parametrize("body", [
    {"measure_id": "STR1", "requirement_id": "9.9", "answer": "met"},
    {"measure_id": "STR1", "requirement_id": "1.1", "answer": "maybe"},
    {"measure_id": "STR1", "requirement_id": "1.1", "answer": "na", "note": "not a cloud requirement"},
    {"measure_id": "HRS6", "requirement_id": "5.4", "answer": "na"},
    [],
])
def test_api_rejects_bad_answers_and_saves_nothing(client, body):
    payload = body if body == [] else [{"measure_id": "STR1", "requirement_id": "1.1", "answer": "met"}, body]
    r = client.post(f"/api/maturity/{FW}/answers", json=payload)
    assert r.status_code == 400
    assert maturity.latest_answers(FW) == {}


def test_api_404_and_viewer_cannot_answer(client):
    assert client.get("/api/maturity/nope").status_code == 404
    assert client.get(f"/api/maturity/{FW}/measures/NOPE").status_code == 404
    with LoggedInClient(app, role="viewer") as viewer:
        assert viewer.get(f"/api/maturity/{FW}").status_code == 200
        r = viewer.post(f"/api/maturity/{FW}/answers",
                        json={"measure_id": "STR1", "requirement_id": "1.1", "answer": "met"})
        assert r.status_code == 403


# ---------- assessment screens ----------

def test_maturity_pages_render(client):
    r = client.get("/maturity", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/maturity/{FW}"
    r = client.get(f"/maturity/{FW}")
    assert r.status_code == 200 and "0/70" in r.text and "Not mature yet" in r.text
    for show in ("below", "open", "bogus"):
        assert client.get(f"/maturity/{FW}?show={show}").status_code == 200
    r = client.get(f"/maturity/{FW}/HRS6")
    assert r.status_code == 200
    assert 'name="a:5.4" value="na"' in r.text            # cloud requirement offers N/A
    assert 'name="a:1.1" value="na"' not in r.text        # others do not
    assert "Save and go to" in r.text
    assert client.get(f"/maturity/{FW}/NOPE").status_code == 404
    assert "Open assessment" in client.get("/").text


def test_form_saves_only_changes_and_applies_the_rule(client):
    url = f"/maturity/{FW}/STR1"
    form = {"a:1.1": "met", "a:1.2": "met", "a:1.3": "not_met", "n:1.3": "No policy yet"}
    r = client.post(url, data=form, follow_redirects=False)
    assert r.status_code == 303 and "3%20answer" in r.headers["location"]
    page = client.get(url).text
    assert "Blocked by" in page and "1.3" in page and "No policy yet" in page
    r = client.post(url, data=form, follow_redirects=False)            # same values again
    assert "No%20changes" in r.headers["location"]
    assert len(maturity.answer_history(FW, "STR1")) == 3
    client.post(url, data={"n:1.3": "Policy draft under review"})        # note only
    latest = maturity.latest_answers(FW)[("STR1", "1.3")]
    assert latest["answer"] == "not_met" and latest["note"] == "Policy draft under review"


def test_form_rejects_invalid_na_and_saves_nothing(client):
    r = client.post(f"/maturity/{FW}/HRS6", data={"a:1.1": "met", "a:5.4": "na"}, follow_redirects=False)
    assert "ok=0" in r.headers["location"] and "Nothing%20was%20saved" in r.headers["location"]
    assert maturity.latest_answers(FW) == {}
    r = client.post(f"/maturity/{FW}/HRS6", data={"a:5.4": "na", "n:5.4": "No cloud services"},
                    follow_redirects=False)
    assert "ok=1" in r.headers["location"]
    assert "No cloud services" in client.get(f"/maturity/{FW}").text      # Cloud section


def test_save_and_next_goes_to_following_measure(client):
    r = client.post(f"/maturity/{FW}/STR1", data={"a:1.1": "met", "next": "1"}, follow_redirects=False)
    assert r.headers["location"].startswith(f"/maturity/{FW}/GOV1?")


def test_viewer_sees_read_only_form(client):
    with LoggedInClient(app, role="viewer") as viewer:
        page = viewer.get(f"/maturity/{FW}/STR1").text
        assert "disabled" in page and "Save and go to" not in page
        assert viewer.post(f"/maturity/{FW}/STR1", data={"a:1.1": "met"}).status_code == 403


# ---------- automated evidence ----------

from datetime import datetime, timedelta, timezone  # noqa: E402

from app import evidence  # noqa: E402
from app.collectors.base import CheckResult  # noqa: E402


@pytest.fixture
def ev_client(client):
    with get_conn() as conn:
        conn.execute("DELETE FROM attachments")
        conn.execute("DELETE FROM evidence")
    yield client


def test_every_mapped_check_is_a_real_collector_check():
    maturity.load_all()
    nis2 = yaml.safe_load(open(maturity.CONTROLS_DIR / "nis2.yaml"))
    known = {a.strip() for cat in nis2["categories"] for c in cat["controls"]
             for a in str(c.get("automation") or "").split(",") if a.strip()}
    maps = maturity.mappings(FW)
    assert len(maps) >= 20
    for mp in maps:
        for src, chk in mp.checks:
            assert f"{src}:{chk}" in known, (mp.measure_id, mp.requirement_id, src, chk)


@pytest.mark.parametrize("entry, message", [
    ({"measure": "NOPE1", "requirement": "1.1", "checks": ["wazuh:fim"], "why": "x"}, "unknown requirement"),
    ({"measure": "SS1", "requirement": "5.2", "checks": ["foo:fim"], "why": "x"}, "invalid check"),
    ({"measure": "SS1", "requirement": "5.2", "checks": [], "why": "x"}, "no checks"),
    ({"measure": "SS1", "requirement": "5.2", "checks": ["wazuh:fim"], "coverage": "most", "why": "x"}, "coverage"),
    ({"measure": "SS1", "requirement": "5.2", "checks": ["wazuh:fim"]}, "why"),
])
def test_invalid_evidence_mapping_is_rejected(entry, message):
    maturity.load_all()
    cats = {FW: maturity.get(FW)}
    with pytest.raises(maturity.MaturityCatalogError, match=message):
        maturity.parse_mappings({"framework": FW, "mappings": [entry]}, "bad.yaml", cats)
    dup = {"measure": "SS1", "requirement": "5.2", "checks": ["wazuh:fim"], "why": "x"}
    with pytest.raises(maturity.MaturityCatalogError, match="mapped twice"):
        maturity.parse_mappings({"framework": FW, "mappings": [dup, dup]}, "bad.yaml", cats)


def test_full_mapping_suggests_met_and_partial_only_supports(ev_client):
    evidence.save_results("wazuh", [CheckResult("fim", "pass", "FIM ran on all agents"),
                                    CheckResult("syscollector", "pass", "Inventory complete")])
    ev = maturity.evidence_status(FW)
    assert ev[("SS1", "5.2")]["signal"] == "supports" and ev[("SS1", "5.2")]["suggestion"] == "met"
    assert ev[("AM2", "4.1")]["signal"] == "supports" and ev[("AM2", "4.1")]["suggestion"] is None
    assert ev[("NS7", "3.2")]["signal"] == "incomplete"          # opnsense:ids never collected


def test_failing_check_contradicts_and_ran_signal_counts_any_result(ev_client):
    evidence.save_results("wazuh", [CheckResult("sca", "fail", "2 agents below 70%"),
                                    CheckResult("vulnerabilities", "fail", "3 critical")])
    ev = maturity.evidence_status(FW)
    assert ev[("SS2", "5.7")]["signal"] == "contradicts" and ev[("SS2", "5.7")]["suggestion"] == "not_met"
    # The scanner found critical issues, which proves it runs: VM1 4.1 is supported
    assert ev[("VM1", "4.1")]["signal"] == "supports" and ev[("VM1", "4.1")]["suggestion"] == "met"


def test_stale_and_unknown_evidence_give_no_signal(ev_client):
    evidence.save_results("wazuh", [CheckResult("fim", "pass", "ok")])
    later = datetime.now(timezone.utc) + timedelta(hours=100)
    assert maturity.evidence_status(FW, now=later)[("SS1", "5.2")]["checks"][0]["state"] == "stale"
    assert maturity.evidence_status(FW, now=later)[("SS1", "5.2")]["suggestion"] is None
    evidence.save_results("wazuh", [CheckResult("fim", "unknown", "API error")])
    assert maturity.evidence_status(FW)[("SS1", "5.2")]["signal"] == "incomplete"


def test_old_evidence_without_check_name_is_matched(ev_client):
    evidence.save_results("wazuh", [CheckResult("fim", "pass", "ok")])
    with get_conn() as conn:
        conn.execute("UPDATE evidence SET check_name = NULL")
    assert maturity.evidence_status(FW)[("SS1", "5.2")]["signal"] == "supports"


def test_apply_suggestions_never_overwrites_a_person(ev_client):
    evidence.save_results("wazuh", [CheckResult("fim", "pass", "FIM ok"),
                                    CheckResult("sca", "fail", "low score")])
    maturity.save_answer(FW, "SS2", "5.7", "met", "Checked by hand", "alice")
    saved = maturity.apply_suggestions(FW, "bob")
    latest = maturity.latest_answers(FW)
    assert saved == 1
    assert latest[("SS1", "5.2")]["answer"] == "met" and latest[("SS1", "5.2")]["evidence_id"]
    assert "wazuh:fim pass" in latest[("SS1", "5.2")]["note"]
    assert latest[("SS2", "5.7")]["answer"] == "met" and latest[("SS2", "5.7")]["answered_by"] == "alice"
    # ...but the contradiction is reported as a conflict
    s = maturity.compute(FW)
    assert [(c["measure_id"], c["requirement_id"]) for c in s["evidence_conflicts"]] == [("SS2", "5.7")]
    assert maturity.apply_suggestions(FW, "bob") == 0


def test_evidence_in_ui_and_api(ev_client):
    evidence.save_results("wazuh", [CheckResult("fim", "pass", "FIM ran on all agents")])
    page = ev_client.get(f"/maturity/{FW}/SS1").text
    assert "Automated evidence" in page and "FIM ran on all agents" in page and "Apply evidence suggestions" in page
    assert "1</strong> unanswered requirement" in ev_client.get(f"/maturity/{FW}").text
    api = ev_client.get(f"/api/maturity/{FW}/evidence").json()
    assert [(p["measure_id"], p["requirement_id"]) for p in api["pending"]] == [("SS1", "5.2")]
    r = ev_client.post(f"/maturity/{FW}/apply-evidence", data={"measure_id": "SS1"}, follow_redirects=False)
    assert r.status_code == 303 and "1%20answer" in r.headers["location"]
    assert ev_client.post(f"/api/maturity/{FW}/evidence/apply").json() == {"saved": 0}
    with LoggedInClient(app, role="viewer") as viewer:
        assert viewer.post(f"/maturity/{FW}/apply-evidence", data={}).status_code == 403
        assert "Apply evidence suggestions" not in viewer.get(f"/maturity/{FW}/SS1").text
