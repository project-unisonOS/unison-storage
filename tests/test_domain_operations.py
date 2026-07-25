from datetime import date, timedelta

import pytest
from cryptography.fernet import Fernet

from domain_operations import DomainRejected, LifeDomainStore


def store(tmp_path):
    return LifeDomainStore(tmp_path / "domains", Fernet.generate_key())


def add(db, domain, kind, facts, source="src-1", person="person-a", space=None, status="observed", confidence=1.0):
    return db.create_record(person, space or f"{domain if domain in {'health', 'finance'} else 'private'}:{person}",
                            domain, kind, facts, [source], status, confidence)


def test_household_one_source_reconciliation_recall_attention_and_draft_only_brief(tmp_path):
    db = store(tmp_path)
    label = add(db, "household", "product", {"manufacturer": "Example", "model": "X1", "serial": "S9"}, "photo")
    receipt = add(db, "household", "receipt", {"manufacturer": "Example", "model": "X1",
                  "serial": "S9", "return_by": (date.today() + timedelta(days=7)).isoformat()}, "receipt")
    match = db.reconcile_product("person-a", label["record_id"], receipt["record_id"])
    assert match == {"match": True, "confidence": 1.0,
                     "compared": {"manufacturer": True, "model": True, "serial": True}, "uncertainty": None}
    attention = db.household_attention("person-a", [{"manufacturer": "Example", "model": "X1",
                                                       "serials": ["S9"], "title": "Battery safety"}])
    assert any("Return window" in item["summary"] for item in attention)
    assert any("Exact product recall" in item["summary"] for item in attention)
    brief = db.repair_brief("person-a", [label["record_id"], receipt["record_id"]])
    assert brief["source_ids"] == ["photo", "receipt"] and "No service" in brief["note"]


def test_household_private_default_explicit_share_and_no_physical_or_purchase_action(tmp_path):
    db = store(tmp_path)
    item = add(db, "household", "item", {"name": "Private purchase"})
    assert item["shared"] is False
    with pytest.raises(DomainRejected):
        db.share_record("person-a", item["record_id"], "shared:household", False)
    shared = db.share_record("person-a", item["record_id"], "shared:household", True)
    assert shared["shared"] is True
    for action in ("physical_actuation", "purchase", "schedule_service"):
        with pytest.raises(DomainRejected):
            db.draft("person-a", action, [item["record_id"]], [], [], "do it")


def test_fhir_normalization_timeline_provenance_contradiction_and_visit_brief(tmp_path):
    db = store(tmp_path)
    records = db.normalize_fhir("person-a", "fhir-source", [
        {"resourceType": "Condition", "id": "c1", "status": "active", "code": "example"},
        {"resourceType": "Observation", "id": "o1", "effectiveDateTime": "2026-01-02", "valueQuantity": {"value": 5}},
    ])
    assert all(record["source_ids"] == ["fhir-source"] for record in records)
    add(db, "health", "condition", {"code": "example", "status": "resolved"}, "pdf", status="self-reported")
    assert db.reconcile_health("person-a")[0]["contradiction"] is True
    timeline = db.health_timeline("person-a")
    brief = db.visit_brief("person-a", [record["record_id"] for record in timeline])
    assert "fhir-source" in brief["source_ids"] and "citations" in brief and "not a diagnosis" in brief["note"]
    observation = next(record for record in records if record["record_type"] == "observation")
    observation["facts"]["numeric"] = 5
    # Create through the store so the persisted record carries the selected trend value.
    trend_record = add(db, "health", "observation", {"date": "2026-01-03", "numeric": 7}, "lab")
    trend = db.health_trend("person-a", [trend_record["record_id"]], "numeric", 6)
    assert trend["rule_selected_by_person"] is True and len(trend["threshold_crossings"]) == 1


def test_health_inference_safety_emergency_selection_and_cross_person_denial(tmp_path):
    db = store(tmp_path)
    with pytest.raises(DomainRejected):
        add(db, "health", "condition", {"clinical_status": "confirmed"}, status="inferred", confidence=0.4)
    outcome = db.health_safety("person-a", "I have chest pain", ["self-report"])
    assert outcome["severity"] == "emergency" and outcome["dismisses_professional_care"] is False
    allergy = add(db, "health", "allergy", {"name": "Example"})
    with pytest.raises(DomainRejected):
        db.emergency_card("person-a", [allergy["record_id"]], False)
    assert db.emergency_card("person-a", [allergy["record_id"]], True)["selective"] is True
    with pytest.raises(DomainRejected):
        db.visit_brief("person-b", [allergy["record_id"]])


def test_finance_reconciliation_inference_contribution_attention_forecast_and_drafts(tmp_path):
    db = store(tmp_path)
    t1 = add(db, "finance", "transaction", {"merchant": "Example", "amount": -20.0, "date": "2026-07-01"}, "statement")
    t2 = add(db, "finance", "transaction", {"merchant": "Example", "amount": -20.0, "date": "2026-07-01"}, "statement")
    assert db.finance_reconcile("person-a", -40.0, [t1["record_id"], t2["record_id"]])["reconciled"] is True
    attention = db.finance_attention("person-a")
    assert len(attention) == 1 and "duplicate" in attention[0]["summary"].lower()
    balance = add(db, "finance", "balance", {"amount": 1000, "include_in_household": False}, "balance-source")
    forecast = db.cash_flow_forecast("person-a")
    assert forecast["evidence_status"] == "inferred" and forecast["confidence"] < 1
    assert db.household_finance_view("person-a", [balance["record_id"]])["total"] == 0
    brief = db.weekly_finance_brief("person-a")
    assert len(brief["citations"]) <= 5 and "suppressed" in brief["note"]
    draft = db.draft("person-a", "dispute-letter", [t1["record_id"]], ["merchant"], ["amount"], "Please review")
    assert draft["executable"] is False
    for action in ("transfer_funds", "trade_security", "open_credit", "file_tax_return"):
        with pytest.raises(DomainRejected):
            db.draft("person-a", action, [t1["record_id"]], [], [], "unsafe")


def test_cross_domain_links_are_purpose_bound_do_not_widen_disclosure_and_unlink_preserves_sources(tmp_path):
    db = store(tmp_path)
    health = add(db, "health", "encounter", {"date": "2026-07-01"}, "health-src")
    finance = add(db, "finance", "reimbursement", {"amount": 40}, "finance-src")
    with pytest.raises(DomainRejected):
        db.link("person-a", health["record_id"], finance["record_id"], "", ["date"], [], True)
    link = db.link("person-a", health["record_id"], finance["record_id"], "claim packet",
                   ["date", "amount"], ["insurer"], True)
    db.unlink("person-a", link["link_id"])
    assert len(db.records("person-a")) == 2
    shared = db.share_record("person-a", finance["record_id"], "shared:household", True)
    with pytest.raises(DomainRejected):
        db.link("person-a", health["record_id"], shared["record_id"], "care planning", ["date"], ["household"], True)


def test_cross_domain_packets_and_transition_templates_remain_drafts(tmp_path):
    db = store(tmp_path)
    health = add(db, "health", "encounter", {"date": "2026-07-01"}, "health-src")
    finance = add(db, "finance", "reimbursement", {"amount": 40}, "finance-src")
    link = db.link("person-a", health["record_id"], finance["record_id"], "claim preparation",
                   ["date", "amount"], ["insurer"], True)
    packet = db.cross_domain_packet("person-a", [link["link_id"]], "claim", ["insurer"])
    assert packet["executable"] is False and packet["disclosed_fields"] == ["amount", "date"]
    template = db.transition_template("moving")
    assert template["status"] == "draft" and template["requires_person_approval"] is True


def test_unified_attention_ranking_is_explainable_and_source_deletion_cascades_only_derived_state(tmp_path):
    db = store(tmp_path)
    receipt = add(db, "household", "receipt", {"return_by": (date.today() + timedelta(days=2)).isoformat()}, "remove-me")
    add(db, "finance", "transaction", {"merchant": "X", "amount": -4, "date": "2026-07-01"}, "keep")
    add(db, "finance", "transaction", {"merchant": "X", "amount": -4, "date": "2026-07-01"}, "keep")
    inbox = db.attention_inbox("person-a", ["return purchase"])
    assert inbox[0]["rank_score"] >= inbox[-1]["rank_score"] and "ranking_basis" in inbox[0]
    removed = db.delete_records_from_source("person-a", "remove-me")
    assert removed["records"] == 1
    assert receipt["record_id"] not in {record["record_id"] for record in db.records("person-a")}
    assert len(db.records("person-a", "finance")) == 2


def test_synthetic_pilot_meets_value_gate_and_human_pilot_requires_opt_in(tmp_path):
    db = store(tmp_path)
    measurements = {"time_to_first_value_minutes": 4, "setup_completion_percent": 95,
                    "extraction_precision_percent": 96, "attention_precision_percent": 90,
                    "brief_usefulness_percent": 88, "notification_burden_per_week": 2,
                    "privacy_comprehension_percent": 100, "deletion_success_percent": 100,
                    "time_returned_minutes": 35}
    report = db.pilot_report("synthetic-household", False, measurements)
    assert report["gate_passed"] is True and report["supported_package_decision"] == "hold"
    with pytest.raises(DomainRejected):
        db.pilot_report("opt-in-human", False, measurements)
