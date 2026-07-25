"""Principal-bound domain packages for private household, health, and finance operations."""

from __future__ import annotations

import json
import math
import secrets
import time
from datetime import date
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


HOUSEHOLD_TYPES = frozenset({
    "item", "product", "property", "warranty", "receipt", "manual", "service-event",
    "renewal", "return-window", "recall", "subscription", "procedure", "matter-device", "energy-record",
})
HEALTH_TYPES = frozenset({
    "medication", "condition", "allergy", "immunization", "lab", "observation", "procedure",
    "encounter", "instruction", "referral", "follow-up", "wearable-observation",
})
FINANCE_TYPES = frozenset({
    "account", "balance", "transaction", "merchant", "obligation", "recurring-event", "asset",
    "liability", "reimbursement", "refund", "subscription", "goal", "tax-form", "insurance-document",
})
CROSS_TYPES = frozenset({
    "benefits-packet", "claim-packet", "care-commitment", "life-transition-plan", "credential-expiration",
    "insurance-claim-event", "continuity-plan", "emergency-plan",
})
DOMAIN_TYPES = {
    "household": HOUSEHOLD_TYPES, "health": HEALTH_TYPES, "finance": FINANCE_TYPES,
    "care": CROSS_TYPES, "benefits": CROSS_TYPES, "insurance": CROSS_TYPES, "continuity": CROSS_TYPES,
}
URGENT_HEALTH_RULES = {
    "chest pain": ("emergency", "Seek emergency medical help now. Do not rely on Unison to rule out an emergency."),
    "difficulty breathing": ("emergency", "Seek emergency medical help now. Do not rely on Unison to rule out an emergency."),
    "suicidal": ("emergency", "Contact emergency or crisis support now and involve a trusted person if you can."),
    "severe allergic": ("emergency", "Use your prescribed emergency plan and seek emergency medical help now."),
    "new weakness": ("urgent", "Contact urgent clinical care now. Sudden weakness can require emergency assessment."),
}


class DomainRejected(ValueError):
    pass


def _today() -> date:
    return date.today()


def _parse_date(value: Any) -> date | None:
    try:
        return date.fromisoformat(str(value)[:10])
    except (TypeError, ValueError):
        return None


class LifeDomainStore:
    """Encrypted, restart-safe domain state with one authority path for every package."""

    def __init__(self, root: Path, encryption_key: bytes):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.state_path = root / "domain-state.enc"
        self.pending_path = root / "domain-state.pending"
        self.fernet = Fernet(encryption_key)
        if not self.state_path.exists():
            self._write({"records": {}, "links": {}, "attention": {}, "briefs": {}, "drafts": {}, "pilots": {}})

    def _read(self) -> dict[str, Any]:
        try:
            return json.loads(self.fernet.decrypt(self.state_path.read_bytes()).decode())
        except (InvalidToken, OSError, json.JSONDecodeError) as exc:
            raise DomainRejected("encrypted domain state is unavailable") from exc

    def _write(self, state: dict[str, Any]) -> None:
        self.pending_path.write_bytes(self.fernet.encrypt(json.dumps(state, sort_keys=True).encode()))
        self.pending_path.chmod(0o600)
        self.pending_path.replace(self.state_path)

    def create_record(self, person_id: str, space_id: str, domain: str, record_type: str,
                      facts: dict[str, Any], source_ids: list[str], evidence_status: str = "observed",
                      confidence: float = 1.0) -> dict[str, Any]:
        if record_type not in DOMAIN_TYPES.get(domain, frozenset()):
            raise DomainRejected("record type is not allowed for this domain")
        if not source_ids or not 0 <= confidence <= 1:
            raise DomainRejected("source provenance and valid confidence are required")
        if domain == "health" and record_type == "condition" and evidence_status == "inferred":
            if facts.get("clinical_status") == "confirmed":
                raise DomainRejected("inferred conditions cannot become confirmed diagnoses")
        if not space_id.startswith((f"private:{person_id}", f"health:{person_id}", f"finance:{person_id}", "shared:")):
            raise DomainRejected("destination space is outside the principal boundary")
        record_id = f"rec_{secrets.token_urlsafe(10)}"
        record = {"schema_version": "life-domain-record.v1", "record_id": record_id,
                  "person_id": person_id, "space_id": space_id, "domain": domain, "record_type": record_type,
                  "facts": facts, "source_ids": source_ids, "evidence_status": evidence_status,
                  "confidence": confidence, "shared": space_id.startswith("shared:"), "created_at": time.time()}
        state = self._read()
        state["records"][record_id] = record
        self._write(state)
        return record

    def records(self, person_id: str, domain: str | None = None) -> list[dict[str, Any]]:
        return [record for record in self._read()["records"].values()
                if record["person_id"] == person_id and (domain is None or record["domain"] == domain)]

    def delete_records_from_source(self, person_id: str, source_id: str) -> dict[str, int]:
        state = self._read()
        removed = {rid for rid, record in state["records"].items()
                   if record["person_id"] == person_id and source_id in record["source_ids"]}
        for record_id in removed:
            state["records"].pop(record_id, None)
        links = {lid for lid, link in state["links"].items()
                 if link["left_record_id"] in removed or link["right_record_id"] in removed}
        for link_id in links:
            state["links"].pop(link_id, None)
        attention = {aid for aid, item in state["attention"].items()
                     if any(rid in removed for rid in item.get("record_ids", []))}
        for item_id in attention:
            state["attention"].pop(item_id, None)
        self._write(state)
        return {"records": len(removed), "links": len(links), "attention": len(attention)}

    def share_record(self, person_id: str, record_id: str, target_space: str,
                     confirmed: bool) -> dict[str, Any]:
        state = self._read()
        source = state["records"].get(record_id)
        if not source or source["person_id"] != person_id:
            raise DomainRejected("record not found")
        if not confirmed or not target_space.startswith("shared:"):
            raise DomainRejected("sharing requires an explicit shared space and confirmation")
        return self.create_record(person_id, target_space, source["domain"], source["record_type"],
                                  source["facts"], source["source_ids"], source["evidence_status"],
                                  source["confidence"])

    def reconcile_product(self, person_id: str, label_record_id: str, receipt_record_id: str) -> dict[str, Any]:
        records = {r["record_id"]: r for r in self.records(person_id, "household")}
        label, receipt = records.get(label_record_id), records.get(receipt_record_id)
        if not label or not receipt:
            raise DomainRejected("household records not found")
        keys = ("manufacturer", "model", "serial", "upc")
        compared = {key: label["facts"].get(key) == receipt["facts"].get(key)
                    for key in keys if label["facts"].get(key) and receipt["facts"].get(key)}
        confidence = sum(compared.values()) / len(compared) if compared else 0.0
        return {"match": confidence >= 0.75, "confidence": confidence, "compared": compared,
                "uncertainty": "No shared exact identifiers" if not compared else None}

    def household_attention(self, person_id: str, recall_feed: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for record in self.records(person_id, "household"):
            facts = record["facts"]
            for field, label in (("return_by", "Return window"), ("warranty_until", "Warranty"),
                                 ("renewal_date", "Renewal"), ("maintenance_due", "Maintenance")):
                deadline = _parse_date(facts.get(field))
                if deadline and 0 <= (deadline - _today()).days <= 30:
                    items.append(self._attention(person_id, [record], f"{label} due {deadline.isoformat()}",
                                                 "medium", deadline))
        for recall in recall_feed or []:
            for record in self.records(person_id, "household"):
                exact = all(recall.get(key) and recall.get(key) == record["facts"].get(key)
                            for key in ("manufacturer", "model"))
                serial_ok = not recall.get("serials") or record["facts"].get("serial") in recall["serials"]
                if exact and serial_ok:
                    items.append(self._attention(person_id, [record], f"Exact product recall: {recall['title']}",
                                                 "high", _today()))
        return items

    def repair_brief(self, person_id: str, record_ids: list[str]) -> dict[str, Any]:
        records = self._owned_records(person_id, record_ids, "household")
        sources = sorted({sid for record in records for sid in record["source_ids"]})
        return self._brief(person_id, "Repair brief", records, sources,
                           "Draft only. No service appointment, purchase, or physical action was performed.")

    def procedure_brief(self, person_id: str, record_id: str) -> dict[str, Any]:
        records = self._owned_records(person_id, [record_id], "household")
        if records[0]["record_type"] not in {"procedure", "manual"}:
            raise DomainRejected("a procedure or manual record is required")
        return self._brief(person_id, "Household procedure", records, records[0]["source_ids"],
                           "Follow the cited manufacturer or owner procedure. No physical actuation was performed.")

    def normalize_fhir(self, person_id: str, source_id: str, resources: list[dict[str, Any]]) -> list[dict[str, Any]]:
        mapping = {"MedicationStatement": "medication", "MedicationRequest": "medication",
                   "Condition": "condition", "AllergyIntolerance": "allergy", "Immunization": "immunization",
                   "Observation": "observation", "Procedure": "procedure", "Encounter": "encounter",
                   "ServiceRequest": "referral", "CarePlan": "follow-up"}
        normalized = []
        for resource in resources:
            resource_type = mapping.get(resource.get("resourceType"))
            if not resource_type:
                continue
            facts = {key: resource[key] for key in ("id", "status", "code", "effectiveDateTime", "valueQuantity")
                     if key in resource}
            evidence_status = "confirmed" if resource_type == "condition" else "observed"
            normalized.append(self.create_record(person_id, f"health:{person_id}", "health", resource_type,
                                                 facts, [source_id], evidence_status, 1.0))
        return normalized

    def health_safety(self, person_id: str, text: str, source_ids: list[str]) -> dict[str, Any] | None:
        lowered = text.lower()
        for phrase, (severity, guidance) in URGENT_HEALTH_RULES.items():
            if phrase in lowered:
                return {"schema_version": "life-safety-outcome.v1", "outcome_id": f"safe_{secrets.token_urlsafe(8)}",
                        "person_id": person_id, "domain": "health", "severity": severity,
                        "guidance": guidance, "source_ids": source_ids,
                        "deterministic_rule": f"urgent-health:{phrase}", "dismisses_professional_care": False}
        return None

    def health_timeline(self, person_id: str) -> list[dict[str, Any]]:
        records = self.records(person_id, "health")
        return sorted(records, key=lambda record: str(record["facts"].get("date") or
                                                       record["facts"].get("effectiveDateTime") or ""))

    def reconcile_health(self, person_id: str) -> list[dict[str, Any]]:
        groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for record in self.records(person_id, "health"):
            key = (record["record_type"], str(record["facts"].get("code") or record["facts"].get("name") or ""))
            groups.setdefault(key, []).append(record)
        return [{"record_type": key[0], "identity": key[1], "record_ids": [r["record_id"] for r in records],
                 "contradiction": len({json.dumps(r["facts"], sort_keys=True) for r in records}) > 1}
                for key, records in groups.items() if len(records) > 1]

    def visit_brief(self, person_id: str, record_ids: list[str]) -> dict[str, Any]:
        records = self._owned_records(person_id, record_ids, "health")
        sources = sorted({sid for record in records for sid in record["source_ids"]})
        uncertainty = [r["record_id"] for r in records if r["confidence"] < 1 or r["evidence_status"] == "inferred"]
        return self._brief(person_id, "Visit preparation brief", records, sources,
                           f"Uncertain or inferred records: {', '.join(uncertainty) if uncertainty else 'none'}. This is not a diagnosis.")

    def health_trend(self, person_id: str, record_ids: list[str], value_field: str,
                     threshold: float | None = None) -> dict[str, Any]:
        records = self._owned_records(person_id, record_ids, "health")
        points = [{"record_id": record["record_id"], "date": record["facts"].get("date") or
                   record["facts"].get("effectiveDateTime"), "value": float(record["facts"][value_field]),
                   "source_ids": record["source_ids"]} for record in records if value_field in record["facts"]]
        points.sort(key=lambda point: str(point["date"] or ""))
        return {"value_field": value_field, "points": points, "rule_selected_by_person": True,
                "threshold": threshold, "threshold_crossings": [point for point in points
                                                                  if threshold is not None and point["value"] >= threshold],
                "interpretation": "descriptive trend only; not a diagnosis"}

    def emergency_card(self, person_id: str, record_ids: list[str], confirmed: bool) -> dict[str, Any]:
        if not confirmed:
            raise DomainRejected("emergency presentation requires explicit selection")
        records = self._owned_records(person_id, record_ids, "health")
        allowed = {"medication", "allergy", "condition", "instruction"}
        return {"person_id": person_id, "records": [r for r in records if r["record_type"] in allowed],
                "selective": True, "expires_after_session": True}

    def finance_reconcile(self, person_id: str, statement_total: float, transaction_record_ids: list[str],
                          tolerance: float = 0.01) -> dict[str, Any]:
        records = self._owned_records(person_id, transaction_record_ids, "finance")
        total = round(sum(float(r["facts"].get("amount", 0)) for r in records), 2)
        difference = round(statement_total - total, 2)
        return {"statement_total": statement_total, "transaction_total": total, "difference": difference,
                "tolerance": tolerance, "reconciled": abs(difference) <= tolerance,
                "source_ids": sorted({sid for r in records for sid in r["source_ids"]})}

    def finance_attention(self, person_id: str) -> list[dict[str, Any]]:
        transactions = [r for r in self.records(person_id, "finance") if r["record_type"] == "transaction"]
        items: list[dict[str, Any]] = []
        seen: dict[tuple[str, float, str], dict[str, Any]] = {}
        for record in transactions:
            facts = record["facts"]
            key = (str(facts.get("merchant")), float(facts.get("amount", 0)), str(facts.get("date")))
            if key in seen:
                items.append(self._attention(person_id, [seen[key], record], "Possible duplicate charge", "medium", _today()))
            seen[key] = record
        subscriptions: dict[str, list[dict[str, Any]]] = {}
        for record in transactions:
            merchant = str(record["facts"].get("merchant", ""))
            subscriptions.setdefault(merchant, []).append(record)
        for merchant, records in subscriptions.items():
            ordered = sorted(records, key=lambda r: str(r["facts"].get("date", "")))
            if len(ordered) >= 2:
                previous, current = map(lambda r: abs(float(r["facts"].get("amount", 0))), ordered[-2:])
                if previous and current > previous * 1.05:
                    items.append(self._attention(person_id, [ordered[-1]],
                                                 f"{merchant} increased from {previous:.2f} to {current:.2f}", "low", _today()))
        for record in self.records(person_id, "finance"):
            facts = record["facts"]
            if record["record_type"] in {"refund", "reimbursement"}:
                expected = _parse_date(facts.get("expected_by"))
                if expected and expected < _today() and facts.get("received") is not True:
                    items.append(self._attention(person_id, [record], "Expected refund or reimbursement is overdue",
                                                 "medium", expected))
            if record["record_type"] in {"subscription", "obligation", "recurring-event"}:
                deadline = _parse_date(facts.get("renewal_date") or facts.get("due_date"))
                if deadline and 0 <= (deadline - _today()).days <= 14:
                    items.append(self._attention(person_id, [record], "Recurring obligation needs review",
                                                 "low", deadline))
        return items

    def cash_flow_forecast(self, person_id: str, horizon_days: int = 30) -> dict[str, Any]:
        records = self.records(person_id, "finance")
        balances = [float(r["facts"].get("amount", 0)) for r in records if r["record_type"] == "balance"]
        recurring = [float(r["facts"].get("amount", 0)) for r in records if r["record_type"] in {"obligation", "recurring-event"}]
        observed = sum(balances) + sum(recurring)
        spread = max(abs(observed) * 0.1, 25.0)
        return {"horizon_days": horizon_days, "range": [round(observed - spread, 2), round(observed + spread, 2)],
                "midpoint": round(observed, 2), "confidence": 0.65 if recurring else 0.3,
                "evidence_status": "inferred", "assumptions": ["Observed balances and recurring records only"],
                "source_ids": sorted({sid for r in records for sid in r["source_ids"]})}

    def household_finance_view(self, person_id: str, contribution_record_ids: list[str]) -> dict[str, Any]:
        records = self._owned_records(person_id, contribution_record_ids, "finance")
        explicit = [r for r in records if r["facts"].get("include_in_household") is True]
        return {"total": round(sum(float(r["facts"].get("amount", 0)) for r in explicit), 2),
                "included_record_ids": [r["record_id"] for r in explicit], "implicit_records_included": 0}

    def weekly_finance_brief(self, person_id: str) -> dict[str, Any]:
        items = self.finance_attention(person_id)
        prioritized = sorted(items, key=lambda item: {"high": 3, "medium": 2, "low": 1}.get(item["risk"], 0), reverse=True)[:5]
        records = [r for r in self.records(person_id, "finance") if any(r["record_id"] in i["record_ids"] for i in prioritized)]
        return self._brief(person_id, "Weekly financial attention", records,
                           sorted({sid for item in prioritized for sid in item["source_ids"]}),
                           f"{len(prioritized)} exception(s) prioritized. Routine activity is suppressed.")

    def draft(self, person_id: str, action_type: str, record_ids: list[str], recipients: list[str],
              disclosed_fields: list[str], content: str) -> dict[str, Any]:
        records = self._owned_records(person_id, record_ids)
        prohibited = {"transfer_funds", "trade_security", "open_credit", "file_tax_return", "change_medication",
                      "diagnose", "physical_actuation", "purchase", "schedule_service"}
        if action_type in prohibited:
            raise DomainRejected("the requested action is prohibited")
        draft = {"schema_version": "life-action-draft.v1", "draft_id": f"draft_{secrets.token_urlsafe(8)}",
                 "person_id": person_id, "action_type": action_type,
                 "domain_record_ids": [r["record_id"] for r in records], "recipients": recipients,
                 "disclosed_fields": disclosed_fields, "content": content, "status": "draft", "executable": False}
        state = self._read()
        state["drafts"][draft["draft_id"]] = draft
        self._write(state)
        return draft

    def link(self, person_id: str, left_record_id: str, right_record_id: str, purpose: str,
             allowed_fields: list[str], recipients: list[str], approved: bool) -> dict[str, Any]:
        records = self._owned_records(person_id, [left_record_id, right_record_id])
        if not approved or not purpose.strip() or not allowed_fields:
            raise DomainRejected("purpose, minimized fields, and person approval are required")
        if any(record["shared"] for record in records) and any(not record["shared"] for record in records):
            if recipients:
                raise DomainRejected("linking private and shared records cannot widen disclosure")
        link = {"schema_version": "life-domain-link.v1", "link_id": f"link_{secrets.token_urlsafe(8)}",
                "person_id": person_id, "left_record_id": left_record_id, "right_record_id": right_record_id,
                "purpose": purpose, "allowed_fields": allowed_fields, "recipient_ids": recipients,
                "approved_by_person": True, "created_at": time.time()}
        state = self._read()
        state["links"][link["link_id"]] = link
        self._write(state)
        return link

    def unlink(self, person_id: str, link_id: str) -> None:
        state = self._read()
        link = state["links"].get(link_id)
        if not link or link["person_id"] != person_id:
            raise DomainRejected("link not found")
        state["links"].pop(link_id)
        self._write(state)

    def transition_template(self, transition: str) -> dict[str, Any]:
        templates = {
            "moving": ["housing", "utilities", "insurance", "records", "communications", "deadlines"],
            "caregiving": ["care commitments", "appointments", "benefits", "contingency", "communications"],
            "job-change": ["benefits", "insurance", "retirement", "credentials", "tax records"],
            "bereavement": ["immediate support", "documents", "benefits", "accounts", "communications"],
            "disaster-recovery": ["safety", "temporary housing", "insurance claim", "records", "continuity"],
        }
        steps = templates.get(transition)
        if not steps:
            raise DomainRejected("unsupported life transition template")
        return {"transition": transition, "steps": steps, "status": "draft", "requires_person_approval": True}

    def cross_domain_packet(self, person_id: str, link_ids: list[str], packet_type: str,
                            recipients: list[str]) -> dict[str, Any]:
        state = self._read()
        links = [state["links"].get(link_id) for link_id in link_ids]
        if not links or any(not link or link["person_id"] != person_id for link in links):
            raise DomainRejected("approved links are required for a cross-domain packet")
        if packet_type not in {"benefits", "claim", "care-coordination", "continuity", "emergency-plan"}:
            raise DomainRejected("unsupported cross-domain packet")
        fields = sorted({field for link in links for field in link["allowed_fields"]})
        record_ids = sorted({record_id for link in links
                             for record_id in (link["left_record_id"], link["right_record_id"])})
        return self.draft(person_id, f"{packet_type}-packet", record_ids, recipients, fields,
                          f"Draft {packet_type} packet using only approved links and fields: {', '.join(fields)}")

    def attention_inbox(self, person_id: str, goals: list[str] | None = None) -> list[dict[str, Any]]:
        items = self.household_attention(person_id) + self.finance_attention(person_id)
        goal_words = {word.lower() for goal in goals or [] for word in goal.split()}
        risk_score = {"high": 100, "medium": 60, "low": 30, "informational": 10}
        for item in items:
            deadline = _parse_date(item.get("deadline"))
            urgency = max(0, 30 - (deadline - _today()).days) if deadline else 0
            relevance = sum(word in item["summary"].lower() for word in goal_words) * 10
            item["rank_score"] = risk_score.get(item["risk"], 0) + urgency + relevance
            item["ranking_basis"] = {"risk": item["risk"], "deadline": item.get("deadline"),
                                     "goal_terms_matched": relevance // 10, "burden": "one review"}
        return sorted(items, key=lambda item: item["rank_score"], reverse=True)

    def pilot_report(self, cohort: str, opted_in: bool, measurements: dict[str, float],
                     boundary_incidents: int = 0, unsafe_actions: int = 0) -> dict[str, Any]:
        if cohort == "opt-in-human" and not opted_in:
            raise DomainRejected("human pilot participation requires opt-in")
        targets = {"time_to_first_value_minutes": 10, "setup_completion_percent": 80,
                   "extraction_precision_percent": 90, "attention_precision_percent": 80,
                   "brief_usefulness_percent": 75, "notification_burden_per_week": 5,
                   "privacy_comprehension_percent": 90, "deletion_success_percent": 100,
                   "time_returned_minutes": 15}
        lower_is_better = {"time_to_first_value_minutes", "notification_burden_per_week"}
        metrics = []
        for name, target in targets.items():
            value = float(measurements.get(name, math.inf if name in lower_is_better else 0))
            metrics.append({"name": name, "value": value,
                            "unit": "minutes" if "minutes" in name else ("items" if "burden" in name else "percent"),
                            "target": target, "passed": value <= target if name in lower_is_better else value >= target})
        report = {"schema_version": "life-operations-pilot.v1", "pilot_id": f"pilot_{secrets.token_urlsafe(8)}",
                  "cohort": cohort, "opted_in": opted_in, "metrics": metrics,
                  "boundary_incidents": boundary_incidents, "unsafe_actions": unsafe_actions,
                  "supported_package_decision": "hold", "generated_at": time.time(),
                  "gate_passed": all(m["passed"] for m in metrics) and boundary_incidents == 0 and unsafe_actions == 0}
        state = self._read()
        state["pilots"][report["pilot_id"]] = report
        self._write(state)
        return report

    def _owned_records(self, person_id: str, record_ids: list[str], domain: str | None = None) -> list[dict[str, Any]]:
        state = self._read()
        records = [state["records"].get(record_id) for record_id in record_ids]
        if not records or any(not r or r["person_id"] != person_id or (domain and r["domain"] != domain) for r in records):
            raise DomainRejected("one or more records are unavailable in this principal and domain")
        return records  # type: ignore[return-value]

    def _attention(self, person_id: str, records: list[dict[str, Any]], summary: str,
                   risk: str, deadline: date) -> dict[str, Any]:
        item = {"schema_version": "attention-item.v1", "item_id": f"attn_{secrets.token_urlsafe(8)}",
                "person_id": person_id, "summary": summary,
                "source_ids": sorted({sid for record in records for sid in record["source_ids"]}),
                "record_ids": [record["record_id"] for record in records], "risk": risk,
                "deadline": deadline.isoformat(), "requires_person": True}
        state = self._read()
        state["attention"][item["item_id"]] = item
        self._write(state)
        return item

    def _brief(self, person_id: str, title: str, records: list[dict[str, Any]], source_ids: list[str],
               note: str) -> dict[str, Any]:
        brief = {"schema_version": "brief.v1", "brief_id": f"brief_{secrets.token_urlsafe(8)}",
                 "person_id": person_id, "title": title, "record_ids": [r["record_id"] for r in records],
                 "source_ids": source_ids, "citations": [{"record_id": r["record_id"], "source_ids": r["source_ids"]}
                                                         for r in records],
                 "note": note, "generated_at": time.time()}
        state = self._read()
        state["briefs"][brief["brief_id"]] = brief
        self._write(state)
        return brief
