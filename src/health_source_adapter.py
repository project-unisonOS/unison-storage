"""Health-specific validation and descriptive presentation for the source contract."""
from health_pilot import Export, decode_unique, records_from_export

class HealthAdapter:
    identifier = "synthetic-health-export.v1"
    purpose = "wellness.summary"
    def extract(self, raw, person, wid, stamp, sha):
        export = Export.model_validate(decode_unique(raw))
        return records_from_export(raw, person, wid, wid, stamp, sha), len(export.observations)
    def present(self, records):
        summary = []
        for metric, label in (("sleep_duration", "Sleep duration"), ("steps", "Steps")):
            values = [r for r in records if r["facts"]["metric"] == metric and r["facts"]["kind"] == "measurement"]
            if not values:
                summary.append({"metric": metric, "text": f"{label}: unknown; no measurement supplied.", "record_ids": []})
                continue
            day = max(r["facts"]["source_day"] for r in values)
            current = [r for r in values if r["facts"]["source_day"] == day]
            latest = {}
            for r in current:
                key = (r["facts"]["source"], r["facts"]["upstream_id"])
                if key not in latest or r["facts"]["revision"] > latest[key]["facts"]["revision"]: latest[key] = r
            current = list(latest.values())
            if len(current) != 1:
                text = f"{label} on {day}: unknown; multiple measurements need review."
            else:
                fact = current[0]["facts"]
                text = (f"{label} on {day}: {fact['value']:g} {fact['unit']}." if fact["quality"] == "valid"
                        else f"{label} on {day}: unknown; {fact['missing_reason']}.")
            summary.append({"metric": metric, "text": text, "record_ids": [r["record_id"] for r in current]})
        return summary, "Descriptive synthetic measurements only. No diagnosis or health recommendation."
