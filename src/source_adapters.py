"""Fixed, reviewed synthetic format adapters. No dynamic code/package loading."""
import csv
import io
import re
from datetime import date
from types import MappingProxyType
from health_source_adapter import HealthAdapter
from source_contracts import PilotDenied, decode_unique, digest


def evidence(person, wid, position, sha, parser, domain, facts, status='observed'):
    return dict(record_id=f'{wid}:{position}', person_id=person, domain=domain,
                record_type='source-extract', shared=False, evidence_status=status,
                facts=facts, source_ids=[wid], provenance=dict(
                    envelope_version='source-evidence.v1', parser_version=parser,
                    source_sha256=sha, row_pointer=f'/rows/{position}', fact_sha256=digest(facts)))


class StatementAdapter:
    identifier = 'synthetic-statement-csv.v1'
    purpose = 'finance.statement.review'
    def extract(self, raw, person, wid, stamp, sha):
        marker, _, text = raw.decode('utf-8').partition('\n')
        if marker.rstrip('\r') != self.identifier:
            raise PilotDenied('explicit synthetic statement required')
        reader = csv.DictReader(io.StringIO(text), strict=True)
        if reader.fieldnames != ['id', 'date', 'amount_minor', 'currency', 'description']:
            raise PilotDenied('statement columns unsupported')
        records, seen, count = [], {}, 0
        for position, row in enumerate(reader):
            count += 1
            if count > 500 or None in row or any(v is None for v in row.values()):
                raise PilotDenied('bounded complete rows required')
            if not 1 <= len(row['id']) <= 128 or len(row['description']) > 500:
                raise PilotDenied('invalid statement row')
            if date.fromisoformat(row['date']).isoformat() != row['date']:
                raise PilotDenied('canonical date required')
            if not re.fullmatch(r'-?(0|[1-9][0-9]{0,12})', row['amount_minor']):
                raise PilotDenied('integer minor units required')
            if row['currency'] not in {'USD', 'EUR', 'GBP'}:
                raise PilotDenied('unqualified currency units')
            if row['id'] in seen:
                if seen[row['id']] != row: raise PilotDenied('conflicting statement identifier')
                continue
            seen[row['id']] = row
            facts = dict(original_payload=row, amount_minor=int(row['amount_minor']),
                         currency=row['currency'], source_day=row['date'], ingested_at=stamp,
                         synthetic=True, consent_id=wid, kind='statement',
                         balance=None, balance_missing_reason='No balance supplied')
            records.append(evidence(person, wid, position, sha, self.identifier, 'finance', facts))
        if not records: raise PilotDenied('no statement rows')
        return records, count
    def present(self, records):
        result = []
        for currency in sorted({r['facts']['currency'] for r in records}):
            rows = [r for r in records if r['facts']['currency'] == currency]
            total = sum(r['facts']['amount_minor'] for r in rows)
            result.append(dict(metric='statement_total', text=f'Supplied entries total {total} {currency} minor units. Balance unknown; no balance supplied.', record_ids=[r['record_id'] for r in rows]))
        return result, 'Synthetic statement entries, not verified bank activity or financial advice.'


class UnfamiliarAdapter:
    identifier = 'synthetic-unfamiliar-document.v1'
    purpose = 'document.review'
    def extract(self, raw, person, wid, stamp, sha):
        value = decode_unique(raw)
        if (not isinstance(value, dict) or set(value) != {'schema_version','synthetic','text'}
                or value['schema_version'] != self.identifier or value['synthetic'] is not True
                or not isinstance(value['text'], str) or not 1 <= len(value['text']) <= 10000):
            raise PilotDenied('bounded synthetic unfamiliar document required')
        facts = dict(original_payload=value, synthetic=True, consent_id=wid,
                     ingested_at=stamp, kind='uninterpreted_source', claims=[],
                     unknowns=['Document meaning, obligations and requested actions are not established.'])
        record = evidence(person, wid, 0, sha, self.identifier, 'document', facts, 'uninterpreted')
        record['provenance']['row_pointer'] = '/text'
        return [record], 1
    def present(self, records):
        return [dict(metric='unknown', text='Source retained for review. Meaning and obligations are unknown; no action has been inferred.', record_ids=[r['record_id'] for r in records])], 'Untrusted document text is evidence, never an instruction or permission.'


ADAPTERS = MappingProxyType({adapter.identifier: adapter for adapter in (HealthAdapter(), StatementAdapter(), UnfamiliarAdapter())})
