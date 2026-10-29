from concurrent.futures import ThreadPoolExecutor
import time
from cryptography.fernet import Fernet
from src.domain_operations import LifeDomainStore


def test_concurrent_health_records_are_not_lost(tmp_path, monkeypatch):
    key = Fernet.generate_key()
    stores = [LifeDomainStore(tmp_path, key) for _ in range(6)]
    original = LifeDomainStore._read
    def delayed(self):
        state = original(self)
        time.sleep(0.01)
        return state
    monkeypatch.setattr(LifeDomainStore, "_read", delayed)
    def create(i):
        return stores[i % 6].create_record("synthetic-alice", "health:synthetic-alice", "health", "observation",
                                         {"synthetic": True, "value": i}, [f"synthetic-source-{i}"])
    with ThreadPoolExecutor(max_workers=6) as pool:
        records = list(pool.map(create, range(18)))
    restored = LifeDomainStore(tmp_path, key)
    assert {r["record_id"] for r in restored.records("synthetic-alice")} == {r["record_id"] for r in records}
    assert restored.records("synthetic-bob") == []
