import json
import os
import tempfile
from pathlib import Path
from typing import Any

import pytest


class ResilientKVStore:
    """Persistent JSON file store with automatic corruption detection and rebuild recovery."""

    def __init__(self, store_path: Path) -> None:
        self.store_path = store_path
        self.data: dict[str, Any] = {}
        self._load_or_rebuild()

    def _load_or_rebuild(self) -> None:
        if not self.store_path.exists():
            self.data = {}
            self.flush()
            return

        try:
            content = self.store_path.read_text(encoding="utf-8")
            self.data = json.loads(content)
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            # Corruption detected: Rebuild state cleanly
            self.data = {}
            self.flush()

    def set(self, key: str, value: Any) -> None:
        self.data[key] = value
        self.flush()

    def get(self, key: str) -> Any:
        return self.data.get(key)

    def flush(self) -> None:
        temp_path = self.store_path.with_suffix(".tmp")
        temp_path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        temp_path.replace(self.store_path)


@pytest.mark.chaos
def test_chaos_corrupt_store_detection_and_rebuild() -> None:
    """Corrupt local store file and verify store detects corruption and rebuilds cleanly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store_file = Path(tmpdir) / "registry_kv.json"

        # 1. Initialize store and populate valid keys
        store = ResilientKVStore(store_file)
        store.set("cert-001", {"score": 95, "status": "valid"})
        assert store.get("cert-001")["score"] == 95

        # 2. Corrupt local store file with binary garbage
        store_file.write_bytes(os.urandom(512))

        # 3. Reload store -> must detect corruption, survive without crashing, and rebuild
        rebuilt_store = ResilientKVStore(store_file)
        assert rebuilt_store.data == {}

        # 4. Prove store is fully functional and can accept new valid writes after rebuild
        rebuilt_store.set("cert-002", {"score": 98, "status": "rebuilt"})
        assert rebuilt_store.get("cert-002")["status"] == "rebuilt"
