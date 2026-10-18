import tempfile
from pathlib import Path
from typing import Any

import pytest
import ube_foundation


def safe_save_report(report_path: Path, data: dict[str, Any]) -> tuple[bool, str]:
    """Write report to file with disk space safety checks."""
    try:
        temp_file = report_path.with_suffix(".tmp")
        temp_file.write_text(str(data), encoding="utf-8")
        temp_file.replace(report_path)
        return True, "SUCCESS"
    except OSError as exc:
        if exc.errno == 28 or "space" in str(exc).lower():
            # Graceful disk full handling
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except OSError:
                    pass
            return False, "ERROR_DISK_FULL"
        raise


@pytest.mark.chaos
def test_chaos_disk_full_simulation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulate full disk during report export and verify graceful error handling."""
    keypair = ube_foundation.PqcKeyPair()
    report = {"id": "report-disk-full-test", "issuer": keypair.public_key_hex()}

    def mock_write_text_disk_full(*args: Any, **kwargs: Any) -> int:
        raise OSError(28, "No space left on device")

    with tempfile.TemporaryDirectory() as tmpdir:
        report_file = Path(tmpdir) / "report.json"

        # Monkeypatch Path.write_text to simulate ENOSPC disk full
        monkeypatch.setattr(Path, "write_text", mock_write_text_disk_full)

        ok, msg = safe_save_report(report_file, report)
        assert ok is False
        assert msg == "ERROR_DISK_FULL"
        assert not report_file.exists()
