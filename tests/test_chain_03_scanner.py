import tempfile
from pathlib import Path
from nti_scanner.scanner import scan_directory


def test_chain_03_scanner_on_real_target():
    """Verify nti-scanner can scan a target directory and produce findings."""
    with tempfile.TemporaryDirectory() as tmpdir:
        target_file = Path(tmpdir) / "sample.py"
        target_file.write_text("import os\nos.system('echo test')\n")

        scan_result = scan_directory(Path(tmpdir))
        assert scan_result is not None
        assert hasattr(scan_result, "findings")
