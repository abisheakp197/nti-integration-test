import pytest


@pytest.mark.real_world
def test_real_world_pypi_packages_imported() -> None:
    """Verify all 5 core NTI packages installed from public PyPI can be imported."""
    import nti_badge
    import nti_scanner
    import ube_foundation
    from attacks._registry import get_all_attacks
    from runner.run_benchmark import run_all

    # 1. ube-foundation
    keypair = ube_foundation.PqcKeyPair()
    assert hasattr(keypair, "sign")
    assert hasattr(keypair, "verify")

    # 2. nti-attack-library
    attacks = get_all_attacks()
    assert len(attacks) > 0

    # 3. nti-scanner
    assert hasattr(nti_scanner, "scanner")

    # 4. nti-benchmark
    assert callable(run_all)

    # 5. nti-badge
    assert hasattr(nti_badge, "render_badge_svg")
    assert hasattr(nti_badge, "parse_certificate")
