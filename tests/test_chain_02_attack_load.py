from attacks._registry import get_all_attacks


def test_chain_02_get_all_attacks_count() -> None:
    """Verify get_all_attacks returns all registered attacks in the attack library."""
    attacks = get_all_attacks()
    assert len(attacks) >= 10
    assert len(attacks) == 11


def test_chain_02_attack_categories() -> None:
    """Verify at least 6 distinct attack categories are present in the library."""
    attacks = get_all_attacks()
    categories = {a.category for a in attacks}
    assert len(categories) == 6
    expected_categories = {"multi_agent", "infrastructure", "tool", "capability", "prompt", "audit"}
    assert categories == expected_categories


def test_chain_02_attack_required_fields() -> None:
    """Verify each attack object exposes required metadata attributes and callable methods."""
    attacks = get_all_attacks()
    required_attrs = [
        "id",
        "name",
        "category",
        "severity",
        "cwe",
        "pillar",
        "description",
        "real_world",
        "detection_rule",
        "remediation",
        "build_payload",
        "check",
        "run",
        "to_dict",
    ]

    for attack in attacks:
        for attr in required_attrs:
            assert hasattr(attack, attr), f"Attack {attack} missing required attribute {attr}"
        assert isinstance(attack.id, str) and len(attack.id) > 0
        assert isinstance(attack.name, str) and len(attack.name) > 0
        assert isinstance(attack.category, str) and len(attack.category) > 0
        assert callable(attack.build_payload)
        assert callable(attack.check)
        assert callable(attack.run)
        assert callable(attack.to_dict)
