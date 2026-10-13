from attacks._registry import get_all_attacks


def test_chain_02_attack_load():
    """Verify loading attacks from nti-attack-library."""
    attacks = get_all_attacks()
    assert len(attacks) >= 10, f"Expected at least 10 attacks, found {len(attacks)}"

    categories = set()
    for attack in attacks:
        assert hasattr(attack, "id"), "Attack missing 'id' attribute"
        assert hasattr(attack, "category"), "Attack missing 'category' attribute"
        categories.add(attack.category)

        has_payload = hasattr(attack, "build_payload") or hasattr(attack, "payload")
        assert has_payload, f"Attack {attack.id} missing payload builder or attribute"

    expected_categories = {"prompt", "tool", "capability", "audit", "multi_agent", "infrastructure"}
    assert expected_categories.issubset(categories), f"Missing categories: {expected_categories - categories}"
    assert len(categories) == 6
