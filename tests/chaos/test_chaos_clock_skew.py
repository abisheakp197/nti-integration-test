import json
from datetime import UTC, datetime


def verify_timestamp_within_window(
    issued_at_iso: str, now_dt: datetime, max_skew_seconds: int = 300
) -> bool:
    """Verify certificate timestamp is within ±max_skew_seconds tolerance window."""
    try:
        issued_dt = datetime.fromisoformat(issued_at_iso)
        delta_seconds = abs((now_dt - issued_dt).total_seconds())
        return delta_seconds <= max_skew_seconds
    except ValueError:
        return False


def test_chaos_clock_skew_tolerance() -> None:
    """Test signature verification and timestamp skew check with ±5 minutes clock skew."""
    import ube_foundation

    keypair = ube_foundation.PqcKeyPair()
    now_utc = datetime.now(UTC)

    # 1. Signature verification is invariant to wall-clock time
    payload = {"agent": "skew-agent", "issued_at": now_utc.isoformat()}
    msg_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    sig = keypair.sign(msg_bytes)

    assert keypair.verify(msg_bytes, sig) is True

    # 2. Test timestamp validation within ±5 mins skew (300 s)
    assert verify_timestamp_within_window(now_utc.isoformat(), now_utc) is True

    # 3. +4 minutes skew (within tolerance)
    time_plus_4m = datetime.fromtimestamp(now_utc.timestamp() + 240, tz=UTC)
    assert verify_timestamp_within_window(payload["issued_at"], time_plus_4m, max_skew_seconds=300) is True

    # 4. -4 minutes skew (within tolerance)
    time_minus_4m = datetime.fromtimestamp(now_utc.timestamp() - 240, tz=UTC)
    assert verify_timestamp_within_window(payload["issued_at"], time_minus_4m, max_skew_seconds=300) is True

    # 5. Out-of-bounds skew (+10 minutes skew) correctly flagged
    time_plus_10m = datetime.fromtimestamp(now_utc.timestamp() + 600, tz=UTC)
    assert verify_timestamp_within_window(payload["issued_at"], time_plus_10m, max_skew_seconds=300) is False
