from HvymStellarTokenHarness import HvymStellarTokenHarness

def run_token_harness():
    harness = HvymStellarTokenHarness()
    tests = [
        harness.test_access_token_valid,
        harness.test_access_token_wrong_caveat,
        harness.test_access_token_wrong_receiver,
        harness.test_access_token_expired,
        harness.test_secret_token_roundtrip,
        harness.test_secret_token_wrong_receiver,
        harness.test_token_tampering,
        harness.test_token_caveat_escalation,
        harness.test_token_location_tampering,
        harness.test_token_canonical_serialization,
        harness.test_token_checksum_tampering,
    ]

    results = [test() for test in tests]

    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(f"[{status}] {r.name} ({r.severity})")
        print(f"    {r.explanation}")

if __name__ == "__main__":
    run_token_harness()
