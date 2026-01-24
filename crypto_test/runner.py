from hvymStellarAdversarialHarness import HvymStellarAdversarialHarness

def run_harness():
    harness = HvymStellarAdversarialHarness()
    tests = [
        harness.test_key_separation,
        harness.test_malleability,
        harness.test_known_plaintext,
        harness.test_nonce_control,
        harness.test_asymmetric_key_separation,
        harness.test_asymmetric_malleability,
        harness.test_key_derivation_sanity,
        harness.test_construction_mapping,
        harness.test_security_claims,
    ]

    results = [test() for test in tests]

    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(f"[{status}] {r.name} ({r.severity})")
        print(f"    {r.explanation}")

if __name__ == "__main__":
    run_harness()
