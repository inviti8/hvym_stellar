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
        harness.test_wrong_receiver_cannot_decrypt,
        harness.test_salt_tampering,
        harness.test_truncation_resistance,
        harness.test_garbage_extension,
        harness.test_mode_isolation,
        harness.test_random_garbage_decryption,
        harness.test_replay_and_multisession,
        harness.test_large_message,
    ]

    results = [test() for test in tests]

    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(f"[{status}] {r.name} ({r.severity})")
        print(f"    {r.explanation}")

if __name__ == "__main__":
    run_harness()