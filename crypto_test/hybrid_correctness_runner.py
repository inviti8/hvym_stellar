#!/usr/bin/env python3
"""
Runner for HvymStellarHybridCorrectnessHarness tests.
Tests the conceptual correctness issues with hybrid construction.
"""

from HvymStellarHybridCorrectnessHarness import HvymStellarHybridCorrectnessHarness


def main():
    print("=== HYBRID CORRECTNESS HARNESS TESTS ===")
    print("Testing hybrid construction conceptual correctness issues...")
    print()
    
    harness = HvymStellarHybridCorrectnessHarness()
    
    tests = [
        harness.test_pynacl_version_and_point_validation_behavior,
        harness.test_hybrid_mode_fails_on_invalid_derived_key,
        harness.test_hybrid_construction_is_broken_by_design,
        harness.test_sha256_output_is_not_a_curve25519_point_distribution,
    ]
    
    results = [test() for test in tests]
    
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(f"[{status}] {r.name} ({r.severity})")
        print(f"    {r.explanation}")
        print()
    
    # Summary
    passed = sum(1 for r in results if r.passed)
    total = len(results)
    critical_failures = sum(1 for r in results if not r.passed and r.severity == "CRITICAL")
    warnings = sum(1 for r in results if not r.passed and r.severity == "WARNING")
    
    print(f"=== SUMMARY ===")
    print(f"Tests passed: {passed}/{total}")
    if critical_failures > 0:
        print(f"🚨 CRITICAL ISSUES: {critical_failures}")
        print("⚠️  HYBRID CONSTRUCTION HAS SERIOUS DESIGN FLAWS!")
    elif warnings > 0:
        print(f"⚠️  WARNINGS: {warnings}")
        print("🔍 HYBRID CONSTRUCTION HAS DESIGN CONCERNS")
    else:
        print("✅ No correctness issues detected")
    
    print("\n=== RECOMMENDATION ===")
    print("🎯 Use SecretBox(derived_key) instead of Box(PrivateKey(derived), PublicKey(derived))")
    print("📚 This follows proper cryptographic design patterns")
    
    return 0 if critical_failures == 0 else 1


if __name__ == "__main__":
    exit(main())
