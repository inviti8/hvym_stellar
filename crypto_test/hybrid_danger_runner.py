#!/usr/bin/env python3
"""
Runner for HvymStellarHybridDangerHarness tests.
Tests the dangerous hybrid construction vulnerabilities.
"""

from HvymStellarHybridDangerHarness import HvymStellarHybridDangerHarness


def main():
    print("=== HYBRID DANGER HARNESS TESTS ===")
    print("Testing dangerous hybrid construction vulnerabilities...")
    print()
    
    harness = HvymStellarHybridDangerHarness()
    
    tests = [
        harness.test_derived_key_valid_point_probability,
        harness.test_hybrid_shared_secret_entropy_collapse,
        harness.test_hybrid_roundtrip_with_zero_shared_secret,
        harness.test_hybrid_vs_proper_symmetric_key_strength,
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
    
    print(f"=== SUMMARY ===")
    print(f"Tests passed: {passed}/{total}")
    if critical_failures > 0:
        print(f"⚠️  CRITICAL FAILURES: {critical_failures}")
        print("🚨 HYBRID CONSTRUCTION HAS SERIOUS SECURITY ISSUES!")
    else:
        print("✅ No critical issues detected")
    
    return 0 if critical_failures == 0 else 1


if __name__ == "__main__":
    exit(main())
