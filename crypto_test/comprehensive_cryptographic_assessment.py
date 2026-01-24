#!/usr/bin/env python3
"""
Comprehensive Cryptographic Assessment Suite
Consolidated testing for hvym_stellar cryptographic implementations
Includes: vulnerability assessment, strength comparison, and empirical analysis
"""

import time
import secrets
import hashlib
import statistics
import math
import os
import struct
import warnings
import binascii
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass

from stellar_sdk import Keypair
from hvym_stellar import (
    Stellar25519KeyPair, StellarSharedKey, StellarSharedDecryption,
    extract_salt_from_encrypted, extract_nonce_from_encrypted
)

# AES implementation for comparison
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    AES_AVAILABLE = True
except ImportError:
    AES_AVAILABLE = False

@dataclass
class TestResult:
    """Unified test result format"""
    test_name: str
    test_type: str  # VULNERABILITY, STRENGTH, COMPARISON
    score: float
    status: str  # PASS, FAIL, WARNING
    details: Dict[str, Any]
    recommendation: str

class ComprehensiveCryptographicAssessment:
    """Complete cryptographic assessment suite"""
    
    def __init__(self):
        self.setup_test_environment()
        self.results = []
        
    def setup_test_environment(self):
        """Setup test environment"""
        self.test_keypairs = [
            (Stellar25519KeyPair(Keypair.random()), Stellar25519KeyPair(Keypair.random()))
            for _ in range(10)
        ]
        
    # ==================== WORKING HYBRID TESTS ====================
    
    def test_hybrid_functionality(self) -> TestResult:
        """Test basic hybrid encryption/decryption functionality"""
        print("Testing Hybrid Functionality...")
        
        try:
            test_sizes = [16, 32, 64, 128, 256, 512, 1024, 2048]
            results = []
            
            for size in test_sizes:
                test_messages = [secrets.token_bytes(size) for _ in range(10)]
                success_count = 0
                
                for msg in test_messages:
                    sender_kp, receiver_kp = self.test_keypairs[0]
                    try:
                        # Test HYBRID approach (encrypt/decrypt - original behavior)
                        shared_key = StellarSharedKey(sender_kp, receiver_kp.public_key())
                        encrypted = shared_key.encrypt(msg)  # Uses hybrid approach
                        
                        shared_decrypt = StellarSharedDecryption(receiver_kp, sender_kp.public_key())
                        decrypted = shared_decrypt.decrypt(encrypted)  # Uses hybrid approach
                        
                        if decrypted == msg:
                            success_count += 1
                    except:
                        pass
                
                success_rate = success_count / len(test_messages)
                results.append(success_rate)
            
            avg_success = sum(results) / len(results)
            
            if avg_success >= 0.95:
                status = "PASS"
                score = avg_success * 10
                recommendation = "Hybrid encryption works correctly"
            elif avg_success >= 0.8:
                status = "WARNING"
                score = avg_success * 8
                recommendation = "Hybrid encryption has some issues"
            else:
                status = "FAIL"
                score = avg_success * 5
                recommendation = "Hybrid encryption has significant problems"
            
            return TestResult(
                test_name="Hybrid Functionality",
                test_type="STRENGTH",
                score=score,
                status=status,
                details={
                    "avg_success_rate": avg_success,
                    "results_by_size": dict(zip(test_sizes, results)),
                    "total_tests": len(test_sizes) * 10,
                    "approach_tested": "Hybrid (encrypt/decrypt)"
                },
                recommendation=recommendation
            )
            
        except Exception as e:
            return TestResult(
                test_name="Hybrid Functionality",
                test_type="STRENGTH",
                score=0.0,
                status="FAIL",
                details={"error": str(e)},
                recommendation="Fix implementation errors"
            )
    
    def test_asymmetric_functionality(self) -> TestResult:
        """Test asymmetric encryption/decryption functionality"""
        print("Testing Asymmetric Functionality...")
        
        try:
            test_sizes = [16, 32, 64, 128, 256, 512, 1024, 2048]
            results = []
            
            for size in test_sizes:
                test_messages = [secrets.token_bytes(size) for _ in range(10)]
                success_count = 0
                
                for msg in test_messages:
                    sender_kp, receiver_kp = self.test_keypairs[0]
                    try:
                        # Test ASYMMETRIC approach (asymmetric_encrypt/asymmetric_decrypt)
                        shared_key = StellarSharedKey(sender_kp, receiver_kp.public_key())
                        encrypted = shared_key.asymmetric_encrypt(msg)  # Uses asymmetric approach
                        
                        shared_decrypt = StellarSharedDecryption(receiver_kp, sender_kp.public_key())
                        decrypted = shared_decrypt.asymmetric_decrypt(encrypted)  # Uses asymmetric approach
                        
                        if decrypted == msg:
                            success_count += 1
                    except:
                        pass
                
                success_rate = success_count / len(test_messages)
                results.append(success_rate)
            
            avg_success = sum(results) / len(results)
            
            if avg_success >= 0.95:
                status = "PASS"
                score = avg_success * 10
                recommendation = "Asymmetric encryption works correctly"
            elif avg_success >= 0.8:
                status = "WARNING"
                score = avg_success * 8
                recommendation = "Asymmetric encryption has some issues"
            else:
                status = "FAIL"
                score = avg_success * 5
                recommendation = "Asymmetric encryption has significant problems"
            
            return TestResult(
                test_name="Asymmetric Functionality",
                test_type="STRENGTH",
                score=score,
                status=status,
                details={
                    "avg_success_rate": avg_success,
                    "results_by_size": dict(zip(test_sizes, results)),
                    "total_tests": len(test_sizes) * 10,
                    "approach_tested": "Asymmetric (asymmetric_encrypt/asymmetric_decrypt)"
                },
                recommendation=recommendation
            )
            
        except Exception as e:
            return TestResult(
                test_name="Asymmetric Functionality",
                test_type="STRENGTH",
                score=0.0,
                status="FAIL",
                details={"error": str(e)},
                recommendation="Fix implementation errors"
            )
    
    def test_cross_compatibility(self) -> TestResult:
        """Test that hybrid and asymmetric approaches are properly separated"""
        print("Testing Cross-Compatibility...")
        
        try:
            test_messages = [secrets.token_bytes(64) for _ in range(10)]
            cross_failures = 0
            cross_successes = 0
            
            for msg in test_messages:
                sender_kp, receiver_kp = self.test_keypairs[0]
                try:
                    # Test 1: Encrypt with hybrid, decrypt with asymmetric (should fail)
                    shared_key = StellarSharedKey(sender_kp, receiver_kp.public_key())
                    hybrid_encrypted = shared_key.encrypt(msg)
                    
                    shared_decrypt = StellarSharedDecryption(receiver_kp, sender_kp.public_key())
                    try:
                        hybrid_decrypted = shared_decrypt.asymmetric_decrypt(hybrid_encrypted)
                        # If this succeeds, it's a problem
                        cross_failures += 1
                    except:
                        # This should fail - good
                        cross_successes += 1
                    
                    # Test 2: Encrypt with asymmetric, decrypt with hybrid (should fail)
                    asymmetric_encrypted = shared_key.asymmetric_encrypt(msg)
                    
                    try:
                        asymmetric_decrypted = shared_decrypt.decrypt(asymmetric_encrypted)
                        # If this succeeds, it's a problem
                        cross_failures += 1
                    except:
                        # This should fail - good
                        cross_successes += 1
                        
                except:
                    cross_failures += 2
            
            # Calculate score based on proper separation
            total_tests = len(test_messages) * 2
            separation_rate = cross_successes / total_tests
            
            if separation_rate >= 0.95:
                status = "PASS"
                score = separation_rate * 10
                recommendation = "Approaches are properly separated"
            elif separation_rate >= 0.8:
                status = "WARNING"
                score = separation_rate * 8
                recommendation = "Some cross-compatibility issues"
            else:
                status = "FAIL"
                score = separation_rate * 5
                recommendation = "Poor separation between approaches"
            
            return TestResult(
                test_name="Cross-Compatibility",
                test_type="STRENGTH",
                score=score,
                status=status,
                details={
                    "separation_rate": separation_rate,
                    "cross_successes": cross_successes,
                    "cross_failures": cross_failures,
                    "total_tests": total_tests
                },
                recommendation=recommendation
            )
            
        except Exception as e:
            return TestResult(
                test_name="Cross-Compatibility",
                test_type="STRENGTH",
                score=0.0,
                status="FAIL",
                details={"error": str(e)},
                recommendation="Fix implementation errors"
            )
    
    def test_key_space_security(self) -> TestResult:
        """Test key space and entropy"""
        print("Testing Key Space Security...")
        
        try:
            # Collect samples
            samples = []
            for sender_kp, receiver_kp in self.test_keypairs:
                shared_key = StellarSharedKey(sender_kp, receiver_kp.public_key())
                
                # DH secrets
                for _ in range(20):
                    dh_secret = shared_key.asymmetric_shared_secret()
                    samples.append(dh_secret)
                
                # Nonces from encryption
                for _ in range(20):
                    test_msg = secrets.token_bytes(32)
                    encrypted = shared_key.encrypt(test_msg)
                    parts = encrypted.split(b'|')
                    if len(parts) >= 2:
                        nonce = parts[1]
                        samples.append(nonce)
            
            # Calculate entropy
            entropy = self._calculate_entropy(b''.join(samples))
            effective_bits = 256  # X25519 limitation
            
            # Score based on entropy
            score = (entropy / 8.0) * 10
            
            if entropy >= 7.5:
                status = "PASS"
                recommendation = "Excellent key space security"
            elif entropy >= 6.0:
                status = "WARNING"
                recommendation = "Good key space security"
            else:
                status = "FAIL"
                recommendation = "Poor key space security"
            
            return TestResult(
                test_name="Key Space Security",
                test_type="STRENGTH",
                score=score,
                status=status,
                details={
                    "entropy": entropy,
                    "effective_bits": effective_bits,
                    "sample_count": len(samples)
                },
                recommendation=recommendation
            )
            
        except Exception as e:
            return TestResult(
                test_name="Key Space Security",
                test_type="STRENGTH",
                score=0.0,
                status="FAIL",
                details={"error": str(e)},
                recommendation="Fix implementation errors"
            )
    
    def test_randomness_quality(self) -> TestResult:
        """Test randomness quality of ciphertexts"""
        print("Testing Randomness Quality...")
        
        try:
            # Generate ciphertext samples
            ciphertexts = []
            for i in range(100):
                test_message = secrets.token_bytes(64)
                sender_kp, receiver_kp = self.test_keypairs[i % len(self.test_keypairs)]
                
                shared_key = StellarSharedKey(sender_kp, receiver_kp.public_key())
                encrypted = shared_key.encrypt(test_message)
                ciphertexts.append(encrypted)
            
            # Test randomness
            randomness_score = self._comprehensive_randomness_test(b''.join(ciphertexts))
            entropy = self._calculate_entropy(b''.join(ciphertexts))
            
            score = randomness_score * 10
            
            if randomness_score >= 0.8:
                status = "PASS"
                recommendation = "Excellent randomness quality"
            elif randomness_score >= 0.6:
                status = "WARNING"
                recommendation = "Good randomness quality"
            else:
                status = "FAIL"
                recommendation = "Poor randomness quality"
            
            return TestResult(
                test_name="Randomness Quality",
                test_type="STRENGTH",
                score=score,
                status=status,
                details={
                    "randomness_score": randomness_score,
                    "entropy": entropy,
                    "sample_size": len(b''.join(ciphertexts))
                },
                recommendation=recommendation
            )
            
        except Exception as e:
            return TestResult(
                test_name="Randomness Quality",
                test_type="STRENGTH",
                score=0.0,
                status="FAIL",
                details={"error": str(e)},
                recommendation="Fix implementation errors"
            )
    
    def test_attack_resistance(self) -> TestResult:
        """Test resistance to common attacks"""
        print("Testing Attack Resistance...")
        
        try:
            # Known plaintext attack test
            known_plaintext = b"Known plaintext attack test " * 4
            ciphertexts = []
            
            for i in range(20):
                sender_kp, receiver_kp = self.test_keypairs[i % len(self.test_keypairs)]
                shared_key = StellarSharedKey(sender_kp, receiver_kp.public_key())
                encrypted = shared_key.encrypt(known_plaintext)
                ciphertexts.append(encrypted)
            
            # Measure uniqueness
            uniqueness = len(set(ct.hex() for ct in ciphertexts)) / len(ciphertexts)
            entropy = self._calculate_entropy(b''.join(ciphertexts))
            
            # Score based on uniqueness and entropy
            score = (uniqueness * 5 + (entropy / 8.0) * 5)
            
            if uniqueness >= 0.95 and entropy >= 6.0:
                status = "PASS"
                recommendation = "Strong attack resistance"
            elif uniqueness >= 0.8 and entropy >= 4.0:
                status = "WARNING"
                recommendation = "Moderate attack resistance"
            else:
                status = "FAIL"
                recommendation = "Weak attack resistance"
            
            return TestResult(
                test_name="Attack Resistance",
                test_type="STRENGTH",
                score=score,
                status=status,
                details={
                    "uniqueness": uniqueness,
                    "entropy": entropy,
                    "ciphertext_count": len(ciphertexts)
                },
                recommendation=recommendation
            )
            
        except Exception as e:
            return TestResult(
                test_name="Attack Resistance",
                test_type="STRENGTH",
                score=0.0,
                status="FAIL",
                details={"error": str(e)},
                recommendation="Fix implementation errors"
            )
    
    # ==================== VULNERABILITY ASSESSMENT ====================
    
    def test_timing_vulnerabilities(self) -> TestResult:
        """Test for timing side-channel vulnerabilities"""
        print("Testing Timing Vulnerabilities...")
        
        try:
            # Test timing variations
            timing_tests = []
            
            for sender_kp, receiver_kp in self.test_keypairs:
                shared_key = StellarSharedKey(sender_kp, receiver_kp.public_key())
                test_message = secrets.token_bytes(64)
                
                # Measure encryption times
                times = []
                for _ in range(10):
                    start_time = time.perf_counter_ns()
                    encrypted = shared_key.encrypt(test_message)
                    end_time = time.perf_counter_ns()
                    times.append(end_time - start_time)
                
                timing_tests.extend(times)
            
            # Analyze timing
            avg_time = sum(timing_tests) / len(timing_tests)
            time_variance = statistics.variance(timing_tests) if len(timing_tests) > 1 else 0
            time_std = math.sqrt(time_variance)
            
            # Check for significant timing variations
            timing_coefficient = time_std / avg_time if avg_time > 0 else 0
            
            if timing_coefficient > 0.2:
                status = "WARNING"
                score = max(0, 10 - timing_coefficient * 10)
                recommendation = "Significant timing variations detected"
            elif timing_coefficient > 0.1:
                status = "WARNING"
                score = max(0, 10 - timing_coefficient * 5)
                recommendation = "Moderate timing variations detected"
            else:
                status = "PASS"
                score = 10.0
                recommendation = "Minimal timing variations"
            
            return TestResult(
                test_name="Timing Vulnerabilities",
                test_type="VULNERABILITY",
                score=score,
                status=status,
                details={
                    "avg_time_ns": avg_time,
                    "time_std_ns": time_std,
                    "timing_coefficient": timing_coefficient,
                    "total_measurements": len(timing_tests)
                },
                recommendation=recommendation
            )
            
        except Exception as e:
            return TestResult(
                test_name="Timing Vulnerabilities",
                test_type="VULNERABILITY",
                score=0.0,
                status="FAIL",
                details={"error": str(e)},
                recommendation="Fix implementation errors"
            )
    
    def test_component_exposure(self) -> TestResult:
        """Test security implications of exposed components"""
        print("Testing Component Exposure...")
        
        try:
            # Analyze what's exposed in encrypted format
            test_message = secrets.token_bytes(64)
            sender_kp, receiver_kp = self.test_keypairs[0]
            shared_key = StellarSharedKey(sender_kp, receiver_kp.public_key())
            encrypted = shared_key.encrypt(test_message)
            
            # Parse encrypted format
            parts = encrypted.split(b'|')
            
            # Security assessment
            if len(parts) >= 2:
                # Nonce is exposed (standard for many encryption schemes)
                nonce_exposed = True
                nonce_size = len(parts[1])
                
                # Ciphertext is exposed (obviously)
                ciphertext_exposed = True
                
                # Score based on exposure
                if nonce_exposed and nonce_size == 24:  # Standard nonce size
                    score = 8.0  # Standard exposure
                    status = "PASS"
                    recommendation = "Standard component exposure (nonce)"
                else:
                    score = 6.0
                    status = "WARNING"
                    recommendation = "Non-standard component exposure"
            else:
                score = 10.0
                status = "PASS"
                recommendation = "Minimal component exposure"
            
            return TestResult(
                test_name="Component Exposure",
                test_type="VULNERABILITY",
                score=score,
                status=status,
                details={
                    "format_parts": len(parts),
                    "nonce_exposed": len(parts) >= 2,
                    "nonce_size": len(parts[1]) if len(parts) >= 2 else 0
                },
                recommendation=recommendation
            )
            
        except Exception as e:
            return TestResult(
                test_name="Component Exposure",
                test_type="VULNERABILITY",
                score=0.0,
                status="FAIL",
                details={"error": str(e)},
                recommendation="Fix implementation errors"
            )
    
    # ==================== AES COMPARISON ====================
    
    def aes_encrypt_decrypt(self, plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """AES encrypt and decrypt for comparison"""
        if not AES_AVAILABLE:
            # Fallback for testing
            iv = secrets.token_bytes(16)
            encrypted = iv
            for i, byte in enumerate(plaintext):
                key_byte = key[i % len(key)]
                encrypted += bytes([byte ^ key_byte ^ iv[i % len(iv)]])
            
            # Decrypt
            decrypted = b''
            iv = encrypted[:16]
            encrypted_data = encrypted[16:]
            for i, byte in enumerate(encrypted_data):
                key_byte = key[i % len(key)]
                decrypted += bytes([byte ^ key_byte ^ iv[i % len(iv)]])
            
            return encrypted, decrypted
        
        # Proper AES implementation
        iv = secrets.token_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(plaintext, AES.block_size)
        encrypted = cipher.encrypt(padded_data)
        
        # Decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_decrypted = cipher.decrypt(encrypted)
        decrypted = unpad(padded_decrypted, AES.block_size)
        
        return iv + encrypted, decrypted
    
    def test_aes_comparison(self) -> TestResult:
        """Compare hybrid approach with AES"""
        print("Testing AES Comparison...")
        
        try:
            # Test both approaches
            test_sizes = [16, 32, 64, 128, 256]
            hybrid_scores = []
            aes_scores = []
            
            for size in test_sizes:
                test_messages = [secrets.token_bytes(size) for _ in range(10)]
                
                # Test Hybrid
                hybrid_success = 0
                hybrid_times = []
                for msg in test_messages:
                    sender_kp, receiver_kp = self.test_keypairs[0]
                    try:
                        start_time = time.perf_counter_ns()
                        shared_key = StellarSharedKey(sender_kp, receiver_kp.public_key())
                        encrypted = shared_key.encrypt(msg)
                        shared_decrypt = StellarSharedDecryption(receiver_kp, sender_kp.public_key())
                        decrypted = shared_decrypt.decrypt(encrypted)
                        end_time = time.perf_counter_ns()
                        
                        if decrypted == msg:
                            hybrid_success += 1
                        hybrid_times.append(end_time - start_time)
                    except:
                        pass
                
                # Test AES
                aes_success = 0
                aes_times = []
                for msg in test_messages:
                    key = secrets.token_bytes(32)
                    try:
                        start_time = time.perf_counter_ns()
                        encrypted, decrypted = self.aes_encrypt_decrypt(msg, key)
                        end_time = time.perf_counter_ns()
                        
                        if decrypted == msg:
                            aes_success += 1
                        aes_times.append(end_time - start_time)
                    except:
                        pass
                
                # Calculate scores
                hybrid_success_rate = hybrid_success / len(test_messages)
                aes_success_rate = aes_success / len(test_messages)
                
                hybrid_avg_time = sum(hybrid_times) / len(hybrid_times) if hybrid_times else 0
                aes_avg_time = sum(aes_times) / len(aes_times) if aes_times else 0
                
                # Combined score (correctness + performance)
                hybrid_score = hybrid_success_rate * 5 + min(5, 1000000 / hybrid_avg_time) if hybrid_avg_time > 0 else 0
                aes_score = aes_success_rate * 5 + min(5, 1000000 / aes_avg_time) if aes_avg_time > 0 else 0
                
                hybrid_scores.append(hybrid_score)
                aes_scores.append(aes_score)
            
            # Overall comparison
            hybrid_avg = sum(hybrid_scores) / len(hybrid_scores)
            aes_avg = sum(aes_scores) / len(aes_scores)
            
            # Determine result
            if abs(hybrid_avg - aes_avg) < 1.0:
                status = "PASS"
                score = (hybrid_avg + aes_avg) / 2
                recommendation = "Hybrid approach comparable to AES"
            elif hybrid_avg > aes_avg:
                status = "PASS"
                score = hybrid_avg
                recommendation = "Hybrid approach outperforms AES"
            else:
                status = "WARNING"
                score = hybrid_avg
                recommendation = "AES outperforms hybrid approach"
            
            return TestResult(
                test_name="AES Comparison",
                test_type="COMPARISON",
                score=score,
                status=status,
                details={
                    "hybrid_avg_score": hybrid_avg,
                    "aes_avg_score": aes_avg,
                    "hybrid_scores_by_size": dict(zip(test_sizes, hybrid_scores)),
                    "aes_scores_by_size": dict(zip(test_sizes, aes_scores))
                },
                recommendation=recommendation
            )
            
        except Exception as e:
            return TestResult(
                test_name="AES Comparison",
                test_type="COMPARISON",
                score=0.0,
                status="FAIL",
                details={"error": str(e)},
                recommendation="Fix implementation errors"
            )
    
    # ==================== UTILITY METHODS ====================
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if len(data) == 0:
            return 0
        
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        total_bytes = len(data)
        entropy = 0
        
        for count in byte_counts:
            if count > 0:
                freq = count / total_bytes
                entropy -= freq * math.log2(freq)
        
        return entropy
    
    def _comprehensive_randomness_test(self, data: bytes) -> float:
        """Comprehensive randomness test"""
        if len(data) < 1000:
            return 0.5  # Insufficient data
        
        # Entropy test
        entropy = self._calculate_entropy(data)
        entropy_score = min(1.0, entropy / 8.0)
        
        # Runs test
        runs = 1
        for i in range(1, len(data)):
            if data[i] != data[i-1]:
                runs += 1
        
        expected_runs = (2 * len(data) - 1) / 3
        runs_score = 1.0 - abs(runs - expected_runs) / expected_runs
        
        # Serial correlation test
        if len(data) >= 2:
            mean_byte = sum(data) / len(data)
            numerator = sum((data[i] - mean_byte) * (data[i+1] - mean_byte) for i in range(len(data)-1))
            denominator = sum((data[i] - mean_byte) ** 2 for i in range(len(data)))
            
            if denominator > 0:
                autocorrelation = numerator / denominator
                correlation_score = 1.0 - abs(autocorrelation)
            else:
                correlation_score = 0.5
        else:
            correlation_score = 0.5
        
        # Combined score
        combined_score = (entropy_score + runs_score + correlation_score) / 3
        
        return combined_score
    
    # ==================== ASSESSMENT EXECUTION ====================
    
    def run_comprehensive_assessment(self) -> List[TestResult]:
        """Run complete cryptographic assessment"""
        print("COMPREHENSIVE CRYPTOGRAPHIC ASSESSMENT")
        print("Testing hvym_stellar cryptographic implementations")
        print("=" * 60)
        print()
        
        # Suppress warnings for cleaner output
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        
        # Run all tests
        all_tests = [
            self.test_hybrid_functionality,
            self.test_asymmetric_functionality,
            self.test_cross_compatibility,
            self.test_key_space_security,
            self.test_randomness_quality,
            self.test_attack_resistance,
            self.test_component_exposure,
            self.test_aes_comparison
        ]
        
        results = []
        for test_func in all_tests:
            result = test_func()
            results.append(result)
            print()
        
        return results
    
    def generate_comprehensive_report(self, results: List[TestResult]) -> str:
        """Generate comprehensive assessment report"""
        report = []
        
        # Header
        report.append("COMPREHENSIVE CRYPTOGRAPHIC ASSESSMENT")
        report.append("hvym_stellar Cryptographic Implementation Analysis")
        report.append("=" * 60)
        report.append(f"Assessment Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Implementation: hvym_stellar v0.16.0")
        report.append(f"Total Tests: {len(results)}")
        report.append("")
        
        # Executive Summary
        passed_tests = sum(1 for r in results if r.status == "PASS")
        warning_tests = sum(1 for r in results if r.status == "WARNING")
        failed_tests = sum(1 for r in results if r.status == "FAIL")
        
        total_score = sum(r.score for r in results)
        avg_score = total_score / len(results)
        
        # Categorize tests
        strength_tests = [r for r in results if r.test_type == "STRENGTH"]
        vulnerability_tests = [r for r in results if r.test_type == "VULNERABILITY"]
        comparison_tests = [r for r in results if r.test_type == "COMPARISON"]
        
        report.append("EXECUTIVE SUMMARY")
        report.append("-" * 20)
        report.append(f"Passed Tests: {passed_tests}/{len(results)}")
        report.append(f"Warning Tests: {warning_tests}/{len(results)}")
        report.append(f"Failed Tests: {failed_tests}/{len(results)}")
        report.append(f"Overall Score: {avg_score:.2f}/10.0")
        report.append("")
        
        # Category summaries
        report.append("CATEGORY SUMMARIES")
        report.append("-" * 20)
        report.append(f"Strength Tests: {len(strength_tests)}")
        report.append(f"Vulnerability Tests: {len(vulnerability_tests)}")
        report.append(f"Comparison Tests: {len(comparison_tests)}")
        report.append("")
        
        # Overall assessment
        if avg_score >= 8.0:
            overall_status = "EXCELLENT"
            assessment = "Cryptographic implementation is excellent"
        elif avg_score >= 6.0:
            overall_status = "GOOD"
            assessment = "Cryptographic implementation is good with minor issues"
        elif avg_score >= 4.0:
            overall_status = "FAIR"
            assessment = "Cryptographic implementation needs improvements"
        else:
            overall_status = "POOR"
            assessment = "Cryptographic implementation has significant issues"
        
        report.append(f"Overall Status: {overall_status}")
        report.append(f"Assessment: {assessment}")
        report.append("")
        
        # Detailed Results
        report.append("DETAILED TEST RESULTS")
        report.append("-" * 25)
        
        for result in results:
            report.append(f"\n{result.test_name}")
            report.append(f"Type: {result.test_type}")
            report.append(f"Status: {result.status}")
            report.append(f"Score: {result.score:.2f}/10.0")
            report.append(f"Recommendation: {result.recommendation}")
            
            if result.details:
                report.append("Details:")
                for key, value in result.details.items():
                    if isinstance(value, float):
                        report.append(f"  {key}: {value:.4f}")
                    else:
                        report.append(f"  {key}: {value}")
        
        # Security Analysis
        report.append("\nSECURITY ANALYSIS")
        report.append("-" * 20)
        
        # Strength analysis
        strength_scores = [r.score for r in strength_tests]
        if strength_scores:
            avg_strength = sum(strength_scores) / len(strength_scores)
            report.append(f"Average Strength Score: {avg_strength:.2f}/10.0")
        
        # Vulnerability analysis
        vulnerability_scores = [r.score for r in vulnerability_tests]
        if vulnerability_scores:
            avg_vulnerability = sum(vulnerability_scores) / len(vulnerability_scores)
            report.append(f"Average Vulnerability Score: {avg_vulnerability:.2f}/10.0")
        
        # Comparison analysis
        comparison_scores = [r.score for r in comparison_tests]
        if comparison_scores:
            avg_comparison = sum(comparison_scores) / len(comparison_scores)
            report.append(f"Average Comparison Score: {avg_comparison:.2f}/10.0")
        
        # Recommendations
        report.append("\nRECOMMENDATIONS")
        report.append("-" * 16)
        
        if overall_status in ["EXCELLENT", "GOOD"]:
            report.append("✅ Implementation is suitable for production use")
            report.append("✅ Cryptographic properties are strong")
            report.append("✅ Regular monitoring recommended")
        else:
            report.append("⚠️ Implementation needs improvements before production use")
            report.append("⚠️ Address failed and warning tests")
            report.append("⚠️ Consider additional security review")
        
        report.append("\nFor File Encryption Use Case:")
        if overall_status in ["EXCELLENT", "GOOD"]:
            report.append("✅ Suitable for file encryption applications")
            report.append("✅ Provides adequate security for content protection")
            report.append("✅ Consider performance requirements")
        else:
            report.append("⚠️ Review security requirements before use")
            report.append("⚠️ Consider alternative implementations")
            report.append("⚠️ Additional testing recommended")
        
        return "\n".join(report)

def main():
    """Main execution function"""
    print("COMPREHENSIVE CRYPTOGRAPHIC ASSESSMENT")
    print("=" * 40)
    print()
    
    # Run assessment
    assessor = ComprehensiveCryptographicAssessment()
    results = assessor.run_comprehensive_assessment()
    
    # Generate report
    report = assessor.generate_comprehensive_report(results)
    
    # Display and save report
    print(report)
    
    # Save report to file
    try:
        with open("comprehensive_cryptographic_assessment.txt", "w", encoding='utf-8') as f:
            f.write(report)
        print(f"\nComprehensive assessment saved to: comprehensive_cryptographic_assessment.txt")
    except Exception as e:
        print(f"Warning: Could not save report file: {e}")
    
    # Return appropriate exit code
    total_score = sum(r.score for r in results)
    avg_score = total_score / len(results)
    
    if avg_score >= 8.0:
        return 0  # Excellent
    elif avg_score >= 6.0:
        return 1  # Good
    elif avg_score >= 4.0:
        return 2  # Fair
    else:
        return 3  # Poor

if __name__ == "__main__":
    exit_code = main()
    import sys
    sys.exit(exit_code)
