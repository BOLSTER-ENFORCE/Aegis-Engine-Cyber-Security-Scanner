import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from myapp.scan_engine import (
    COMMON_PORTS,
    CREDENTIAL_PATTERNS,
    RISK_WEIGHT,
    SUSPICIOUS_EXTENSIONS,
    SUSPICIOUS_NAMES,
    TEXT_EXTENSIONS,
    _contains_credential,
    _port_resolution,
    _risk_level,
    _sha256,
    ai_recommendations,
    behavioral_analysis,
    compliance_check,
    credential_file_scan,
    exposure_assessment,
    fim_snapshot,
    identity_privilege_assessment,
    osi_model,
    port_scan,
    threat_database_matches,
    threat_intel_lookup,
    usb_monitoring_snapshot,
)

User = get_user_model()


# ------------------------------------------------------------------
# _risk_level
# ------------------------------------------------------------------
class RiskLevelTests(TestCase):
    def test_low(self):
        self.assertEqual(_risk_level(85), "LOW")
        self.assertEqual(_risk_level(100), "LOW")

    def test_medium(self):
        self.assertEqual(_risk_level(70), "MEDIUM")
        self.assertEqual(_risk_level(84), "MEDIUM")

    def test_high(self):
        self.assertEqual(_risk_level(45), "HIGH")
        self.assertEqual(_risk_level(69), "HIGH")

    def test_critical(self):
        self.assertEqual(_risk_level(0), "CRITICAL")
        self.assertEqual(_risk_level(44), "CRITICAL")

    def test_boundary_85(self):
        self.assertEqual(_risk_level(85), "LOW")
        self.assertEqual(_risk_level(84), "MEDIUM")

    def test_boundary_70(self):
        self.assertEqual(_risk_level(70), "MEDIUM")
        self.assertEqual(_risk_level(69), "HIGH")

    def test_boundary_45(self):
        self.assertEqual(_risk_level(45), "HIGH")
        self.assertEqual(_risk_level(44), "CRITICAL")


# ------------------------------------------------------------------
# _sha256
# ------------------------------------------------------------------
class Sha256Tests(TestCase):
    def test_known_content(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"hello world")
            tmp.flush()
            result = _sha256(tmp.name)
        os.unlink(tmp.name)
        self.assertEqual(len(result), 64)
        self.assertTrue(result.isalnum())

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.flush()
            result = _sha256(tmp.name)
        os.unlink(tmp.name)
        self.assertEqual(len(result), 64)

    def test_nonexistent_file(self):
        self.assertEqual(_sha256("/nonexistent/path/file.bin"), "")

    def test_deterministic(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"test data")
            tmp.flush()
            r1 = _sha256(tmp.name)
            r2 = _sha256(tmp.name)
        os.unlink(tmp.name)
        self.assertEqual(r1, r2)


# ------------------------------------------------------------------
# _port_resolution
# ------------------------------------------------------------------
class PortResolutionTests(TestCase):
    def test_critical(self):
        result = _port_resolution(23, "critical")
        self.assertIn("Close port 23", result)

    def test_high(self):
        result = _port_resolution(21, "high")
        self.assertIn("Limit port 21", result)

    def test_medium(self):
        result = _port_resolution(80, "medium")
        self.assertIn("Confirm the service", result)

    def test_low(self):
        result = _port_resolution(443, "low")
        self.assertIn("Keep patched", result)


# ------------------------------------------------------------------
# _contains_credential
# ------------------------------------------------------------------
class ContainsCredentialTests(TestCase):
    def test_empty_string(self):
        self.assertFalse(_contains_credential(""))

    def test_none(self):
        self.assertFalse(_contains_credential(None))

    def test_aws_key(self):
        self.assertTrue(_contains_credential("some AKIAIOSFODNN7EXAMPLE text"))

    def test_bearer_token(self):
        self.assertTrue(_contains_credential("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI"))

    def test_password_assignment(self):
        self.assertTrue(_contains_credential("password=supersecretvalue"))

    def test_private_key(self):
        self.assertTrue(_contains_credential("-----BEGIN RSA PRIVATE KEY-----"))

    def test_clean_string(self):
        self.assertFalse(_contains_credential("ls -la /home/user"))


# ------------------------------------------------------------------
# credential_file_scan
# ------------------------------------------------------------------
class CredentialFileScanTests(TestCase):
    def test_file_with_credentials(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as tmp:
            tmp.write("AWS_KEY=AKIAIOSFODNN7EXAMPLE\npassword=secretpass123\n")
            tmp.flush()
            matches = credential_file_scan(Path(tmp.name))
        os.unlink(tmp.name)
        self.assertGreater(len(matches), 0)

    def test_clean_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("This is a normal text file with nothing secret.\n")
            tmp.flush()
            matches = credential_file_scan(Path(tmp.name))
        os.unlink(tmp.name)
        self.assertEqual(len(matches), 0)

    def test_nonexistent_file(self):
        matches = credential_file_scan(Path("/nonexistent/file.txt"))
        self.assertEqual(matches, [])

    def test_max_five_matches(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write(
                "password=aaa\npasswd=bbb\npwd=ccc\n"
                "api_key=ddddddddddddddddddd\ntoken=eeeeeeeeeeeeeeeeeeeeee\n"
                "secret=fffffffffffffffffffff\nBearer abcdefghijklmnopqrstuvwxyz\n"
                "-----BEGIN RSA PRIVATE KEY-----\n"
            )
            tmp.flush()
            matches = credential_file_scan(Path(tmp.name))
        os.unlink(tmp.name)
        self.assertLessEqual(len(matches), 5)


# ------------------------------------------------------------------
# compliance_check
# ------------------------------------------------------------------
class ComplianceCheckTests(TestCase):
    def test_returns_dict(self):
        result = compliance_check()
        self.assertIn("cis_summary", result)
        self.assertIn("checks", result)

    def test_checks_list_not_empty(self):
        result = compliance_check()
        self.assertGreater(len(result["checks"]), 0)

    def test_each_check_has_required_keys(self):
        result = compliance_check()
        for check in result["checks"]:
            self.assertIn("name", check)
            self.assertIn("status", check)
            self.assertIn("risk", check)
            self.assertIn("detail", check)


# ------------------------------------------------------------------
# identity_privilege_assessment
# ------------------------------------------------------------------
class IdentityPrivilegeTests(TestCase):
    def test_anonymous(self):
        result = identity_privilege_assessment(None)
        self.assertEqual(result["user"], "anonymous")
        self.assertEqual(result["risk"], "low")

    def test_superuser(self):
        user = MagicMock()
        user.username = "root"
        user.email = "root@test.com"
        user.is_superuser = True
        user.is_staff = True
        result = identity_privilege_assessment(user)
        self.assertEqual(result["risk"], "critical")
        self.assertEqual(result["user"], "root")

    def test_normal_user(self):
        user = MagicMock()
        user.username = "alice"
        user.email = "alice@test.com"
        user.is_superuser = False
        user.is_staff = False
        result = identity_privilege_assessment(user)
        self.assertEqual(result["risk"], "low")


# ------------------------------------------------------------------
# fim_snapshot
# ------------------------------------------------------------------
class FimSnapshotTests(TestCase):
    def test_basic(self):
        files = {
            "scanned_count": 2,
            "detected_count": 2,
            "files": [
                {"path": "/tmp/a.exe", "risk": "high"},
                {"path": "/tmp/b.dll", "risk": "critical"},
            ],
        }
        result = fim_snapshot(files)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["file"], "/tmp/a.exe")
        self.assertEqual(result[0]["change"], "new_or_suspicious")

    def test_empty_files(self):
        files = {"scanned_count": 0, "detected_count": 0, "files": []}
        result = fim_snapshot(files)
        self.assertEqual(result, [])

    def test_caps_at_50(self):
        files = {
            "scanned_count": 100,
            "detected_count": 100,
            "files": [{"path": f"/tmp/f{i}.exe", "risk": "high"} for i in range(100)],
        }
        result = fim_snapshot(files)
        self.assertLessEqual(len(result), 50)


# ------------------------------------------------------------------
# usb_monitoring_snapshot
# ------------------------------------------------------------------
class UsbMonitoringSnapshotTests(TestCase):
    def test_basic(self):
        files = {
            "scanned_count": 10,
            "detected_count": 3,
            "files": [
                {"risk": "high"},
                {"risk": "low"},
                {"risk": "critical"},
            ],
        }
        result = usb_monitoring_snapshot(files)
        self.assertEqual(result["files_scanned"], 10)
        self.assertEqual(result["malicious"], 2)

    def test_no_malicious(self):
        files = {"scanned_count": 5, "detected_count": 0, "files": [{"risk": "low"}]}
        result = usb_monitoring_snapshot(files)
        self.assertEqual(result["malicious"], 0)


# ------------------------------------------------------------------
# behavioral_analysis
# ------------------------------------------------------------------
class BehavioralAnalysisTests(TestCase):
    def test_many_suspicious_files(self):
        processes = []
        files = {
            "scanned_count": 10,
            "detected_count": 5,
            "files": [{"risk": "high"} for _ in range(5)],
        }
        connections = []
        result = behavioral_analysis(processes, files, connections)
        behaviors = [f["behavior"] for f in result]
        self.assertIn("multiple_suspicious_files", behaviors)

    def test_credential_process(self):
        processes = [{"risk": "critical"}]
        files = {"scanned_count": 0, "detected_count": 0, "files": []}
        connections = []
        result = behavioral_analysis(processes, files, connections)
        behaviors = [f["behavior"] for f in result]
        self.assertIn("credential_or_encoded_process_activity", behaviors)

    def test_c2_port(self):
        processes = []
        files = {"scanned_count": 0, "detected_count": 0, "files": []}
        connections = [{"port": 4444}]
        result = behavioral_analysis(processes, files, connections)
        behaviors = [f["behavior"] for f in result]
        self.assertIn("possible_reverse_shell_or_c2", behaviors)

    def test_clean(self):
        processes = []
        files = {"scanned_count": 0, "detected_count": 0, "files": []}
        connections = [{"port": 443}]
        result = behavioral_analysis(processes, files, connections)
        self.assertEqual(result, [])


# ------------------------------------------------------------------
# threat_database_matches
# ------------------------------------------------------------------
class ThreatDatabaseMatchesTests(TestCase):
    def test_bad_ports(self):
        files = {"scanned_count": 0, "detected_count": 0, "files": []}
        ports = [{"port": 23, "protocol": "TCP"}, {"port": 445, "protocol": "TCP"}]
        result = threat_database_matches(files, ports)
        self.assertEqual(len(result), 2)

    def test_credential_files(self):
        files = {
            "scanned_count": 1,
            "detected_count": 1,
            "files": [{"malicious": "Credential Exposure", "sha256": "abc123"}],
        }
        ports = []
        result = threat_database_matches(files, ports)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["confidence"], "95%")

    def test_no_matches(self):
        files = {"scanned_count": 1, "detected_count": 0, "files": []}
        ports = [{"port": 443, "protocol": "TCP"}]
        result = threat_database_matches(files, ports)
        self.assertEqual(result, [])


# ------------------------------------------------------------------
# threat_intel_lookup
# ------------------------------------------------------------------
class ThreatIntelLookupTests(TestCase):
    def test_returns_offline(self):
        result = threat_intel_lookup()
        self.assertEqual(result["status"], "offline")
        self.assertIn("sources", result)


# ------------------------------------------------------------------
# osi_model
# ------------------------------------------------------------------
class OsiModelTests(TestCase):
    def test_seven_layers(self):
        result = osi_model()
        self.assertEqual(len(result), 7)

    def test_layer_numbers(self):
        result = osi_model()
        layers = [item["layer"] for item in result]
        self.assertEqual(layers, [7, 6, 5, 4, 3, 2, 1])

    def test_required_keys(self):
        result = osi_model()
        for item in result:
            self.assertIn("layer", item)
            self.assertIn("name", item)
            self.assertIn("examples", item)
            self.assertIn("security", item)


# ------------------------------------------------------------------
# ai_recommendations
# ------------------------------------------------------------------
class AiRecommendationsTests(TestCase):
    def test_low_score_adds_priority(self):
        recs = ai_recommendations(50, [], {"detected_count": 0, "files": []}, [], [])
        self.assertTrue(any("Priority" in r for r in recs))

    def test_high_risk_ports(self):
        ports = [{"risk": "critical"}]
        recs = ai_recommendations(90, ports, {"detected_count": 0, "files": []}, [], [])
        self.assertTrue(any("ports" in r.lower() for r in recs))

    def test_detected_files(self):
        files = {"detected_count": 3, "files": []}
        recs = ai_recommendations(90, [], files, [], [])
        self.assertTrue(any("files" in r.lower() for r in recs))

    def test_suspicious_processes(self):
        recs = ai_recommendations(90, [], {"detected_count": 0, "files": []}, [{"risk": "high"}], [])
        self.assertTrue(any("process" in r.lower() for r in recs))

    def test_credential_exposure(self):
        files = {"detected_count": 1, "files": [{"malicious": "Credential Exposure"}]}
        recs = ai_recommendations(90, [], files, [], [])
        self.assertTrue(any("credential" in r.lower() for r in recs))

    def test_startup_items(self):
        recs = ai_recommendations(90, [], {"detected_count": 0, "files": []}, [], [{"risk": "high"}])
        self.assertTrue(any("startup" in r.lower() for r in recs))

    def test_all_clean(self):
        recs = ai_recommendations(100, [], {"detected_count": 0, "files": []}, [], [])
        self.assertTrue(any("low" in r.lower() for r in recs))

    def test_always_ends_with_blogs_recommendation(self):
        recs = ai_recommendations(100, [], {"detected_count": 0, "files": []}, [], [])
        self.assertIn("blogs", recs[-1].lower())


# ------------------------------------------------------------------
# port_scan (localhost, minimal integration test)
# ------------------------------------------------------------------
class PortScanTests(TestCase):
    def test_returns_list(self):
        result = port_scan("127.0.0.1", [65534])
        self.assertIsInstance(result, list)

    def test_closed_port_returns_empty(self):
        result = port_scan("127.0.0.1", [1])
        self.assertEqual(result, [])


# ------------------------------------------------------------------
# Constants sanity checks
# ------------------------------------------------------------------
class ConstantsTests(TestCase):
    def test_common_ports_has_entries(self):
        self.assertGreater(len(COMMON_PORTS), 10)

    def test_risk_weight_keys(self):
        self.assertEqual(set(RISK_WEIGHT.keys()), {"low", "medium", "high", "critical"})

    def test_suspicious_extensions_are_lowercase_with_dot(self):
        for ext in SUSPICIOUS_EXTENSIONS:
            self.assertTrue(ext.startswith("."), f"{ext} missing leading dot")
            self.assertEqual(ext, ext.lower())

    def test_suspicious_names_are_lowercase(self):
        for name in SUSPICIOUS_NAMES:
            self.assertEqual(name, name.lower())

    def test_credential_patterns_compile(self):
        for label, pattern in CREDENTIAL_PATTERNS.items():
            self.assertTrue(hasattr(pattern, "search"))

    def test_text_extensions_overlap_with_suspicious(self):
        overlap = TEXT_EXTENSIONS & SUSPICIOUS_EXTENSIONS
        self.assertIn(".ps1", overlap)
