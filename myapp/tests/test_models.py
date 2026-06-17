from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from myapp.models import (
    AssetInventory,
    AuditLog,
    ComplianceCheck,
    ContactMessage,
    EndpointFingerprint,
    FileMonitorEvent,
    Incident,
    IOC,
    MitreMapping,
    MitreTechnique,
    QuarantineItem,
    RiskAssessment,
    ScanResult,
    ThreatFinding,
    ThreatIntel,
    ThreatTimeline,
    UserActivity,
)

User = get_user_model()


# ------------------------------------------------------------------
# CustomUser
# ------------------------------------------------------------------
class CustomUserTests(TestCase):
    def test_str(self):
        user = User.objects.create_user(username="testuser", password="pass1234")
        self.assertEqual(str(user), "testuser")

    def test_default_fields(self):
        user = User.objects.create_user(username="u2", password="pass1234")
        self.assertFalse(user.is_analyst)
        self.assertIsNone(user.phone)
        self.assertFalse(bool(user.profile_image))

    def test_analyst_flag(self):
        user = User.objects.create_user(username="analyst1", password="pass1234")
        user.is_analyst = True
        user.save()
        user.refresh_from_db()
        self.assertTrue(user.is_analyst)


# ------------------------------------------------------------------
# AssetInventory
# ------------------------------------------------------------------
class AssetInventoryTests(TestCase):
    def test_str(self):
        asset = AssetInventory.objects.create(
            hostname="srv01",
            operating_system="Linux",
        )
        self.assertEqual(str(asset), "srv01")

    def test_defaults(self):
        asset = AssetInventory.objects.create(
            hostname="srv02",
            operating_system="Windows",
        )
        self.assertEqual(asset.risk_level, "LOW")
        self.assertEqual(asset.os_version, "")
        self.assertIsNone(asset.ip_address)


# ------------------------------------------------------------------
# EndpointFingerprint
# ------------------------------------------------------------------
class EndpointFingerprintTests(TestCase):
    def test_str(self):
        asset = AssetInventory.objects.create(hostname="ep1", operating_system="Linux")
        fp = EndpointFingerprint.objects.create(
            asset=asset,
            fingerprint_hash="abc123",
        )
        self.assertEqual(str(fp), "abc123")

    def test_defaults(self):
        asset = AssetInventory.objects.create(hostname="ep2", operating_system="Linux")
        fp = EndpointFingerprint.objects.create(
            asset=asset,
            fingerprint_hash="def456",
        )
        self.assertEqual(fp.cpu_count, 0)
        self.assertEqual(fp.ram_gb, 0)
        self.assertEqual(fp.disk_count, 0)

    def test_related_name(self):
        asset = AssetInventory.objects.create(hostname="ep3", operating_system="Linux")
        EndpointFingerprint.objects.create(asset=asset, fingerprint_hash="fp1")
        EndpointFingerprint.objects.create(asset=asset, fingerprint_hash="fp2")
        self.assertEqual(asset.fingerprints.count(), 2)


# ------------------------------------------------------------------
# ComplianceCheck
# ------------------------------------------------------------------
class ComplianceCheckTests(TestCase):
    def test_defaults(self):
        asset = AssetInventory.objects.create(hostname="cc1", operating_system="Linux")
        cc = ComplianceCheck.objects.create(asset=asset)
        self.assertEqual(cc.compliance_score, 0)
        self.assertFalse(cc.firewall_enabled)
        self.assertFalse(cc.defender_enabled)
        self.assertFalse(cc.secure_boot_enabled)
        self.assertFalse(cc.bitlocker_enabled)
        self.assertFalse(cc.uac_enabled)
        self.assertEqual(cc.failed_controls, [])


# ------------------------------------------------------------------
# ThreatFinding
# ------------------------------------------------------------------
class ThreatFindingTests(TestCase):
    def test_str(self):
        tf = ThreatFinding.objects.create(
            title="Open RDP",
            description="Port 3389 exposed",
        )
        self.assertEqual(str(tf), "Open RDP")

    def test_defaults(self):
        tf = ThreatFinding.objects.create(title="t", description="d")
        self.assertEqual(tf.severity, "LOW")
        self.assertEqual(tf.status, "OPEN")
        self.assertEqual(tf.evidence, {})


# ------------------------------------------------------------------
# Incident
# ------------------------------------------------------------------
class IncidentTests(TestCase):
    def test_str(self):
        inc = Incident.objects.create(
            incident_id="INC-001",
            title="Breach",
            description="Data breach",
            severity="HIGH",
        )
        self.assertEqual(str(inc), "INC-001")

    def test_default_status(self):
        inc = Incident.objects.create(
            incident_id="INC-002",
            title="Test",
            description="Test",
            severity="LOW",
        )
        self.assertEqual(inc.status, "OPEN")


# ------------------------------------------------------------------
# ThreatIntel
# ------------------------------------------------------------------
class ThreatIntelTests(TestCase):
    def test_str(self):
        ti = ThreatIntel.objects.create(
            indicator="192.168.1.1",
            indicator_type="IP",
            source="test",
        )
        self.assertEqual(str(ti), "192.168.1.1")


# ------------------------------------------------------------------
# IOC
# ------------------------------------------------------------------
class IOCTests(TestCase):
    def test_str(self):
        ioc = IOC.objects.create(
            ioc_type="IP",
            value="10.0.0.1",
            source="manual",
        )
        self.assertEqual(str(ioc), "10.0.0.1")

    def test_unique_value(self):
        IOC.objects.create(ioc_type="IP", value="10.0.0.2", source="a")
        with self.assertRaises(Exception):
            IOC.objects.create(ioc_type="IP", value="10.0.0.2", source="b")


# ------------------------------------------------------------------
# MitreTechnique / MitreMapping
# ------------------------------------------------------------------
class MitreTechniqueTests(TestCase):
    def test_str(self):
        t = MitreTechnique.objects.create(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="Execution",
            description="desc",
        )
        self.assertEqual(str(t), "T1059")


class MitreMappingTests(TestCase):
    def test_creation(self):
        finding = ThreatFinding.objects.create(title="f", description="d")
        technique = MitreTechnique.objects.create(
            technique_id="T1046",
            technique_name="Network Service Scan",
            tactic="Discovery",
            description="desc",
        )
        mapping = MitreMapping.objects.create(
            finding=finding,
            technique=technique,
            confidence=80,
        )
        self.assertEqual(mapping.confidence, 80)


# ------------------------------------------------------------------
# ThreatTimeline
# ------------------------------------------------------------------
class ThreatTimelineTests(TestCase):
    def test_str_truncates(self):
        event_text = "A" * 200
        tt = ThreatTimeline.objects.create(event=event_text)
        self.assertEqual(len(str(tt)), 100)

    def test_default_severity(self):
        tt = ThreatTimeline.objects.create(event="test")
        self.assertEqual(tt.severity, "INFO")


# ------------------------------------------------------------------
# QuarantineItem
# ------------------------------------------------------------------
class QuarantineItemTests(TestCase):
    def test_str(self):
        qi = QuarantineItem.objects.create(
            file_name="malware.exe",
            original_path="/tmp/malware.exe",
            quarantine_path="/quarantine/malware.exe",
            sha256="a" * 64,
        )
        self.assertEqual(str(qi), "malware.exe")


# ------------------------------------------------------------------
# RiskAssessment
# ------------------------------------------------------------------
class RiskAssessmentTests(TestCase):
    def test_defaults(self):
        ra = RiskAssessment.objects.create(level="LOW")
        self.assertEqual(ra.score, 0)
        self.assertEqual(ra.findings_count, 0)


# ------------------------------------------------------------------
# FileMonitorEvent
# ------------------------------------------------------------------
class FileMonitorEventTests(TestCase):
    def test_creation(self):
        fme = FileMonitorEvent.objects.create(
            file_path="/etc/hosts",
            event_type="MODIFIED",
        )
        self.assertEqual(fme.event_type, "MODIFIED")
        self.assertEqual(fme.sha256, "")


# ------------------------------------------------------------------
# ScanResult
# ------------------------------------------------------------------
class ScanResultTests(TestCase):
    def test_str(self):
        user = User.objects.create_user(username="scanner", password="pass1234")
        sr = ScanResult.objects.create(user=user, scan_type="combined", score=85)
        self.assertIn("combined", str(sr))

    def test_defaults(self):
        sr = ScanResult.objects.create(scan_type="system")
        self.assertEqual(sr.score, 100)
        self.assertEqual(sr.risk_level, "LOW")
        self.assertEqual(sr.open_ports, [])
        self.assertEqual(sr.detected_files, [])
        self.assertEqual(sr.protocols, [])
        self.assertEqual(sr.modules, {})
        self.assertEqual(sr.recommendations, [])

    def test_null_user(self):
        sr = ScanResult.objects.create(scan_type="network")
        self.assertIsNone(sr.user)


# ------------------------------------------------------------------
# UserActivity
# ------------------------------------------------------------------
class UserActivityTests(TestCase):
    def test_str_with_user(self):
        user = User.objects.create_user(username="uauser", password="pass1234")
        ua = UserActivity.objects.create(user=user, option_used="scan")
        self.assertIn("uauser", str(ua))
        self.assertIn("scan", str(ua))

    def test_str_anonymous(self):
        ua = UserActivity.objects.create(option_used="browse")
        self.assertIn("Anonymous", str(ua))


# ------------------------------------------------------------------
# ContactMessage
# ------------------------------------------------------------------
class ContactMessageTests(TestCase):
    def test_str(self):
        cm = ContactMessage.objects.create(
            name="Alice",
            email="alice@test.com",
            message="Hello",
        )
        self.assertIn("suggestion", str(cm))
        self.assertIn("alice@test.com", str(cm))

    def test_default_type(self):
        cm = ContactMessage.objects.create(
            name="Bob",
            email="bob@test.com",
            message="Hi",
        )
        self.assertEqual(cm.message_type, "suggestion")
        self.assertFalse(cm.is_resolved)


# ------------------------------------------------------------------
# AuditLog
# ------------------------------------------------------------------
class AuditLogTests(TestCase):
    def test_str(self):
        al = AuditLog.objects.create(action="Login", details="ok")
        self.assertEqual(str(al), "Login")
