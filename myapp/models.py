
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone


# ==========================================================
# CUSTOM USER
# ==========================================================

class CustomUser(AbstractUser):

    phone = models.CharField(
        max_length=20,
        blank=True,
        null=True
    )

    profile_image = models.ImageField(
        upload_to="profiles/",
        blank=True,
        null=True
    )

    is_analyst = models.BooleanField(
        default=False
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    updated_at = models.DateTimeField(
        auto_now=True
    )

    def __str__(self):
        return self.username


# ==========================================================
# ASSET INVENTORY
# ==========================================================

class AssetInventory(models.Model):

    hostname = models.CharField(
        max_length=255
    )

    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True
    )

    operating_system = models.CharField(
        max_length=255
    )

    os_version = models.CharField(
        max_length=255,
        blank=True
    )

    machine_type = models.CharField(
        max_length=255,
        blank=True
    )

    processor = models.CharField(
        max_length=500,
        blank=True
    )

    risk_level = models.CharField(
        max_length=50,
        default="LOW"
    )

    discovered_at = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):
        return self.hostname


# ==========================================================
# ENDPOINT FINGERPRINT
# ==========================================================

class EndpointFingerprint(models.Model):

    asset = models.ForeignKey(
        AssetInventory,
        on_delete=models.CASCADE,
        related_name="fingerprints"
    )

    fingerprint_hash = models.CharField(
        max_length=128,
        unique=True
    )

    cpu_count = models.IntegerField(
        default=0
    )

    ram_gb = models.FloatField(
        default=0
    )

    disk_count = models.IntegerField(
        default=0
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):
        return self.fingerprint_hash


# ==========================================================
# COMPLIANCE CHECK
# ==========================================================

class ComplianceCheck(models.Model):

    asset = models.ForeignKey(
        AssetInventory,
        on_delete=models.CASCADE
    )

    compliance_score = models.IntegerField(
        default=0
    )

    firewall_enabled = models.BooleanField(
        default=False
    )

    defender_enabled = models.BooleanField(
        default=False
    )

    secure_boot_enabled = models.BooleanField(
        default=False
    )

    bitlocker_enabled = models.BooleanField(
        default=False
    )

    uac_enabled = models.BooleanField(
        default=False
    )

    failed_controls = models.JSONField(
        default=list
    )

    checked_at = models.DateTimeField(
        auto_now_add=True
    )


# ==========================================================
# THREAT FINDINGS
# ==========================================================

class ThreatFinding(models.Model):

    SEVERITY_CHOICES = [

        ("LOW", "LOW"),
        ("MEDIUM", "MEDIUM"),
        ("HIGH", "HIGH"),
        ("CRITICAL", "CRITICAL"),
    ]

    STATUS_CHOICES = [

        ("OPEN", "OPEN"),
        ("INVESTIGATING", "INVESTIGATING"),
        ("RESOLVED", "RESOLVED"),
        ("CLOSED", "CLOSED"),
    ]

    title = models.CharField(
        max_length=500
    )

    description = models.TextField()

    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES,
        default="LOW"
    )

    status = models.CharField(
        max_length=30,
        choices=STATUS_CHOICES,
        default="OPEN"
    )

    evidence = models.JSONField(
        default=dict
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    updated_at = models.DateTimeField(
        auto_now=True
    )

    def __str__(self):
        return self.title

# ==========================================================
# INCIDENT MANAGEMENT
# ==========================================================

class Incident(models.Model):

    STATUS_CHOICES = [

        ("OPEN", "OPEN"),
        ("INVESTIGATING", "INVESTIGATING"),
        ("CONTAINED", "CONTAINED"),
        ("RESOLVED", "RESOLVED"),
        ("CLOSED", "CLOSED"),
    ]

    incident_id = models.CharField(
        max_length=50,
        unique=True
    )

    title = models.CharField(
        max_length=500
    )

    description = models.TextField()

    severity = models.CharField(
        max_length=20
    )

    status = models.CharField(
        max_length=30,
        choices=STATUS_CHOICES,
        default="OPEN"
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    updated_at = models.DateTimeField(
        auto_now=True
    )

    def __str__(self):
        return self.incident_id


# ==========================================================
# THREAT INTELLIGENCE
# ==========================================================

class ThreatIntel(models.Model):

    indicator = models.CharField(
        max_length=500
    )

    indicator_type = models.CharField(
        max_length=50
    )

    source = models.CharField(
        max_length=200
    )

    classification = models.CharField(
        max_length=200,
        blank=True
    )

    confidence = models.IntegerField(
        default=0
    )

    checked_at = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):
        return self.indicator


# ==========================================================
# IOC DATABASE
# ==========================================================

class IOC(models.Model):

    IOC_TYPES = [

        ("IP", "IP"),
        ("DOMAIN", "DOMAIN"),
        ("URL", "URL"),
        ("HASH", "HASH"),
    ]

    ioc_type = models.CharField(
        max_length=20,
        choices=IOC_TYPES
    )

    value = models.CharField(
        max_length=1000,
        unique=True
    )

    source = models.CharField(
        max_length=200
    )

    malicious = models.BooleanField(
        default=False
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):
        return self.value


# ==========================================================
# MITRE ATT&CK TECHNIQUES
# ==========================================================

class MitreTechnique(models.Model):

    technique_id = models.CharField(
        max_length=20,
        unique=True
    )

    technique_name = models.CharField(
        max_length=300
    )

    tactic = models.CharField(
        max_length=200
    )

    description = models.TextField()

    def __str__(self):
        return self.technique_id


# ==========================================================
# MITRE MAPPING
# ==========================================================

class MitreMapping(models.Model):

    finding = models.ForeignKey(
        ThreatFinding,
        on_delete=models.CASCADE
    )

    technique = models.ForeignKey(
        MitreTechnique,
        on_delete=models.CASCADE
    )

    confidence = models.IntegerField(
        default=50
    )

    mapped_at = models.DateTimeField(
        auto_now_add=True
    )


# ==========================================================
# THREAT TIMELINE
# ==========================================================

class ThreatTimeline(models.Model):

    event = models.TextField()

    severity = models.CharField(
        max_length=30,
        default="INFO"
    )

    timestamp = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):
        return self.event[:100]


# ==========================================================
# QUARANTINE ENGINE
# ==========================================================

class QuarantineItem(models.Model):

    file_name = models.CharField(
        max_length=500
    )

    original_path = models.TextField()

    quarantine_path = models.TextField()

    sha256 = models.CharField(
        max_length=128
    )

    quarantined_at = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):
        return self.file_name


# ==========================================================
# RISK SCORING
# ==========================================================

class RiskAssessment(models.Model):

    score = models.IntegerField(
        default=0
    )

    level = models.CharField(
        max_length=50
    )

    findings_count = models.IntegerField(
        default=0
    )

    calculated_at = models.DateTimeField(
        auto_now_add=True
    )


# ==========================================================
# FILE MONITOR EVENTS
# ==========================================================

class FileMonitorEvent(models.Model):

    EVENT_TYPES = [

        ("CREATED", "CREATED"),
        ("MODIFIED", "MODIFIED"),
        ("DELETED", "DELETED"),
    ]

    file_path = models.TextField()

    event_type = models.CharField(
        max_length=20,
        choices=EVENT_TYPES
    )

    sha256 = models.CharField(
        max_length=128,
        blank=True
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )


# ==========================================================
# COMBINED SCAN RESULTS
# ==========================================================

class ScanResult(models.Model):

    scan_type = models.CharField(
        max_length=80,
        default="combined"
    )

    user = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    score = models.IntegerField(
        default=100
    )

    risk_level = models.CharField(
        max_length=40,
        default="LOW"
    )

    open_ports = models.JSONField(
        default=list
    )

    detected_files = models.JSONField(
        default=list
    )

    protocols = models.JSONField(
        default=list
    )

    modules = models.JSONField(
        default=dict
    )

    recommendations = models.JSONField(
        default=list
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):
        return f"{self.scan_type} - {self.risk_level} - {self.created_at}"


# ==========================================================
# USER ACTIVITY
# ==========================================================

class UserActivity(models.Model):

    user = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    option_used = models.CharField(
        max_length=120
    )

    detail = models.TextField(
        blank=True
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):
        username = self.user.username if self.user else "Anonymous"
        return f"{username} used {self.option_used}"


# ==========================================================
# CONTACT / FEEDBACK
# ==========================================================

class ContactMessage(models.Model):

    MESSAGE_TYPES = [
        ("suggestion", "Suggestion"),
        ("complaint", "Complaint"),
        ("question", "Question"),
    ]

    user = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    name = models.CharField(
        max_length=150
    )

    email = models.EmailField()

    message_type = models.CharField(
        max_length=30,
        choices=MESSAGE_TYPES,
        default="suggestion"
    )

    message = models.TextField()

    is_resolved = models.BooleanField(
        default=False
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):
        return f"{self.message_type}: {self.email}"


# ==========================================================
# AUDIT LOG
# ==========================================================

class AuditLog(models.Model):

    user = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    action = models.CharField(
        max_length=300
    )

    details = models.TextField(
        blank=True
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):
        return self.action
