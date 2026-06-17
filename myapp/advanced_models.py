"""
Advanced Cyber Security Models - Extended Threat Intelligence & Detection
"""

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


# ==========================================================
# MALWARE ANALYSIS & FILE REPUTATION
# ==========================================================

class MalwareSignature(models.Model):
    """Store known malware signatures and hashes"""
    
    THREAT_TYPES = [
        ("TROJAN", "Trojan"),
        ("RANSOMWARE", "Ransomware"),
        ("WORM", "Worm"),
        ("VIRUS", "Virus"),
        ("ADWARE", "Adware"),
        ("SPYWARE", "Spyware"),
        ("PUP", "PUP"),
        ("ROOTKIT", "Rootkit"),
        ("BACKDOOR", "Backdoor"),
        ("CRYPTOMINER", "Cryptominer"),
    ]
    
    threat_type = models.CharField(
        max_length=50,
        choices=THREAT_TYPES
    )
    
    name = models.CharField(max_length=255)
    
    sha256 = models.CharField(
        max_length=128,
        unique=True,
        db_index=True
    )
    
    md5 = models.CharField(
        max_length=64,
        blank=True
    )
    
    file_type = models.CharField(max_length=50)
    
    family = models.CharField(max_length=200)
    
    severity = models.CharField(max_length=20)
    
    first_seen = models.DateTimeField(auto_now_add=True)
    
    last_seen = models.DateTimeField(auto_now=True)
    
    detection_count = models.IntegerField(default=1)
    
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return f"{self.threat_type}: {self.name}"


class FileReputation(models.Model):
    """Track file reputation from threat intelligence sources"""
    
    VERDICT_CHOICES = [
        ("CLEAN", "Clean"),
        ("SUSPICIOUS", "Suspicious"),
        ("MALICIOUS", "Malicious"),
        ("UNKNOWN", "Unknown"),
    ]
    
    sha256 = models.CharField(
        max_length=128,
        unique=True,
        db_index=True
    )
    
    verdict = models.CharField(
        max_length=20,
        choices=VERDICT_CHOICES,
        default="UNKNOWN"
    )
    
    vt_detection_count = models.IntegerField(default=0)
    
    vt_detection_ratio = models.CharField(max_length=20)
    
    first_submission_date = models.DateTimeField(null=True, blank=True)
    
    last_analysis_date = models.DateTimeField(null=True, blank=True)
    
    tags = models.JSONField(default=list)
    
    checked_at = models.DateTimeField(auto_now_add=True)
    
    last_checked = models.DateTimeField(auto_now=True)


# ==========================================================
# PROCESS & BEHAVIOR ANALYSIS
# ==========================================================

class ProcessAnalysis(models.Model):
    """Analyze suspicious process behavior"""
    
    PROCESS_THREATS = [
        ("MASQUERADING", "Process Masquerading"),
        ("INJECTION", "Process Injection"),
        ("PARENT_ANOMALY", "Parent/Child Anomaly"),
        ("PRIVILEGE_ESCALATION", "Privilege Escalation"),
        ("CREDENTIAL_DUMP", "Credential Dumping"),
        ("PERSISTENCE", "Persistence Activity"),
        ("C2_CALLBACK", "C2 Callback"),
        ("RESOURCE_ABUSE", "Resource Abuse"),
        ("KEYLOGGER", "Keylogger"),
        ("RANSOMWARE", "Ransomware Behavior"),
    ]
    
    process_name = models.CharField(max_length=255)
    
    process_id = models.IntegerField()
    
    threat_type = models.CharField(
        max_length=50,
        choices=PROCESS_THREATS
    )
    
    parent_process = models.CharField(max_length=255, blank=True)
    
    command_line = models.TextField()
    
    file_path = models.TextField()
    
    suspicious_dlls = models.JSONField(default=list)
    
    network_connections = models.JSONField(default=list)
    
    registry_modifications = models.JSONField(default=list)
    
    risk_score = models.IntegerField()
    
    detected_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.process_name} - {self.threat_type}"


class BehavioralThreat(models.Model):
    """Detect behavioral patterns indicating malware activity"""
    
    BEHAVIOR_TYPES = [
        ("MASS_ENCRYPTION", "Mass File Encryption"),
        ("FILE_DELETION", "Mass File Deletion"),
        ("REGISTRY_WIPE", "Registry Modification Spam"),
        ("NETWORK_SCAN", "Network Reconnaissance"),
        ("DATA_EXFILTRATION", "Data Exfiltration"),
        ("COMMAND_EXECUTION", "Command Execution"),
        ("SCHEDULED_TASK", "Suspicious Scheduled Task"),
        ("SERVICE_CREATION", "Suspicious Service Creation"),
    ]
    
    behavior_type = models.CharField(
        max_length=50,
        choices=BEHAVIOR_TYPES
    )
    
    description = models.TextField()
    
    affected_files = models.JSONField(default=list)
    
    affected_processes = models.JSONField(default=list)
    
    evidence = models.JSONField(default=dict)
    
    confidence = models.IntegerField()  # 0-100
    
    severity = models.CharField(max_length=20)
    
    detected_at = models.DateTimeField(auto_now_add=True)


# ==========================================================
# NETWORK THREAT INTELLIGENCE
# ==========================================================

class IPReputation(models.Model):
    """Track IP address reputation and threat level"""
    
    THREAT_LEVELS = [
        ("CLEAN", "Clean"),
        ("SUSPICIOUS", "Suspicious"),
        ("MALICIOUS", "Malicious"),
        ("C2", "C2 Server"),
        ("SCANNER", "Scanner"),
        ("PHISHING", "Phishing"),
        ("BOTNET", "Botnet"),
    ]
    
    ip_address = models.CharField(
        max_length=45,
        unique=True,
        db_index=True
    )
    
    threat_level = models.CharField(
        max_length=20,
        choices=THREAT_LEVELS,
        default="CLEAN"
    )
    
    country = models.CharField(max_length=100)
    
    abuse_score = models.IntegerField(default=0)  # AbuseIPDB
    
    is_vpn = models.BooleanField(default=False)
    
    is_tor = models.BooleanField(default=False)
    
    is_proxy = models.BooleanField(default=False)
    
    is_datacenter = models.BooleanField(default=False)
    
    reports = models.JSONField(default=list)
    
    last_checked = models.DateTimeField(auto_now_add=True)


class DomainReputation(models.Model):
    """Track domain reputation and C2 infrastructure"""
    
    domain = models.CharField(
        max_length=255,
        unique=True,
        db_index=True
    )
    
    reputation = models.CharField(max_length=50)
    
    is_phishing = models.BooleanField(default=False)
    
    is_malware_site = models.BooleanField(default=False)
    
    is_c2 = models.BooleanField(default=False)
    
    threat_type = models.CharField(max_length=100, blank=True)
    
    resolved_ips = models.JSONField(default=list)
    
    associated_malware = models.JSONField(default=list)
    
    registrar = models.CharField(max_length=200, blank=True)
    
    creation_date = models.DateTimeField(null=True, blank=True)
    
    last_checked = models.DateTimeField(auto_now_add=True)


# ==========================================================
# REAL-TIME MONITORING
# ==========================================================

class FileIntegrityEvent(models.Model):
    """File Integrity Monitoring (FIM) events"""
    
    EVENT_TYPES = [
        ("CREATED", "Created"),
        ("MODIFIED", "Modified"),
        ("DELETED", "Deleted"),
        ("PERMISSION_CHANGED", "Permission Changed"),
        ("ATTRIBUTES_CHANGED", "Attributes Changed"),
    ]
    
    RISK_LEVELS = [
        ("LOW", "Low"),
        ("MEDIUM", "Medium"),
        ("HIGH", "High"),
        ("CRITICAL", "Critical"),
    ]
    
    file_path = models.TextField(db_index=True)
    
    event_type = models.CharField(max_length=30, choices=EVENT_TYPES)
    
    risk_level = models.CharField(max_length=20, choices=RISK_LEVELS)
    
    hash_before = models.CharField(max_length=128, blank=True)
    
    hash_after = models.CharField(max_length=128, blank=True)
    
    size_before = models.BigIntegerField(null=True, blank=True)
    
    size_after = models.BigIntegerField(null=True, blank=True)
    
    detected_at = models.DateTimeField(auto_now_add=True, db_index=True)
    
    alert_sent = models.BooleanField(default=False)


class USBDeviceActivity(models.Model):
    """Monitor USB device insertions and file transfers"""
    
    device_name = models.CharField(max_length=255)
    
    device_id = models.CharField(max_length=255, unique=True)
    
    vendor = models.CharField(max_length=255, blank=True)
    
    serial_number = models.CharField(max_length=255, blank=True)
    
    capacity_gb = models.FloatField(null=True, blank=True)
    
    files_scanned = models.IntegerField(default=0)
    
    suspicious_files = models.IntegerField(default=0)
    
    malware_detected = models.IntegerField(default=0)
    
    threat_details = models.JSONField(default=list)
    
    inserted_at = models.DateTimeField(auto_now_add=True)
    
    removed_at = models.DateTimeField(null=True, blank=True)


class RealTimeAlert(models.Model):
    """Real-time security alerts"""
    
    ALERT_TYPES = [
        ("MALWARE", "Malware Detection"),
        ("INTRUSION", "Intrusion Attempt"),
        ("DATA_EXFIL", "Data Exfiltration"),
        ("PERSISTENCE", "Persistence Detected"),
        ("LATERAL_MOVE", "Lateral Movement"),
        ("PRIVILEGE_ESC", "Privilege Escalation"),
        ("CREDENTIAL", "Credential Theft"),
        ("C2", "C2 Communication"),
        ("EXPLOIT", "Exploit Attempt"),
    ]
    
    alert_type = models.CharField(max_length=50, choices=ALERT_TYPES)
    
    severity = models.CharField(max_length=20)
    
    title = models.CharField(max_length=500)
    
    description = models.TextField()
    
    source = models.CharField(max_length=100)
    
    indicators = models.JSONField(default=dict)
    
    recommendations = models.JSONField(default=list)
    
    is_acknowledged = models.BooleanField(default=False)
    
    is_resolved = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    
    resolved_at = models.DateTimeField(null=True, blank=True)


# ==========================================================
# INCIDENT RESPONSE & FORENSICS
# ==========================================================

class ForensicSnapshot(models.Model):
    """Capture system state for forensic analysis"""
    
    snapshot_id = models.CharField(max_length=64, unique=True)
    
    snapshot_type = models.CharField(max_length=50)  # full, process, network, etc.
    
    running_processes = models.JSONField(default=list)
    
    network_connections = models.JSONField(default=list)
    
    open_files = models.JSONField(default=list)
    
    system_info = models.JSONField(default=dict)
    
    event_logs = models.JSONField(default=list)
    
    registry_data = models.JSONField(default=dict, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    associated_incident = models.CharField(max_length=50, blank=True)


class RemediationAction(models.Model):
    """Track remediation actions taken on threats"""
    
    ACTION_TYPES = [
        ("KILL_PROCESS", "Kill Process"),
        ("DELETE_FILE", "Delete File"),
        ("QUARANTINE", "Quarantine"),
        ("BLOCK_IP", "Block IP"),
        ("DISABLE_ACCOUNT", "Disable Account"),
        ("REMOVE_PERSISTENCE", "Remove Persistence"),
        ("ROLLBACK", "Rollback"),
    ]
    
    STATUS_CHOICES = [
        ("PENDING", "Pending"),
        ("IN_PROGRESS", "In Progress"),
        ("SUCCESS", "Success"),
        ("FAILED", "Failed"),
    ]
    
    threat_id = models.CharField(max_length=64)
    
    action_type = models.CharField(max_length=50, choices=ACTION_TYPES)
    
    target = models.CharField(max_length=500)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    
    result = models.TextField(blank=True)
    
    executed_by = models.CharField(max_length=100)
    
    executed_at = models.DateTimeField(auto_now_add=True)


# ==========================================================
# THREAT HUNTING & IOC TRACKING
# ==========================================================

class ThreatHuntingRule(models.Model):
    """Threat hunting rules and yara patterns"""
    
    RULE_TYPES = [
        ("YARA", "YARA Rule"),
        ("SIGMA", "Sigma Rule"),
        ("IOC", "IOC Pattern"),
        ("BEHAVIOR", "Behavior Pattern"),
    ]
    
    rule_name = models.CharField(max_length=255, unique=True)
    
    rule_type = models.CharField(max_length=50, choices=RULE_TYPES)
    
    description = models.TextField()
    
    rule_content = models.TextField()  # YARA/Sigma rule code
    
    created_by = models.CharField(max_length=100)
    
    is_active = models.BooleanField(default=True)
    
    last_execution = models.DateTimeField(null=True, blank=True)
    
    match_count = models.IntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    updated_at = models.DateTimeField(auto_now=True)


class IndicatorOfCompromise(models.Model):
    """Store and track IOCs from threat intelligence sources"""
    
    IOC_TYPES = [
        ("HASH", "Hash"),
        ("IP", "IP Address"),
        ("DOMAIN", "Domain"),
        ("URL", "URL"),
        ("EMAIL", "Email"),
        ("REGISTRY", "Registry Key"),
        ("FILENAME", "Filename"),
        ("C2", "C2 Infrastructure"),
    ]
    
    ioc_type = models.CharField(max_length=50, choices=IOC_TYPES)
    
    value = models.CharField(max_length=1000, db_index=True)
    
    source = models.CharField(max_length=200)  # VirusTotal, AlienVault, etc.
    
    threat_name = models.CharField(max_length=255)
    
    confidence = models.IntegerField()  # 0-100
    
    last_seen = models.DateTimeField(null=True, blank=True)
    
    matches_found = models.IntegerField(default=0)
    
    is_active = models.BooleanField(default=True)
    
    discovered_at = models.DateTimeField(auto_now_add=True)


# ==========================================================
# THREAT INTELLIGENCE AGGREGATION
# ==========================================================

class ThreatIntelFeed(models.Model):
    """External threat intelligence feeds"""
    
    FEED_TYPES = [
        ("VT", "VirusTotal"),
        ("ABUSEIPDB", "AbuseIPDB"),
        ("OTX", "AlienVault OTX"),
        ("MISP", "MISP"),
        ("PHISHING", "OpenPhish"),
        ("CUSTOM", "Custom Feed"),
    ]
    
    feed_name = models.CharField(max_length=255)
    
    feed_type = models.CharField(max_length=50, choices=FEED_TYPES)
    
    feed_url = models.URLField(blank=True)
    
    api_key = models.CharField(max_length=500, blank=True)
    
    is_active = models.BooleanField(default=True)
    
    last_sync = models.DateTimeField(null=True, blank=True)
    
    ioc_count = models.IntegerField(default=0)
    
    last_updated = models.DateTimeField(auto_now=True)


class ThreatIntelMatch(models.Model):
    """Correlation of findings with threat intelligence"""
    
    finding_id = models.IntegerField()
    
    ioc_value = models.CharField(max_length=1000)
    
    threat_name = models.CharField(max_length=255)
    
    threat_actor = models.CharField(max_length=255, blank=True)
    
    campaign = models.CharField(max_length=255, blank=True)
    
    confidence = models.IntegerField()
    
    additional_context = models.JSONField(default=dict)
    
    matched_at = models.DateTimeField(auto_now_add=True)


# ==========================================================
# ATTACK PATTERN & KILL CHAIN ANALYSIS
# ==========================================================

class AttackPatternDetection(models.Model):
    """Map findings to MITRE ATT&CK Kill Chain"""
    
    attack_id = models.CharField(max_length=100, unique=True)
    
    kill_chain_phase = models.CharField(max_length=100)
    
    mitre_techniques = models.JSONField(default=list)  # List of T###
    
    indicators_found = models.JSONField(default=list)
    
    confidence = models.IntegerField()
    
    affected_systems = models.IntegerField(default=1)
    
    first_detected = models.DateTimeField(auto_now_add=True)
    
    last_detected = models.DateTimeField(auto_now=True)


# ==========================================================
# COMPLIANCE & RISK SCORING
# ==========================================================

class ComplianceFramework(models.Model):
    """Track compliance against security frameworks"""
    
    FRAMEWORKS = [
        ("CIS", "CIS Controls"),
        ("NIST", "NIST 800-53"),
        ("HIPAA", "HIPAA"),
        ("PCI", "PCI DSS"),
        ("ISO", "ISO 27001"),
    ]
    
    framework = models.CharField(max_length=50, choices=FRAMEWORKS)
    
    control_id = models.CharField(max_length=50)
    
    description = models.TextField()
    
    status = models.CharField(max_length=50)  # Compliant, Non-compliant, etc.
    
    remediation_required = models.BooleanField(default=False)
    
    due_date = models.DateTimeField(null=True, blank=True)
    
    last_assessed = models.DateTimeField(auto_now_add=True)


class RiskMetric(models.Model):
    """Calculate and track risk metrics"""
    
    scan_date = models.DateTimeField(auto_now_add=True, db_index=True)
    
    overall_risk_score = models.IntegerField()
    
    critical_findings = models.IntegerField(default=0)
    
    high_findings = models.IntegerField(default=0)
    
    medium_findings = models.IntegerField(default=0)
    
    low_findings = models.IntegerField(default=0)
    
    unique_threats = models.IntegerField(default=0)
    
    affected_assets = models.IntegerField(default=0)
    
    trending = models.CharField(max_length=20)  # UP, DOWN, STABLE
    
    risk_breakdown = models.JSONField(default=dict)
