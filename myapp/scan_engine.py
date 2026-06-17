import hashlib
import os
import platform
import re
import socket
import uuid
from pathlib import Path

import psutil

from .utils import base_system_info, bytes_to_gb, security_score_to_level


COMMON_PORTS = {
    20: ("FTP data", "File transfer channel. Risky when exposed without encryption.", "high"),
    21: ("FTP", "Plain FTP can expose credentials and files.", "high"),
    22: ("SSH", "Remote administration. Safe when patched and key protected.", "medium"),
    23: ("Telnet", "Unencrypted remote shell. Usually harmful if open.", "critical"),
    25: ("SMTP", "Mail transfer. Can be abused for spam if misconfigured.", "medium"),
    53: ("DNS", "Name resolution. Public exposure can enable abuse if recursive.", "medium"),
    80: ("HTTP", "Web service. Safe if intended, risky if unpatched.", "medium"),
    110: ("POP3", "Mail retrieval without modern protection is risky.", "medium"),
    135: ("RPC", "Windows RPC. Avoid exposing outside trusted networks.", "high"),
    139: ("NetBIOS", "Legacy Windows sharing. Risky on public networks.", "high"),
    143: ("IMAP", "Mail retrieval. Prefer encrypted IMAPS.", "medium"),
    443: ("HTTPS", "Encrypted web service. Usually safe if configured well.", "low"),
    445: ("SMB", "Windows file sharing. Harmful when exposed to the internet.", "critical"),
    3306: ("MySQL", "Database service. Should not be public.", "high"),
    3389: ("RDP", "Remote desktop. High brute-force target.", "critical"),
    5432: ("PostgreSQL", "Database service. Should be restricted.", "high"),
    5900: ("VNC", "Remote desktop. Risky unless tightly controlled.", "high"),
    8000: ("Django dev server", "Development web server. Do not expose publicly.", "medium"),
    8080: ("HTTP alternate", "Web/proxy service. Review if intended.", "medium"),
}

RISK_WEIGHT = {
    "low": 3,
    "medium": 8,
    "high": 15,
    "critical": 25,
}

SUSPICIOUS_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".dll",
    ".docm",
    ".exe",
    ".iso",
    ".jar",
    ".js",
    ".pdf",
    ".ps1",
    ".rar",
    ".scr",
    ".vbs",
    ".xlsm",
    ".zip",
}

SUSPICIOUS_NAMES = (
    "mimikatz",
    "keylogger",
    "meterpreter",
    "payload",
    "ransom",
    "reverse_shell",
    "trojan",
)

CREDENTIAL_PATTERNS = {
    "Private key": re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Generic API token": re.compile(r"(?i)\b(api[_-]?key|token|secret)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"),
    "Password assignment": re.compile(r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*['\"]?[^'\"\s]{6,}"),
    "Bearer token": re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-.]{20,}"),
}

TEXT_EXTENSIONS = {
    ".cfg",
    ".conf",
    ".env",
    ".ini",
    ".json",
    ".log",
    ".ps1",
    ".py",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}


def _sha256(path):
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""


def profile_system():
    info = base_system_info()
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage(str(Path.home().anchor or "C:\\"))
    info.update({
        "ip_address": _local_ip(),
        "mac_address": ":".join(f"{(uuid.getnode() >> bits) & 0xff:02x}" for bits in range(40, -1, -8)),
        "cpu_count": psutil.cpu_count(),
        "ram_available_gb": bytes_to_gb(memory.available),
        "disk_total_gb": bytes_to_gb(disk.total),
        "disk_free_gb": bytes_to_gb(disk.free),
        "endpoint_fingerprint": hashlib.sha256(
            f"{platform.node()}-{platform.processor()}-{platform.machine()}-{uuid.getnode()}".encode()
        ).hexdigest(),
    })
    return info


def _local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def compliance_check():
    checks = [
        {
            "name": "Firewall",
            "status": "Review",
            "risk": "medium",
            "detail": "Confirm Windows Firewall is enabled for public and private profiles.",
        },
        {
            "name": "Defender or antivirus",
            "status": "Review",
            "risk": "medium",
            "detail": "Confirm real-time protection is enabled and signatures are current.",
        },
        {
            "name": "Secure Boot",
            "status": "Review",
            "risk": "medium",
            "detail": "Enable Secure Boot where supported to reduce boot-level tampering.",
        },
        {
            "name": "BitLocker",
            "status": "Review",
            "risk": "medium",
            "detail": "Encrypt portable devices and laptops that store sensitive data.",
        },
        {
            "name": "UAC",
            "status": "Review",
            "risk": "low",
            "detail": "Keep User Account Control enabled for privilege-change prompts.",
        },
    ]
    return {
        "cis_summary": "Baseline-style local review. Manual confirmation is required for exact CIS compliance.",
        "checks": checks,
    }


def process_audit(limit=80):
    suspicious = []
    for proc in psutil.process_iter(["pid", "name", "exe", "username", "cpu_percent", "memory_percent", "cmdline"]):
        try:
            info = proc.info
            name = (info.get("name") or "").lower()
            exe = info.get("exe") or ""
            cmdline = " ".join(info.get("cmdline") or [])
            if any(token in name or token in exe.lower() for token in SUSPICIOUS_NAMES):
                suspicious.append({
                    "pid": info.get("pid"),
                    "name": info.get("name"),
                    "path": exe,
                    "risk": "high",
                    "reason": "Name or path matches common offensive/malware keywords.",
                    "resolution": "Verify publisher, isolate if unknown, and scan with antivirus.",
                })
            if _contains_credential(cmdline):
                suspicious.append({
                    "pid": info.get("pid"),
                    "name": info.get("name"),
                    "path": exe,
                    "risk": "critical",
                    "reason": "Credential-like token or password appears in process command line.",
                    "resolution": "Stop the process if unauthorized, rotate the exposed secret, and remove secrets from scripts.",
                })
            if "powershell" in name and ("-enc" in cmdline.lower() or "frombase64string" in cmdline.lower()):
                suspicious.append({
                    "pid": info.get("pid"),
                    "name": info.get("name"),
                    "path": exe,
                    "risk": "high",
                    "reason": "Encoded PowerShell command detected.",
                    "resolution": "Inspect the command, parent process, and script source before trusting it.",
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if len(suspicious) >= limit:
            break
    return suspicious


def _contains_credential(text):
    return bool(text and any(pattern.search(text) for pattern in CREDENTIAL_PATTERNS.values()))


def startup_audit():
    entries = []
    folders = [
        Path(os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")),
        Path(os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup")),
    ]
    for folder in folders:
        if not folder.exists():
            continue
        for item in folder.iterdir():
            suffix = item.suffix.lower()
            risky = suffix in {".bat", ".cmd", ".ps1", ".vbs", ".js", ".exe"}
            entries.append({
                "name": item.name,
                "path": str(item),
                "risk": "high" if risky else "low",
                "reason": "Script or executable starts automatically." if risky else "Normal startup item.",
                "resolution": "Disable unknown startup entries and verify publisher." if risky else "No action needed if recognized.",
            })
    return entries


def active_network_connections(limit=120):
    rows = []
    for conn in psutil.net_connections(kind="inet"):
        if not conn.laddr:
            continue
        port = conn.laddr.port
        service, why, risk = COMMON_PORTS.get(port, ("Unknown service", "Open by an application or OS service.", "medium"))
        rows.append({
            "local_address": conn.laddr.ip,
            "port": port,
            "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
            "status": conn.status,
            "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
            "service": service,
            "why_open": why,
            "risk": risk,
            "harmful": risk in {"high", "critical"},
            "resolution": _port_resolution(port, risk),
        })
        if len(rows) >= limit:
            break
    return sorted(rows, key=lambda row: (row["risk"], row["port"]))


def port_scan(host="127.0.0.1", ports=None):
    ports = ports or sorted(COMMON_PORTS)
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.08)
            if sock.connect_ex((host, port)) == 0:
                service, why, risk = COMMON_PORTS.get(port, ("Unknown service", "Open by an application.", "medium"))
                open_ports.append({
                    "host": host,
                    "port": port,
                    "protocol": "TCP",
                    "service": service,
                    "why_open": why,
                    "risk": risk,
                    "harmful": risk in {"high", "critical"},
                    "resolution": _port_resolution(port, risk),
                })
    return open_ports


def _port_resolution(port, risk):
    if risk == "critical":
        return f"Close port {port} if not required, restrict it with firewall rules, and patch the owning service."
    if risk == "high":
        return f"Limit port {port} to trusted IP addresses and disable it if unused."
    if risk == "medium":
        return f"Confirm the service on port {port} is intentional and not exposed publicly."
    return "Keep patched and monitor normally."


def file_scan(max_files=300):
    findings = []
    roots = [Path.home() / "Downloads", Path.home() / "Desktop", Path.home() / "Documents"]
    scanned = 0
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if scanned >= max_files:
                break
            if not path.is_file():
                continue
            scanned += 1
            suffix = path.suffix.lower()
            name = path.name.lower()
            suspicious = suffix in SUSPICIOUS_EXTENSIONS or any(token in name for token in SUSPICIOUS_NAMES)
            credential_matches = credential_file_scan(path) if suffix in TEXT_EXTENSIONS or path.name.lower().startswith(".env") else []
            if suspicious:
                findings.append({
                    "name": path.name,
                    "path": str(path),
                    "sha256": _sha256(path),
                    "risk": "high" if suffix in {".exe", ".dll", ".scr", ".ps1", ".vbs"} else "medium",
                    "malicious": "Suspicious",
                    "reason": "Extension or filename is commonly abused by malware.",
                    "resolution": "Do not open it. Verify the source, upload to a trusted scanner, or quarantine/delete if unknown.",
                })
            for match in credential_matches:
                findings.append({
                    "name": path.name,
                    "path": str(path),
                    "sha256": _sha256(path),
                    "risk": "critical",
                    "malicious": "Credential Exposure",
                    "reason": f"Credential detection logic matched: {match}",
                    "resolution": "Remove the secret from the file, rotate the credential, and store secrets in a protected vault or environment variable.",
                })
    return {
        "scanned_count": scanned,
        "detected_count": len(findings),
        "files": findings,
    }


def credential_file_scan(path):
    matches = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return matches
    for label, pattern in CREDENTIAL_PATTERNS.items():
        if pattern.search(text):
            matches.append(label)
    return matches[:5]


def exposure_assessment():
    shares = []
    for partition in psutil.disk_partitions(all=False):
        if "removable" in partition.opts.lower():
            shares.append({
                "share": partition.device,
                "permission": "Removable media",
                "risk": "medium",
                "reason": "USB/removable storage can introduce untrusted files.",
            })
    return shares


def identity_privilege_assessment(user=None):
    return {
        "user": getattr(user, "username", "anonymous"),
        "email": getattr(user, "email", ""),
        "is_superuser": getattr(user, "is_superuser", False),
        "is_staff": getattr(user, "is_staff", False),
        "risk": "critical" if getattr(user, "is_superuser", False) else "low",
        "reason": "Superuser accounts should be used only for administration." if getattr(user, "is_superuser", False) else "Standard user privileges reduce blast radius.",
    }


def fim_snapshot(files):
    return [
        {"file": item["path"], "change": "new_or_suspicious", "risk": item["risk"]}
        for item in files["files"][:50]
    ]


def usb_monitoring_snapshot(files):
    return {
        "device": "Removable devices checked through mounted partitions",
        "files_scanned": files["scanned_count"],
        "malicious": len([item for item in files["files"] if item["risk"] in {"high", "critical"}]),
    }


def behavioral_analysis(processes, files, connections):
    findings = []
    if len(files["files"]) >= 5:
        findings.append({
            "behavior": "multiple_suspicious_files",
            "risk": "high",
            "reason": "Several suspicious files were found in landing zones.",
        })
    if any(item["risk"] == "critical" for item in processes):
        findings.append({
            "behavior": "credential_or_encoded_process_activity",
            "risk": "critical",
            "reason": "A process exposed credentials or used suspicious encoded execution.",
        })
    if any(row["port"] in {4444, 5555, 6667, 1337} for row in connections):
        findings.append({
            "behavior": "possible_reverse_shell_or_c2",
            "risk": "critical",
            "reason": "Connection uses a port commonly associated with callbacks or tooling.",
        })
    return findings


def threat_database_matches(files, ports):
    bad_ports = {23: "Telnet exposure", 445: "SMB exposure", 3389: "RDP exposure"}
    matches = []
    for row in ports:
        if row["port"] in bad_ports:
            matches.append({
                "match": bad_ports[row["port"]],
                "confidence": "85%",
                "ioc": f"{row['protocol']}:{row['port']}",
            })
    for item in files["files"]:
        if item["malicious"] == "Credential Exposure":
            matches.append({
                "match": "Credential material on disk",
                "confidence": "95%",
                "ioc": item["sha256"],
            })
    return matches


def threat_intel_lookup():
    return {
        "status": "offline",
        "sources": ["Local IOC rules", "Port risk map", "Suspicious filename heuristics"],
        "note": "External feeds require API keys; this build uses local analysis only.",
    }


def osi_model():
    return [
        {"layer": 7, "name": "Application", "examples": "HTTP, DNS, SMTP", "security": "Input validation, authentication, application logs"},
        {"layer": 6, "name": "Presentation", "examples": "TLS, encoding", "security": "Certificate validation and encryption strength"},
        {"layer": 5, "name": "Session", "examples": "RPC, SMB sessions", "security": "Session timeout and hijack protection"},
        {"layer": 4, "name": "Transport", "examples": "TCP, UDP", "security": "Open port review and firewall rules"},
        {"layer": 3, "name": "Network", "examples": "IP, ICMP", "security": "Routing, segmentation, exposure control"},
        {"layer": 2, "name": "Data Link", "examples": "Ethernet, Wi-Fi", "security": "MAC filtering and wireless security"},
        {"layer": 1, "name": "Physical", "examples": "Cable, radio", "security": "Device access and tamper protection"},
    ]


def ai_recommendations(score, ports, files, processes, startup):
    recommendations = []
    if score < 70:
        recommendations.append("Priority: reduce exposed services, review suspicious files, and patch endpoint protection before normal use.")
    if any(item["risk"] in {"high", "critical"} for item in ports):
        recommendations.append("High-risk ports are open. Restrict remote administration and file-sharing ports to trusted networks only.")
    if files["detected_count"]:
        recommendations.append("Suspicious files were found. Quarantine unknown files, verify hashes, and avoid running downloaded scripts.")
    if processes:
        recommendations.append("Suspicious processes are running. Check the executable path, digital signature, and parent process.")
    if any(item.get("malicious") == "Credential Exposure" for item in files["files"]):
        recommendations.append("Credential material was detected. Rotate exposed secrets immediately and move credentials to a secure vault.")
    if startup:
        recommendations.append("Review startup entries so unknown scripts do not run automatically after reboot.")
    if not recommendations:
        recommendations.append("Risk is currently low. Keep updates enabled, retain firewall rules, and scan downloads before opening them.")
    recommendations.append("For deeper analysis, review the linked blogs about open ports, malware triage, and OSI-layer troubleshooting.")
    return recommendations


def run_combined_scan(user=None, scan_type="combined"):
    profile = profile_system()
    compliance = compliance_check()
    processes = process_audit()
    startup = startup_audit()
    connections = active_network_connections()
    ports = port_scan()
    files = file_scan()
    exposure = exposure_assessment()
    identity = identity_privilege_assessment(user)
    behavioral = behavioral_analysis(processes, files, connections + ports)
    threat_db = threat_database_matches(files, connections + ports)
    protocols = sorted({row["protocol"] for row in connections + ports})

    risk_points = 0
    for row in connections + ports:
        risk_points += RISK_WEIGHT.get(row["risk"], 8)
    for item in files["files"]:
        risk_points += RISK_WEIGHT.get(item["risk"], 8)
    risk_points += len(processes) * 15
    risk_points += sum(RISK_WEIGHT.get(item["risk"], 3) for item in startup)
    risk_points += sum(RISK_WEIGHT.get(item["risk"], 3) for item in behavioral)
    risk_points += len(threat_db) * 10
    score = max(0, 100 - min(risk_points, 100))
    risk = security_score_to_level(score)

    return {
        "scan_type": scan_type,
        "score": score,
        "risk_level": risk,
        "profile": profile,
        "modules": {
            "asset_discovery": profile,
            "endpoint_fingerprinting": {"fingerprint": profile["endpoint_fingerprint"]},
            "security_compliance": compliance,
            "endpoint_protection": compliance["checks"][1],
            "identity_privilege_assessment": identity,
            "exposure_assessment": exposure,
            "network_exposure": connections,
            "landing_zone_scanner": files,
            "threat_hunting": processes,
            "startup_audit": startup,
            "malware_analysis": files,
            "real_time_monitoring": {"status": "dashboard_polling_enabled", "monitored": ["Downloads", "Desktop", "Documents", "WhatsApp", "USB"]},
            "usb_monitoring": usb_monitoring_snapshot(files),
            "file_integrity_monitoring": fim_snapshot(files),
            "threat_intelligence": threat_intel_lookup(),
            "ioc_correlation": threat_db,
            "threat_database": threat_db,
            "behavioral_analysis": behavioral,
            "mitre_attack": [
                {"technique": "T1547", "name": "Boot or Logon Autostart Execution", "matched": bool(startup)},
                {"technique": "T1046", "name": "Network Service Discovery", "matched": bool(ports)},
                {"technique": "T1204", "name": "User Execution", "matched": files["detected_count"] > 0},
                {"technique": "T1003", "name": "Credential Dumping / Credential Exposure", "matched": any(item.get("malicious") == "Credential Exposure" for item in files["files"])},
                {"technique": "T1059", "name": "Command and Scripting Interpreter", "matched": any("PowerShell" in item.get("reason", "") for item in processes)},
                {"technique": "T1071", "name": "Application Layer Protocol C2", "matched": bool(threat_db)},
            ],
            "quarantine": {"available": True, "mode": "manual_review_before_action"},
            "remediation": {"actions": ["kill process", "delete file", "block IP", "remove startup entry", "rotate credentials"]},
            "incident_response": {"create_incident_on_critical": True},
            "threat_timeline": [
                {"event": "Collection completed", "risk": "info"},
                {"event": "Analysis completed", "risk": risk},
                {"event": "Report generated", "risk": "info"},
            ],
            "osi_model": osi_model(),
        },
        "open_ports": ports,
        "connections": connections,
        "protocols": protocols,
        "detected_files": files,
        "recommendations": ai_recommendations(score, connections + ports, files, processes, startup),
    }
