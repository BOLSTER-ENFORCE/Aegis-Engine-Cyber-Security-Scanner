"""
Shared utilities used across views, scan_engine, and scanner_backend.

Centralises helpers that were previously duplicated in multiple modules.
"""

import platform
import socket

import psutil


# ------------------------------------------------------------------
# Unit conversion
# ------------------------------------------------------------------

def bytes_to_gb(value, decimals=2):
    """Convert bytes to gigabytes, rounded to *decimals* places."""
    return round(value / (1024 ** 3), decimals)


def bytes_to_mb(value, decimals=2):
    """Convert bytes to megabytes, rounded to *decimals* places."""
    return round(value / (1024 ** 2), decimals)


# ------------------------------------------------------------------
# Risk-level helpers
# ------------------------------------------------------------------

def security_score_to_level(score):
    """Map a 0-100 *security* score to a risk label.

    Higher score == safer endpoint.  Used by the scan engine.
    """
    if score >= 85:
        return "LOW"
    if score >= 70:
        return "MEDIUM"
    if score >= 45:
        return "HIGH"
    return "CRITICAL"


def risk_score_to_level(score):
    """Map a 0-100 *risk* score to a severity label.

    Higher score == more risk.  Used by the advanced threat views.
    """
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "MINIMAL"


# ------------------------------------------------------------------
# Activity tracking
# ------------------------------------------------------------------

def track_activity(request, option, detail=""):
    """Record a :class:`UserActivity` row if the user is authenticated."""
    if request.user.is_authenticated:
        from .models import UserActivity

        UserActivity.objects.create(
            user=request.user,
            option_used=option,
            detail=detail,
        )


# ------------------------------------------------------------------
# Threat severity counting
# ------------------------------------------------------------------

def get_threat_severity_counts():
    """Return a dict with finding counts keyed by severity level."""
    from .models import ThreatFinding

    return {
        "critical": ThreatFinding.objects.filter(severity="CRITICAL").count(),
        "high": ThreatFinding.objects.filter(severity="HIGH").count(),
        "medium": ThreatFinding.objects.filter(severity="MEDIUM").count(),
        "low": ThreatFinding.objects.filter(severity="LOW").count(),
    }


# ------------------------------------------------------------------
# Base system information (shared by scan_engine & scanner_backend)
# ------------------------------------------------------------------

def base_system_info():
    """Return the system fields common to both profiling functions."""
    return {
        "hostname": socket.gethostname(),
        "os_name": platform.system(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "ram_total_gb": bytes_to_gb(psutil.virtual_memory().total),
    }
