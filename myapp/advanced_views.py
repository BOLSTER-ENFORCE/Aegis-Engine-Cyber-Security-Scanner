"""
Advanced Threat Detection Views - Intermediate/Advanced Cybersecurity Module
"""

import json
import hashlib
from datetime import datetime, timedelta
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.http import require_http_methods
from django.db.models import Count, Q, Sum
from django.utils import timezone

from .models import (
    ThreatFinding,
    Incident,
    ScanResult,
)
from .advanced_models import (
    MalwareSignature,
    FileReputation,
    ProcessAnalysis,
    BehavioralThreat,
    IPReputation,
    DomainReputation,
    FileIntegrityEvent,
    USBDeviceActivity,
    RealTimeAlert,
    ForensicSnapshot,
    RemediationAction,
    IndicatorOfCompromise,
    ThreatIntelMatch,
    AttackPatternDetection,
    RiskMetric,
)
from .utils import get_threat_severity_counts, risk_score_to_level, track_activity


# ==========================================================
# MALWARE & FILE ANALYSIS VIEWS
# ==========================================================

@login_required
def malware_analysis_dashboard(request):
    """Comprehensive malware analysis dashboard"""
    
    track_activity(request, "malware_analysis", "Viewed malware analysis dashboard")
    
    # Get recent detections
    recent_malware = MalwareSignature.objects.filter(
        is_active=True
    ).order_by("-last_seen")[:10]
    
    # Threat type distribution
    threat_distribution = MalwareSignature.objects.values(
        'threat_type'
    ).annotate(count=Count('id')).order_by('-count')
    
    # High-risk families
    high_risk_families = MalwareSignature.objects.values(
        'family'
    ).annotate(
        count=Count('id'),
        avg_severity=Count('id')
    ).order_by('-count')[:15]
    
    context = {
        'recent_malware': recent_malware,
        'threat_distribution': threat_distribution,
        'high_risk_families': high_risk_families,
        'total_signatures': MalwareSignature.objects.count(),
        'active_threats': MalwareSignature.objects.filter(is_active=True).count(),
    }
    
    return render(request, 'myapp/malware_analysis.html', context)


@login_required
@require_http_methods(["GET", "POST"])
def file_reputation_check(request):
    """Check file reputation using VirusTotal API"""
    
    if request.method == "POST":
        sha256 = request.POST.get('sha256', '').strip().upper()
        
        if not sha256 or len(sha256) != 64:
            return JsonResponse({
                'success': False,
                'error': 'Invalid SHA256 hash format'
            }, status=400)
        
        # Check local database first
        try:
            reputation = FileReputation.objects.get(sha256=sha256)
            
            return JsonResponse({
                'success': True,
                'data': {
                    'sha256': reputation.sha256,
                    'verdict': reputation.verdict,
                    'vt_detections': reputation.vt_detection_count,
                    'ratio': reputation.vt_detection_ratio,
                    'tags': reputation.tags,
                    'last_checked': reputation.last_checked.isoformat(),
                }
            })
        except FileReputation.DoesNotExist:
            return JsonResponse({
                'success': True,
                'data': {
                    'sha256': sha256,
                    'verdict': 'UNKNOWN',
                    'message': 'File not found in database. Perform a scan to check reputation.'
                }
            })
    
    return render(request, 'myapp/file_reputation_check.html')


@login_required
def malware_family_analysis(request, family_name):
    """Analyze specific malware family"""
    
    malware_samples = MalwareSignature.objects.filter(
        family=family_name
    ).order_by('-detection_count')
    
    # Statistics
    stats = {
        'total_variants': malware_samples.count(),
        'total_detections': malware_samples.aggregate(Sum('detection_count'))['detection_count__sum'] or 0,
        'threat_types': malware_samples.values('threat_type').distinct().count(),
        'file_types': malware_samples.values('file_type').distinct(),
    }
    
    context = {
        'family_name': family_name,
        'samples': malware_samples,
        'stats': stats,
    }
    
    return render(request, 'myapp/malware_family_analysis.html', context)


# ==========================================================
# PROCESS & BEHAVIOR ANALYSIS VIEWS
# ==========================================================

@login_required
def process_analysis_dashboard(request):
    """Monitor suspicious process behavior"""
    
    track_activity(request, "process_analysis", "Viewed process analysis")
    
    # Recent suspicious processes
    suspicious_processes = ProcessAnalysis.objects.order_by(
        '-detected_at'
    )[:20]
    
    # Threat type breakdown
    threat_breakdown = ProcessAnalysis.objects.values(
        'threat_type'
    ).annotate(count=Count('id')).order_by('-count')
    
    # High-risk processes
    high_risk = ProcessAnalysis.objects.filter(
        risk_score__gte=80
    ).order_by('-risk_score')[:10]
    
    context = {
        'suspicious_processes': suspicious_processes,
        'threat_breakdown': threat_breakdown,
        'high_risk_processes': high_risk,
        'total_processes_analyzed': ProcessAnalysis.objects.count(),
        'critical_processes': ProcessAnalysis.objects.filter(risk_score__gte=90).count(),
    }
    
    return render(request, 'myapp/process_analysis.html', context)


@login_required
def behavioral_threat_detection(request):
    """Detect behavioral patterns indicating malware"""
    
    track_activity(request, "behavioral_analysis", "Viewed behavioral threat detection")
    
    # Recent behavioral detections
    recent_behaviors = BehavioralThreat.objects.order_by(
        '-detected_at'
    )[:15]
    
    # Behavior type distribution
    behavior_stats = BehavioralThreat.objects.values(
        'behavior_type'
    ).annotate(
        count=Count('id'),
        avg_confidence=Count('id')
    ).order_by('-count')
    
    # High-confidence threats
    high_confidence = BehavioralThreat.objects.filter(
        confidence__gte=80
    ).order_by('-confidence')[:10]
    
    context = {
        'recent_behaviors': recent_behaviors,
        'behavior_stats': behavior_stats,
        'high_confidence_threats': high_confidence,
        'total_behaviors': BehavioralThreat.objects.count(),
    }
    
    return render(request, 'myapp/behavioral_threats.html', context)


# ==========================================================
# NETWORK THREAT INTELLIGENCE VIEWS
# ==========================================================

@login_required
def network_threat_intelligence(request):
    """Analyze network-based threats"""
    
    track_activity(request, "network_threat_intel", "Viewed network threat intelligence")
    
    # Malicious IPs
    malicious_ips = IPReputation.objects.filter(
        threat_level__in=['MALICIOUS', 'C2', 'BOTNET']
    ).order_by('-abuse_score')[:20]
    
    # High-risk domains
    malicious_domains = DomainReputation.objects.filter(
        Q(is_malware_site=True) | Q(is_phishing=True) | Q(is_c2=True)
    ).order_by('-last_checked')[:20]
    
    # VPN/Proxy detection
    vpn_proxies = IPReputation.objects.filter(
        Q(is_vpn=True) | Q(is_proxy=True)
    ).count()
    
    # TOR exit nodes
    tor_nodes = IPReputation.objects.filter(is_tor=True).count()
    
    context = {
        'malicious_ips': malicious_ips,
        'malicious_domains': malicious_domains,
        'vpn_proxy_count': vpn_proxies,
        'tor_nodes': tor_nodes,
        'total_ip_reputation_records': IPReputation.objects.count(),
        'total_domain_records': DomainReputation.objects.count(),
    }
    
    return render(request, 'myapp/network_threat_intel.html', context)


@login_required
def ip_reputation_lookup(request, ip_address):
    """Detailed IP reputation analysis"""
    
    ip_rep = get_object_or_404(IPReputation, ip_address=ip_address)
    
    context = {
        'ip': ip_rep,
        'reports': ip_rep.reports,
    }
    
    return render(request, 'myapp/ip_reputation_detail.html', context)


@login_required
def domain_reputation_lookup(request, domain):
    """Detailed domain reputation analysis"""
    
    domain_rep = get_object_or_404(DomainReputation, domain=domain)
    
    context = {
        'domain': domain_rep,
        'associated_malware': domain_rep.associated_malware,
        'resolved_ips': domain_rep.resolved_ips,
    }
    
    return render(request, 'myapp/domain_reputation_detail.html', context)


# ==========================================================
# REAL-TIME MONITORING & ALERTS
# ==========================================================

@login_required
def real_time_monitoring_dashboard(request):
    """Real-time security monitoring"""
    
    track_activity(request, "real_time_monitoring", "Viewed real-time monitoring")
    
    # Active alerts
    active_alerts = RealTimeAlert.objects.filter(
        is_resolved=False
    ).order_by('-created_at')[:20]
    
    # Recent file integrity events
    file_events = FileIntegrityEvent.objects.order_by(
        '-detected_at'
    )[:15]
    
    # USB activity
    recent_usb = USBDeviceActivity.objects.order_by(
        '-inserted_at'
    )[:10]
    
    # Alert summary
    alert_summary = RealTimeAlert.objects.values(
        'alert_type'
    ).annotate(
        count=Count('id')
    ).order_by('-count')
    
    context = {
        'active_alerts': active_alerts,
        'file_events': file_events,
        'usb_devices': recent_usb,
        'alert_summary': alert_summary,
        'critical_alerts': RealTimeAlert.objects.filter(severity='CRITICAL').count(),
        'high_alerts': RealTimeAlert.objects.filter(severity='HIGH').count(),
    }
    
    return render(request, 'myapp/real_time_monitoring.html', context)


@login_required
def file_integrity_dashboard(request):
    """File Integrity Monitoring (FIM) dashboard"""
    
    track_activity(request, "fim_monitoring", "Viewed FIM dashboard")
    
    # Recent file changes
    recent_changes = FileIntegrityEvent.objects.order_by(
        '-detected_at'
    )[:50]
    
    # High-risk changes
    high_risk_changes = FileIntegrityEvent.objects.filter(
        risk_level__in=['HIGH', 'CRITICAL']
    ).order_by('-detected_at')[:20]
    
    # Event type distribution
    event_distribution = FileIntegrityEvent.objects.values(
        'event_type'
    ).annotate(count=Count('id')).order_by('-count')
    
    context = {
        'recent_changes': recent_changes,
        'high_risk_changes': high_risk_changes,
        'event_distribution': event_distribution,
        'total_events': FileIntegrityEvent.objects.count(),
        'critical_events': FileIntegrityEvent.objects.filter(risk_level='CRITICAL').count(),
    }
    
    return render(request, 'myapp/fim_dashboard.html', context)


@login_required
def usb_monitoring_dashboard(request):
    """USB device monitoring and threats"""
    
    track_activity(request, "usb_monitoring", "Viewed USB monitoring")
    
    # Recent USB activity
    usb_devices = USBDeviceActivity.objects.order_by(
        '-inserted_at'
    )[:30]
    
    # Devices with threats
    threat_usbs = USBDeviceActivity.objects.filter(
        malware_detected__gt=0
    ).order_by('-malware_detected')[:10]
    
    # Statistics
    stats = {
        'total_devices_seen': USBDeviceActivity.objects.count(),
        'devices_with_malware': USBDeviceActivity.objects.filter(malware_detected__gt=0).count(),
        'total_suspicious_files': USBDeviceActivity.objects.aggregate(Sum('suspicious_files'))['suspicious_files__sum'] or 0,
    }
    
    context = {
        'usb_devices': usb_devices,
        'threat_devices': threat_usbs,
        'stats': stats,
    }
    
    return render(request, 'myapp/usb_monitoring.html', context)


# ==========================================================
# INCIDENT RESPONSE & FORENSICS
# ==========================================================

@login_required
def forensic_analysis_dashboard(request):
    """Forensic analysis and incident response"""
    
    track_activity(request, "forensics", "Viewed forensic analysis")
    
    # Recent snapshots
    snapshots = ForensicSnapshot.objects.order_by(
        '-created_at'
    )[:20]
    
    # Remediation actions
    remediation_actions = RemediationAction.objects.order_by(
        '-executed_at'
    )[:15]
    
    # Action status summary
    action_status = RemediationAction.objects.values(
        'status'
    ).annotate(count=Count('id'))
    
    context = {
        'snapshots': snapshots,
        'remediation_actions': remediation_actions,
        'action_status': action_status,
        'total_snapshots': ForensicSnapshot.objects.count(),
        'failed_actions': RemediationAction.objects.filter(status='FAILED').count(),
    }
    
    return render(request, 'myapp/forensic_analysis.html', context)


@login_required
def forensic_snapshot_detail(request, snapshot_id):
    """Detailed forensic snapshot analysis"""
    
    snapshot = get_object_or_404(ForensicSnapshot, snapshot_id=snapshot_id)
    
    context = {
        'snapshot': snapshot,
        'processes_count': len(snapshot.running_processes),
        'connections_count': len(snapshot.network_connections),
        'files_count': len(snapshot.open_files),
    }
    
    return render(request, 'myapp/forensic_snapshot_detail.html', context)


# ==========================================================
# THREAT HUNTING & IOC CORRELATION
# ==========================================================

@login_required
def threat_hunting_dashboard(request):
    """Threat hunting with custom rules and IOC matching"""
    
    track_activity(request, "threat_hunting", "Viewed threat hunting")
    
    # IOC statistics
    ioc_stats = IndicatorOfCompromise.objects.values(
        'ioc_type'
    ).annotate(
        count=Count('id'),
        active_count=Count('id', filter=Q(is_active=True))
    ).order_by('-count')
    
    # Active IOCs
    active_iocs = IndicatorOfCompromise.objects.filter(
        is_active=True
    ).order_by('-matches_found')[:30]
    
    # Recent threats
    recent_threats = ThreatIntelMatch.objects.order_by(
        '-matched_at'
    )[:20]
    
    context = {
        'ioc_stats': ioc_stats,
        'active_iocs': active_iocs,
        'recent_threats': recent_threats,
        'total_iocs': IndicatorOfCompromise.objects.count(),
        'threats_detected': ThreatIntelMatch.objects.count(),
    }
    
    return render(request, 'myapp/threat_hunting.html', context)


@login_required
def ioc_lookup(request, ioc_type, ioc_value):
    """Lookup specific IOC"""
    
    ioc = get_object_or_404(
        IndicatorOfCompromise,
        ioc_type=ioc_type,
        value=ioc_value
    )
    
    # Find all matches
    matches = ThreatIntelMatch.objects.filter(ioc_value=ioc_value)
    
    context = {
        'ioc': ioc,
        'matches': matches,
    }
    
    return render(request, 'myapp/ioc_detail.html', context)


# ==========================================================
# ATTACK PATTERN & KILL CHAIN ANALYSIS
# ==========================================================

@login_required
def attack_pattern_dashboard(request):
    """MITRE ATT&CK Kill Chain analysis"""
    
    track_activity(request, "attack_patterns", "Viewed attack patterns")
    
    # Recent attacks
    recent_attacks = AttackPatternDetection.objects.order_by(
        '-first_detected'
    )[:20]
    
    # Kill chain distribution
    kill_chain_stats = AttackPatternDetection.objects.values(
        'kill_chain_phase'
    ).annotate(count=Count('id')).order_by('-count')
    
    # Most common techniques
    technique_stats = AttackPatternDetection.objects.values(
        'mitre_techniques'
    ).annotate(count=Count('id')).order_by('-count')[:15]
    
    context = {
        'recent_attacks': recent_attacks,
        'kill_chain_stats': kill_chain_stats,
        'technique_stats': technique_stats,
        'total_patterns': AttackPatternDetection.objects.count(),
    }
    
    return render(request, 'myapp/attack_patterns.html', context)


@login_required
def kill_chain_visualization(request):
    """Visualize kill chain progression"""
    
    # Aggregate data by kill chain phase
    phases = AttackPatternDetection.objects.values(
        'kill_chain_phase'
    ).annotate(
        count=Count('id'),
        systems_affected=Sum('affected_systems')
    ).order_by('kill_chain_phase')
    
    context = {
        'phases': phases,
    }
    
    return render(request, 'myapp/kill_chain_visualization.html', context)


# ==========================================================
# RISK ASSESSMENT & METRICS
# ==========================================================

@login_required
def risk_metrics_dashboard(request):
    """Overall risk metrics and trending"""
    
    track_activity(request, "risk_metrics", "Viewed risk metrics")
    
    # Latest risk assessment
    latest_risk = RiskMetric.objects.order_by('-scan_date').first()
    
    # Risk trend (last 30 days)
    thirty_days_ago = timezone.now() - timedelta(days=30)
    risk_trend = RiskMetric.objects.filter(
        scan_date__gte=thirty_days_ago
    ).order_by('scan_date')
    
    # Risk breakdown
    risk_categories = get_threat_severity_counts()
    
    context = {
        'latest_risk': latest_risk,
        'risk_trend': risk_trend,
        'risk_categories': risk_categories,
        'overall_score': latest_risk.overall_risk_score if latest_risk else 0,
    }
    
    return render(request, 'myapp/risk_metrics.html', context)


# ==========================================================
# API ENDPOINTS FOR REAL-TIME UPDATES
# ==========================================================

@login_required
@require_http_methods(["GET"])
def api_live_alerts(request):
    """Fetch live alerts via AJAX"""
    
    limit = int(request.GET.get('limit', 10))
    
    alerts = RealTimeAlert.objects.filter(
        is_resolved=False
    ).order_by('-created_at')[:limit]
    
    return JsonResponse({
        'success': True,
        'alerts': [
            {
                'id': alert.id,
                'type': alert.alert_type,
                'severity': alert.severity,
                'title': alert.title,
                'created_at': alert.created_at.isoformat(),
            }
            for alert in alerts
        ]
    })


@login_required
@require_http_methods(["GET"])
def api_threat_stats(request):
    """Fetch threat statistics"""
    
    stats = {
        'total_malware': MalwareSignature.objects.count(),
        'active_malware': MalwareSignature.objects.filter(is_active=True).count(),
        'total_iocs': IndicatorOfCompromise.objects.count(),
        'active_alerts': RealTimeAlert.objects.filter(is_resolved=False).count(),
        'critical_findings': ThreatFinding.objects.filter(severity='CRITICAL').count(),
        'incidents_open': Incident.objects.filter(status='OPEN').count(),
    }
    
    return JsonResponse({'success': True, 'stats': stats})


@login_required
@require_http_methods(["GET"])
def api_risk_score(request):
    """Get current risk score"""
    
    latest_risk = RiskMetric.objects.order_by('-scan_date').first()
    
    if not latest_risk:
        return JsonResponse({
            'success': True,
            'score': 0,
            'level': 'LOW',
            'message': 'No risk assessment available'
        })
    
    return JsonResponse({
        'success': True,
        'score': latest_risk.overall_risk_score,
        'level': risk_score_to_level(latest_risk.overall_risk_score),
        'critical': latest_risk.critical_findings,
        'high': latest_risk.high_findings,
    })


@login_required
@require_http_methods(["GET"])
def api_recent_threats(request):
    """Get recent detected threats"""
    
    limit = int(request.GET.get('limit', 5))
    
    threats = ThreatIntelMatch.objects.select_related().order_by(
        '-matched_at'
    )[:limit]
    
    return JsonResponse({
        'success': True,
        'threats': [
            {
                'threat_name': threat.threat_name,
                'ioc_value': threat.ioc_value,
                'confidence': threat.confidence,
                'matched_at': threat.matched_at.isoformat(),
            }
            for threat in threats
        ]
    })


# ==========================================================
# HELPER FUNCTIONS
# ==========================================================

# track_activity and risk_score_to_level are imported from .utils
