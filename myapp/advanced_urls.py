"""
Advanced Threat Detection URLs - Route configuration for intermediate/advanced modules
"""

from django.urls import path
from . import advanced_views

app_name = "advanced"

urlpatterns = [
    
    # ========== MALWARE ANALYSIS ==========
    path("malware-analysis/", advanced_views.malware_analysis_dashboard, name="malware_analysis"),
    path("file-reputation/", advanced_views.file_reputation_check, name="file_reputation_check"),
    path("malware-family/<str:family_name>/", advanced_views.malware_family_analysis, name="malware_family"),
    
    # ========== PROCESS ANALYSIS ==========
    path("process-analysis/", advanced_views.process_analysis_dashboard, name="process_analysis"),
    path("behavioral-threats/", advanced_views.behavioral_threat_detection, name="behavioral_threats"),
    
    # ========== NETWORK THREAT INTELLIGENCE ==========
    path("network-threat-intel/", advanced_views.network_threat_intelligence, name="network_threat_intel"),
    path("ip-reputation/<str:ip_address>/", advanced_views.ip_reputation_lookup, name="ip_reputation"),
    path("domain-reputation/<str:domain>/", advanced_views.domain_reputation_lookup, name="domain_reputation"),
    
    # ========== REAL-TIME MONITORING ==========
    path("real-time-monitoring/", advanced_views.real_time_monitoring_dashboard, name="real_time_monitoring"),
    path("fim-dashboard/", advanced_views.file_integrity_dashboard, name="fim_dashboard"),
    path("usb-monitoring/", advanced_views.usb_monitoring_dashboard, name="usb_monitoring"),
    
    # ========== INCIDENT RESPONSE & FORENSICS ==========
    path("forensic-analysis/", advanced_views.forensic_analysis_dashboard, name="forensic_analysis"),
    path("forensic-snapshot/<str:snapshot_id>/", advanced_views.forensic_snapshot_detail, name="forensic_snapshot"),
    
    # ========== THREAT HUNTING & IOC ==========
    path("threat-hunting/", advanced_views.threat_hunting_dashboard, name="threat_hunting"),
    path("ioc-lookup/<str:ioc_type>/<str:ioc_value>/", advanced_views.ioc_lookup, name="ioc_lookup"),
    
    # ========== ATTACK PATTERNS & KILL CHAIN ==========
    path("attack-patterns/", advanced_views.attack_pattern_dashboard, name="attack_patterns"),
    path("kill-chain/", advanced_views.kill_chain_visualization, name="kill_chain"),
    
    # ========== RISK ASSESSMENT ==========
    path("risk-metrics/", advanced_views.risk_metrics_dashboard, name="risk_metrics"),
    
    # ========== API ENDPOINTS ==========
    path("api/live-alerts/", advanced_views.api_live_alerts, name="api_live_alerts"),
    path("api/threat-stats/", advanced_views.api_threat_stats, name="api_threat_stats"),
    path("api/risk-score/", advanced_views.api_risk_score, name="api_risk_score"),
    path("api/recent-threats/", advanced_views.api_recent_threats, name="api_recent_threats"),
]
