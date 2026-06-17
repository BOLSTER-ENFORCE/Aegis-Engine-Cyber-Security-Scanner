from django.urls import path

from . import views


urlpatterns = [
    path("", views.home, name="home"),
    path("about/", views.about, name="about"),
    path("contact/", views.contact, name="contact"),
    path("privacy/", views.privacy_policy, name="privacy"),
    path("osi-model/", views.osi_model_view, name="osi_model"),
    path("blogs/", views.blogs, name="blogs"),

    path("login/", views.user_login, name="login"),
    path("logout/", views.user_logout, name="logout"),
    path("register/", views.register, name="register"),
    path("forgot-password/", views.forgot_password, name="forgot_password"),
    path("change-password/", views.change_password, name="change_password"),

    path("dashboard/", views.dashboard, name="dashboard"),
    path("security-admin/", views.admin_dashboard, name="admin_dashboard"),
    path("profile/", views.profile, name="profile"),
    path("edit-profile/", views.edit_profile, name="edit_profile"),
    path("launcher/", views.launcher, name="launcher"),

    path("scan/", views.combined_scan, name="combined_scan"),
    path("scan/<int:result_id>/", views.scan_result, name="scan_result"),
    path("scan/<int:result_id>/pdf/", views.download_scan_pdf, name="scan_pdf"),

    path("system/", views.system_scan, name="system_scan"),
    path("network/", views.network_scan, name="network_scan"),
    path("threat-detection/", views.threat_detection, name="threat_detection"),
    path("threat-intelligence/", views.threat_intelligence, name="threat_intelligence"),
    path("ioc-correlation/", views.ioc_correlation, name="ioc_correlation"),
    path("mitre-mapping/", views.mitre_mapping, name="mitre_mapping"),
    path("fim/", views.real_time_monitoring, name="real_time_monitoring"),
    path("usb-monitor/", views.usb_monitoring, name="usb_monitoring"),
    path("incidents/", views.incidents, name="incidents"),
    path("quarantine/", views.quarantine_view, name="quarantine"),
    path("risk-assessment/", views.risk_assessment, name="risk_assessment"),
    path("timeline/", views.threat_timeline, name="threat_timeline"),

    path("report/pdf/", views.download_scan_pdf, name="download_scan_pdf"),
    path("report/json/", views.export_json_report, name="export_json_report"),
    path("api/dashboard-metrics/", views.api_dashboard_metrics, name="api_dashboard_metrics"),
]
