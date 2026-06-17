import json
import secrets

from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.sessions.models import Session
from django.db.models import Count
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import psutil

from .models import (
    AuditLog,
    ContactMessage,
    Incident,
    RiskAssessment,
    ScanResult,
    ThreatFinding,
    UserActivity,
)
from .scan_engine import active_network_connections, osi_model, run_combined_scan


User = get_user_model()

BLOGS = [
    {
        "title": "How to judge whether an open port is dangerous",
        "category": "Network security",
        "body": "An open port is not automatically malicious. Risk depends on the service, exposure, patch level, and who can reach it. Remote admin, database, and file-sharing ports should be restricted.",
    },
    {
        "title": "What to do when a scan finds suspicious files",
        "category": "Malware triage",
        "body": "Do not run unknown files. Check the source, hash the file, scan it with a trusted antivirus service, and quarantine or delete files that cannot be verified.",
    },
    {
        "title": "OSI model for practical troubleshooting",
        "category": "Learning",
        "body": "Use the OSI layers to narrow problems: ports and protocols live around transport/application layers, while local network exposure starts lower at network and data-link layers.",
    },
    {
        "title": "Endpoint hardening checklist",
        "category": "System security",
        "body": "Keep firewall, antivirus, secure boot, disk encryption, patching, and user privilege controls enabled. Review startup apps and browser downloads regularly.",
    },
]


def track_activity(request, option, detail=""):
    if request.user.is_authenticated:
        UserActivity.objects.create(
            user=request.user,
            option_used=option,
            detail=detail,
        )


def home(request):
    return render(request, "myapp/home.html")


def register(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        email = request.POST.get("email", "").strip()
        password1 = request.POST.get("password", "")
        password2 = request.POST.get("confirm_password", "")

        if not username or not email or not password1:
            messages.error(request, "Username, email, and password are required.")
            return redirect("register")

        if password1 != password2:
            messages.error(request, "Passwords do not match.")
            return redirect("register")

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return redirect("register")

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")
            return redirect("register")

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password1,
        )
        AuditLog.objects.create(
            user=user,
            action="User Registration",
            details=f"User {username} registered",
        )
        messages.success(request, "Registration successful. You can now log in.")
        return redirect("login")

    return render(request, "myapp/register.html")


def user_login(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            AuditLog.objects.create(
                user=user,
                action="User Login",
                details="Successful login",
            )
            UserActivity.objects.create(
                user=user,
                option_used="login",
                detail="User logged in",
            )
            return redirect("dashboard")
        messages.error(request, "Invalid username or password.")

    return render(request, "myapp/login.html")


@login_required
def user_logout(request):
    if request.method != "POST":
        return redirect("dashboard")
    track_activity(request, "logout", "User logged out")
    AuditLog.objects.create(
        user=request.user,
        action="Logout",
        details="User logged out",
    )
    logout(request)
    return redirect("login")


def forgot_password(request):
    context = {"step": "request"}
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "request":
            user = User.objects.filter(
                username=request.POST.get("username", "").strip(),
                email=request.POST.get("email", "").strip(),
            ).first()
            if not user:
                messages.error(request, "No matching account was found.")
                return redirect("forgot_password")
            request.session["reset_user_id"] = user.id
            otp = f"{secrets.randbelow(1000000):06d}"
            request.session["reset_otp"] = otp
            # TODO: send OTP via email; for now surface it in-session only
            context = {"step": "otp", "email_sent": True}
        elif action == "otp":
            if request.POST.get("otp") == request.session.get("reset_otp"):
                context = {"step": "reset", "verified": True}
            else:
                messages.error(request, "Invalid OTP. Please check your email.")
                context = {"step": "otp"}
        elif action == "reset":
            user = User.objects.filter(id=request.session.get("reset_user_id")).first()
            password = request.POST.get("password", "")
            confirm = request.POST.get("confirm_password", "")
            if not user or password != confirm or len(password) < 8:
                messages.error(request, "Password must match and be at least 8 characters.")
                context = {"step": "reset", "verified": True}
            else:
                user.set_password(password)
                user.save()
                request.session.pop("reset_user_id", None)
                request.session.pop("reset_otp", None)
                context = {"step": "success", "success": True}
    return render(request, "myapp/forgot_password.html", context)


@login_required
def dashboard(request):
    track_activity(request, "dashboard", "Viewed user dashboard")
    latest_scan = ScanResult.objects.filter(user=request.user).order_by("-created_at").first()
    severity_filter = request.GET.get("severity", "")
    scans = ScanResult.objects.filter(user=request.user).order_by("-created_at")[:8]
    if severity_filter:
        scans = scans.filter(risk_level=severity_filter)
    context = {
        "risk_score": latest_scan.score if latest_scan else 100,
        "risk_level": latest_scan.risk_level if latest_scan else "LOW",
        "total_findings": ThreatFinding.objects.count(),
        "critical_findings": ThreatFinding.objects.filter(severity="CRITICAL").count(),
        "high_findings": ThreatFinding.objects.filter(severity="HIGH").count(),
        "total_incidents": Incident.objects.count(),
        "open_incidents": Incident.objects.filter(status="OPEN").count(),
        "recent_findings": ThreatFinding.objects.order_by("-created_at")[:10],
        "recent_incidents": Incident.objects.order_by("-created_at")[:10],
        "latest_scan": latest_scan,
        "scans": scans,
        "severity_filter": severity_filter,
    }
    return render(request, "myapp/dashboard.html", context)


@login_required
def launcher(request):
    track_activity(request, "launcher", "Viewed scanner launcher")
    modules = [
        {"name": "Combined Scan", "url": "/scan/"},
        {"name": "System Scan", "url": "/system/"},
        {"name": "Network Scan", "url": "/network/"},
        {"name": "Threat Detection", "url": "/threat-detection/"},
        {"name": "OSI Model", "url": "/osi-model/"},
        {"name": "Blogs", "url": "/blogs/"},
    ]
    return render(request, "myapp/launcher.html", {"modules": modules})


@login_required
def profile(request):
    track_activity(request, "profile", "Viewed profile")
    return render(request, "myapp/profile.html", {"user_obj": request.user})


@login_required
def edit_profile(request):
    user = request.user
    if request.method == "POST":
        user.first_name = request.POST.get("first_name", user.first_name)
        user.last_name = request.POST.get("last_name", user.last_name)
        user.email = request.POST.get("email", user.email)
        user.phone = request.POST.get("phone", user.phone)
        if "profile_image" in request.FILES:
            img = request.FILES["profile_image"]
            allowed_types = {"image/jpeg", "image/png", "image/gif", "image/webp"}
            max_size = 5 * 1024 * 1024  # 5 MB
            if img.content_type not in allowed_types:
                messages.error(request, "Only JPEG, PNG, GIF, or WebP images are allowed.")
                return redirect("edit_profile")
            if img.size > max_size:
                messages.error(request, "Image must be smaller than 5 MB.")
                return redirect("edit_profile")
            user.profile_image = img
        user.save()
        track_activity(request, "profile", "Updated profile")
        messages.success(request, "Profile updated successfully.")
        return redirect("profile")
    return render(request, "myapp/edit_profile.html", {"user_obj": user})


@login_required
def change_password(request):
    form = PasswordChangeForm(request.user, request.POST or None)
    if request.method == "POST":
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            track_activity(request, "password", "Changed password")
            messages.success(request, "Password changed successfully.")
            return redirect("profile")
        messages.error(request, "Please correct the password form errors.")
    return render(request, "myapp/change_password.html", {"form": form})


def _save_scan(request, data):
    result = ScanResult.objects.create(
        user=request.user,
        scan_type=data["scan_type"],
        score=data["score"],
        risk_level=data["risk_level"],
        open_ports=data["open_ports"],
        detected_files=data["detected_files"]["files"],
        protocols=data["protocols"],
        modules=data["modules"],
        recommendations=data["recommendations"],
    )
    RiskAssessment.objects.create(
        score=data["score"],
        level=data["risk_level"],
        findings_count=data["detected_files"]["detected_count"],
    )
    return result


@login_required
def combined_scan(request):
    if request.method == "POST":
        data = run_combined_scan(request.user, "combined")
        result = _save_scan(request, data)
        track_activity(request, "combined scan", f"Started scan #{result.id}")
        return redirect("scan_result", result_id=result.id)

    latest_scan = ScanResult.objects.filter(user=request.user).order_by("-created_at").first()
    return render(request, "myapp/combined_scan.html", {"latest_scan": latest_scan})


@login_required
def scan_result(request, result_id):
    result = get_object_or_404(ScanResult, id=result_id)
    if not request.user.is_superuser and result.user_id != request.user.id:
        messages.error(request, "You cannot view another user's scan result.")
        return redirect("dashboard")
    track_activity(request, "scan result", f"Viewed scan #{result.id}")
    context = {
        "result": result,
        "modules": result.modules,
        "ports": result.open_ports,
        "files": result.detected_files,
        "protocols": result.protocols,
        "recommendations": result.recommendations,
        "blogs": BLOGS,
    }
    return render(request, "myapp/scan_result.html", context)


@login_required
def system_scan(request):
    if request.method == "POST":
        data = run_combined_scan(request.user, "system")
        result = _save_scan(request, data)
        track_activity(request, "system scan", f"Started scan #{result.id}")
        return redirect("scan_result", result_id=result.id)
    latest_scan = ScanResult.objects.filter(user=request.user).order_by("-created_at").first()
    return render(request, "myapp/system.html", {"latest_scan": latest_scan})


@login_required
def network_scan(request):
    if request.method == "POST":
        data = run_combined_scan(request.user, "network")
        result = _save_scan(request, data)
        track_activity(request, "network scan", f"Started scan #{result.id}")
        return redirect("scan_result", result_id=result.id)
    latest_scan = ScanResult.objects.filter(user=request.user).order_by("-created_at").first()
    return render(request, "myapp/network.html", {"latest_scan": latest_scan})


@login_required
def threat_detection(request):
    if request.method == "POST":
        data = run_combined_scan(request.user, "threat detection")
        result = _save_scan(request, data)
        track_activity(request, "threat detection", f"Started scan #{result.id}")
        return redirect("scan_result", result_id=result.id)
    latest_scan = ScanResult.objects.filter(user=request.user).order_by("-created_at").first()
    return render(request, "myapp/threat_detection.html", {"latest_scan": latest_scan})


@login_required
def threat_intelligence(request):
    return threat_detection(request)


@login_required
def ioc_correlation(request):
    return threat_detection(request)


@login_required
def mitre_mapping(request):
    return threat_detection(request)


@login_required
def real_time_monitoring(request):
    return threat_detection(request)


@login_required
def usb_monitoring(request):
    return threat_detection(request)


@login_required
def incidents(request):
    track_activity(request, "incidents", "Viewed incidents")
    return render(request, "myapp/threat_detection.html", {"incidents": Incident.objects.order_by("-created_at")})


@login_required
def quarantine_view(request):
    return threat_detection(request)


@login_required
def risk_assessment(request):
    track_activity(request, "risk assessment", "Viewed risk assessment")
    latest_scan = ScanResult.objects.filter(user=request.user).order_by("-created_at").first()
    return render(request, "myapp/dashboard.html", {"latest_scan": latest_scan})


@login_required
def threat_timeline(request):
    return threat_detection(request)


@login_required
def download_scan_pdf(request, result_id=None):
    result = get_object_or_404(ScanResult, id=result_id) if result_id else ScanResult.objects.filter(user=request.user).order_by("-created_at").first()
    if not result:
        messages.error(request, "Run a scan before downloading a PDF report.")
        return redirect("combined_scan")
    if not request.user.is_superuser and result.user_id != request.user.id:
        messages.error(request, "You cannot download another user's scan result.")
        return redirect("dashboard")

    track_activity(request, "pdf report", f"Downloaded scan #{result.id}")
    response = HttpResponse(content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="aegis_scan_{result.id}.pdf"'
    pdf = canvas.Canvas(response, pagesize=letter)
    width, height = letter
    y = height - 50

    def line(text, size=10, bold=False):
        nonlocal y
        if y < 60:
            pdf.showPage()
            y = height - 50
        pdf.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        pdf.drawString(45, y, str(text)[:110])
        y -= 16

    line("Aegis Engine Security Scan Report", 16, True)
    line(f"User: {result.user.username if result.user else 'Unknown'}")
    line(f"Date: {result.created_at}")
    line(f"Score: {result.score} / 100")
    line(f"Risk level: {result.risk_level}", 12, True)
    line("")
    line("Open Ports", 12, True)
    for port in result.open_ports[:40]:
        line(f"{port.get('protocol')} {port.get('port')} {port.get('service')} risk={port.get('risk')} - {port.get('resolution')}")
    line("")
    line("Detected Files", 12, True)
    for item in result.detected_files[:40]:
        line(f"{item.get('name')} risk={item.get('risk')} path={item.get('path')}")
    line("")
    line("Recommendations", 12, True)
    for rec in result.recommendations:
        line(f"- {rec}")
    pdf.save()
    return response


@login_required
def export_json_report(request):
    latest = ScanResult.objects.filter(user=request.user).order_by("-created_at").first()
    if not latest:
        return JsonResponse({"error": "No scan results yet."}, status=404)
    return JsonResponse({
        "id": latest.id,
        "score": latest.score,
        "risk_level": latest.risk_level,
        "open_ports": latest.open_ports,
        "detected_files": latest.detected_files,
        "protocols": latest.protocols,
        "modules": latest.modules,
        "recommendations": latest.recommendations,
        "created_at": latest.created_at,
    }, json_dumps_params={"indent": 2}, safe=False)


@staff_member_required
def admin_dashboard(request):
    active_sessions = Session.objects.filter(expire_date__gte=timezone.now())
    active_user_ids = []
    for session in active_sessions:
        data = session.get_decoded()
        user_id = data.get("_auth_user_id")
        if user_id:
            active_user_ids.append(user_id)

    active_users = User.objects.filter(id__in=active_user_ids)
    activity_summary = (
        UserActivity.objects.values("user__username", "user__email", "option_used")
        .annotate(total=Count("id"))
        .order_by("user__username", "option_used")
    )
    context = {
        "active_users": active_users,
        "activity_summary": activity_summary,
        "contacts": ContactMessage.objects.order_by("-created_at")[:50],
        "scan_count": ScanResult.objects.count(),
        "user_count": User.objects.count(),
        "latest_scans": ScanResult.objects.select_related("user").order_by("-created_at")[:20],
    }
    return render(request, "myapp/admin_dashboard.html", context)


def about(request):
    return render(request, "myapp/about.html")


def privacy_policy(request):
    return render(request, "myapp/privacy.html")


def contact(request):
    if request.method == "POST":
        ContactMessage.objects.create(
            user=request.user if request.user.is_authenticated else None,
            name=request.POST.get("name", "").strip() or "Anonymous",
            email=request.POST.get("email", "").strip(),
            message_type=request.POST.get("message_type", "suggestion"),
            message=request.POST.get("message", "").strip(),
        )
        if request.user.is_authenticated:
            track_activity(request, "contact", "Submitted contact form")
        messages.success(request, "Your message was sent to the admin dashboard.")
        return redirect("contact")
    return render(request, "myapp/contact.html")


def osi_model_view(request):
    return render(request, "myapp/osi_model.html", {"layers": osi_model()})


def blogs(request):
    return render(request, "myapp/blogs.html", {"blogs": BLOGS})


@login_required
def api_dashboard_metrics(request):
    latest_scan = ScanResult.objects.filter(user=request.user).order_by("-created_at").first()
    user_scans = list(ScanResult.objects.filter(user=request.user).order_by("-created_at")[:12])
    network_rows = active_network_connections(limit=20)
    alerts = []
    if latest_scan:
        if latest_scan.risk_level in {"HIGH", "CRITICAL"}:
            alerts.append({
                "severity": latest_scan.risk_level,
                "message": f"Latest scan risk is {latest_scan.risk_level} with score {latest_scan.score}.",
            })
        for file_item in latest_scan.detected_files[:5]:
            alerts.append({
                "severity": file_item.get("risk", "medium").upper(),
                "message": f"{file_item.get('malicious')} detected: {file_item.get('name')}",
            })
    cpu = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory().percent
    return JsonResponse({
        "cpu": cpu,
        "memory": memory,
        "risk_score": latest_scan.score if latest_scan else 100,
        "risk_level": latest_scan.risk_level if latest_scan else "LOW",
        "traffic": [
            {"label": row.get("service"), "port": row.get("port"), "risk": row.get("risk")}
            for row in network_rows[:10]
        ],
        "network_logs": network_rows[:12],
        "alerts": alerts[:8],
        "trend": [
            {"label": scan.created_at.strftime("%H:%M"), "score": scan.score, "risk": scan.risk_level}
            for scan in reversed(user_scans)
        ],
    })
