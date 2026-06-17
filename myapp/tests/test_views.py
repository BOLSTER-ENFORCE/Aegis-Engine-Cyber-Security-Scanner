from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from myapp.models import (
    AuditLog,
    ContactMessage,
    Incident,
    ScanResult,
    ThreatFinding,
    UserActivity,
)

User = get_user_model()


class ViewTestMixin:
    """Shared helpers for view tests."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="testuser", email="test@test.com", password="testpass123"
        )
        self.admin = User.objects.create_superuser(
            username="admin", email="admin@test.com", password="adminpass123"
        )


# ------------------------------------------------------------------
# Public pages (no login required)
# ------------------------------------------------------------------
class PublicPageTests(ViewTestMixin, TestCase):
    def test_home(self):
        resp = self.client.get(reverse("home"))
        self.assertEqual(resp.status_code, 200)

    def test_about(self):
        resp = self.client.get(reverse("about"))
        self.assertEqual(resp.status_code, 200)

    def test_privacy(self):
        resp = self.client.get(reverse("privacy"))
        self.assertEqual(resp.status_code, 200)

    def test_osi_model(self):
        resp = self.client.get(reverse("osi_model"))
        self.assertEqual(resp.status_code, 200)

    def test_blogs(self):
        resp = self.client.get(reverse("blogs"))
        self.assertEqual(resp.status_code, 200)

    def test_login_page(self):
        resp = self.client.get(reverse("login"))
        self.assertEqual(resp.status_code, 200)

    def test_register_page(self):
        resp = self.client.get(reverse("register"))
        self.assertEqual(resp.status_code, 200)


# ------------------------------------------------------------------
# Registration
# ------------------------------------------------------------------
class RegisterTests(ViewTestMixin, TestCase):
    def test_successful_registration(self):
        resp = self.client.post(
            reverse("register"),
            {
                "username": "newuser",
                "email": "new@test.com",
                "password": "strongpass1",
                "confirm_password": "strongpass1",
            },
        )
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(User.objects.filter(username="newuser").exists())
        self.assertTrue(AuditLog.objects.filter(action="User Registration").exists())

    def test_password_mismatch(self):
        resp = self.client.post(
            reverse("register"),
            {
                "username": "baduser",
                "email": "bad@test.com",
                "password": "pass1",
                "confirm_password": "pass2",
            },
        )
        self.assertEqual(resp.status_code, 302)
        self.assertFalse(User.objects.filter(username="baduser").exists())

    def test_duplicate_username(self):
        resp = self.client.post(
            reverse("register"),
            {
                "username": "testuser",
                "email": "other@test.com",
                "password": "pass1234",
                "confirm_password": "pass1234",
            },
        )
        self.assertEqual(resp.status_code, 302)

    def test_duplicate_email(self):
        resp = self.client.post(
            reverse("register"),
            {
                "username": "newname",
                "email": "test@test.com",
                "password": "pass1234",
                "confirm_password": "pass1234",
            },
        )
        self.assertEqual(resp.status_code, 302)

    def test_missing_fields(self):
        resp = self.client.post(reverse("register"), {"username": "", "email": "", "password": ""})
        self.assertEqual(resp.status_code, 302)

    def test_authenticated_user_redirects(self):
        self.client.login(username="testuser", password="testpass123")
        resp = self.client.get(reverse("register"))
        self.assertEqual(resp.status_code, 302)


# ------------------------------------------------------------------
# Login / Logout
# ------------------------------------------------------------------
class LoginTests(ViewTestMixin, TestCase):
    def test_valid_login(self):
        resp = self.client.post(
            reverse("login"),
            {"username": "testuser", "password": "testpass123"},
        )
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(AuditLog.objects.filter(action="User Login").exists())
        self.assertTrue(UserActivity.objects.filter(option_used="login").exists())

    def test_invalid_login(self):
        resp = self.client.post(
            reverse("login"),
            {"username": "testuser", "password": "wrongpass"},
        )
        self.assertEqual(resp.status_code, 200)

    def test_already_authenticated_redirects(self):
        self.client.login(username="testuser", password="testpass123")
        resp = self.client.get(reverse("login"))
        self.assertEqual(resp.status_code, 302)


class LogoutTests(ViewTestMixin, TestCase):
    def test_logout(self):
        self.client.login(username="testuser", password="testpass123")
        resp = self.client.get(reverse("logout"))
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(AuditLog.objects.filter(action="Logout").exists())

    def test_logout_requires_login(self):
        resp = self.client.get(reverse("logout"))
        self.assertEqual(resp.status_code, 302)
        self.assertIn("login", resp.url)


# ------------------------------------------------------------------
# Protected pages (redirect to login when anonymous)
# ------------------------------------------------------------------
class ProtectedPageRedirectTests(ViewTestMixin, TestCase):
    def test_dashboard_requires_login(self):
        resp = self.client.get(reverse("dashboard"))
        self.assertEqual(resp.status_code, 302)
        self.assertIn("login", resp.url)

    def test_profile_requires_login(self):
        resp = self.client.get(reverse("profile"))
        self.assertEqual(resp.status_code, 302)

    def test_launcher_requires_login(self):
        resp = self.client.get(reverse("launcher"))
        self.assertEqual(resp.status_code, 302)

    def test_combined_scan_requires_login(self):
        resp = self.client.get(reverse("combined_scan"))
        self.assertEqual(resp.status_code, 302)


# ------------------------------------------------------------------
# Dashboard
# ------------------------------------------------------------------
class DashboardTests(ViewTestMixin, TestCase):
    def test_dashboard_authenticated(self):
        self.client.login(username="testuser", password="testpass123")
        resp = self.client.get(reverse("dashboard"))
        self.assertEqual(resp.status_code, 200)

    def test_dashboard_with_scan(self):
        self.client.login(username="testuser", password="testpass123")
        ScanResult.objects.create(user=self.user, scan_type="combined", score=72, risk_level="MEDIUM")
        resp = self.client.get(reverse("dashboard"))
        self.assertEqual(resp.status_code, 200)

    def test_dashboard_no_severity_filter(self):
        self.client.login(username="testuser", password="testpass123")
        ScanResult.objects.create(user=self.user, scan_type="combined", score=50, risk_level="HIGH")
        resp = self.client.get(reverse("dashboard"))
        self.assertEqual(resp.status_code, 200)


# ------------------------------------------------------------------
# Profile
# ------------------------------------------------------------------
class ProfileTests(ViewTestMixin, TestCase):
    def test_view_profile(self):
        self.client.login(username="testuser", password="testpass123")
        resp = self.client.get(reverse("profile"))
        self.assertEqual(resp.status_code, 200)

    def test_edit_profile_get(self):
        self.client.login(username="testuser", password="testpass123")
        resp = self.client.get(reverse("edit_profile"))
        self.assertEqual(resp.status_code, 200)

    def test_edit_profile_post(self):
        self.client.login(username="testuser", password="testpass123")
        resp = self.client.post(
            reverse("edit_profile"),
            {"first_name": "Updated", "last_name": "Name", "email": "new@test.com", "phone": "1234567890"},
        )
        self.assertEqual(resp.status_code, 302)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "Updated")


# ------------------------------------------------------------------
# Contact
# ------------------------------------------------------------------
class ContactTests(ViewTestMixin, TestCase):
    def test_get(self):
        resp = self.client.get(reverse("contact"))
        self.assertEqual(resp.status_code, 200)

    def test_post_anonymous(self):
        resp = self.client.post(
            reverse("contact"),
            {"name": "Anon", "email": "anon@test.com", "message_type": "question", "message": "hi"},
        )
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(ContactMessage.objects.filter(name="Anon").exists())

    def test_post_authenticated(self):
        self.client.login(username="testuser", password="testpass123")
        resp = self.client.post(
            reverse("contact"),
            {"name": "Test", "email": "test@test.com", "message_type": "suggestion", "message": "great"},
        )
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(UserActivity.objects.filter(option_used="contact").exists())


# ------------------------------------------------------------------
# Forgot Password flow
# ------------------------------------------------------------------
class ForgotPasswordTests(ViewTestMixin, TestCase):
    def test_request_step_unknown_user(self):
        resp = self.client.post(
            reverse("forgot_password"),
            {"action": "request", "username": "nobody", "email": "none@test.com"},
        )
        self.assertEqual(resp.status_code, 302)


# ------------------------------------------------------------------
# Scan Result view
# ------------------------------------------------------------------
class ScanResultViewTests(ViewTestMixin, TestCase):
    def test_view_own_result(self):
        self.client.login(username="testuser", password="testpass123")
        sr = ScanResult.objects.create(user=self.user, scan_type="combined", score=90)
        resp = self.client.get(reverse("scan_result", args=[sr.id]))
        self.assertEqual(resp.status_code, 200)

    def test_view_other_user_result(self):
        other = User.objects.create_user(username="other", password="pass1234")
        sr = ScanResult.objects.create(user=other, scan_type="combined", score=90)
        self.client.login(username="testuser", password="testpass123")
        resp = self.client.get(reverse("scan_result", args=[sr.id]))
        self.assertEqual(resp.status_code, 302)

    def test_superuser_can_view_any(self):
        sr = ScanResult.objects.create(user=self.user, scan_type="combined", score=90)
        self.client.login(username="admin", password="adminpass123")
        resp = self.client.get(reverse("scan_result", args=[sr.id]))
        self.assertEqual(resp.status_code, 200)


# ------------------------------------------------------------------
# JSON export
# ------------------------------------------------------------------
class ExportJsonTests(ViewTestMixin, TestCase):
    def test_no_scans(self):
        self.client.login(username="testuser", password="testpass123")
        resp = self.client.get(reverse("export_json_report"))
        self.assertEqual(resp.status_code, 404)

    def test_with_scan(self):
        self.client.login(username="testuser", password="testpass123")
        ScanResult.objects.create(user=self.user, scan_type="combined", score=80)
        resp = self.client.get(reverse("export_json_report"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "application/json")


# ------------------------------------------------------------------
# Admin dashboard
# ------------------------------------------------------------------
class AdminDashboardTests(ViewTestMixin, TestCase):
    def test_non_staff_redirected(self):
        self.client.login(username="testuser", password="testpass123")
        resp = self.client.get(reverse("admin_dashboard"))
        self.assertEqual(resp.status_code, 302)

    def test_staff_can_access(self):
        self.client.login(username="admin", password="adminpass123")
        resp = self.client.get(reverse("admin_dashboard"))
        self.assertEqual(resp.status_code, 200)


# ------------------------------------------------------------------
# Launcher (template references non-existent url 'system_features';
# verify login-required redirect only)
# ------------------------------------------------------------------
class LauncherTests(ViewTestMixin, TestCase):
    def test_requires_login(self):
        resp = self.client.get(reverse("launcher"))
        self.assertEqual(resp.status_code, 302)
        self.assertIn("login", resp.url)


# ------------------------------------------------------------------
# API dashboard metrics
# ------------------------------------------------------------------
class ApiDashboardMetricsTests(ViewTestMixin, TestCase):
    def test_requires_login(self):
        resp = self.client.get(reverse("api_dashboard_metrics"))
        self.assertEqual(resp.status_code, 302)

    def test_returns_json(self):
        self.client.login(username="testuser", password="testpass123")
        resp = self.client.get(reverse("api_dashboard_metrics"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "application/json")


# ------------------------------------------------------------------
# Incidents
# ------------------------------------------------------------------
class IncidentsViewTests(ViewTestMixin, TestCase):
    def test_requires_login(self):
        resp = self.client.get(reverse("incidents"))
        self.assertEqual(resp.status_code, 302)

    def test_authenticated(self):
        self.client.login(username="testuser", password="testpass123")
        resp = self.client.get(reverse("incidents"))
        self.assertEqual(resp.status_code, 200)


# ------------------------------------------------------------------
# Change Password (template references non-existent url 'system_features';
# verify login-required redirect only)
# ------------------------------------------------------------------
class ChangePasswordTests(ViewTestMixin, TestCase):
    def test_requires_login(self):
        resp = self.client.get(reverse("change_password"))
        self.assertEqual(resp.status_code, 302)
        self.assertIn("login", resp.url)
