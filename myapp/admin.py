from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import (
    AssetInventory,
    AuditLog,
    ComplianceCheck,
    ContactMessage,
    CustomUser,
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


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (
        ("Aegis profile", {"fields": ("phone", "profile_image", "is_analyst")}),
    )


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ("scan_type", "user", "score", "risk_level", "created_at")
    list_filter = ("scan_type", "risk_level", "created_at")
    search_fields = ("user__username", "user__email")


@admin.register(UserActivity)
class UserActivityAdmin(admin.ModelAdmin):
    list_display = ("user", "option_used", "created_at")
    list_filter = ("option_used", "created_at")
    search_fields = ("user__username", "user__email", "detail")


@admin.register(ContactMessage)
class ContactMessageAdmin(admin.ModelAdmin):
    list_display = ("name", "email", "message_type", "is_resolved", "created_at")
    list_filter = ("message_type", "is_resolved", "created_at")
    search_fields = ("name", "email", "message")


admin.site.register(AssetInventory)
admin.site.register(AuditLog)
admin.site.register(ComplianceCheck)
admin.site.register(EndpointFingerprint)
admin.site.register(FileMonitorEvent)
admin.site.register(Incident)
admin.site.register(IOC)
admin.site.register(MitreMapping)
admin.site.register(MitreTechnique)
admin.site.register(QuarantineItem)
admin.site.register(RiskAssessment)
admin.site.register(ThreatFinding)
admin.site.register(ThreatIntel)
admin.site.register(ThreatTimeline)
