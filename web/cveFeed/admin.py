from django.contrib import admin

from cveFeed.models import CVEEntry, CVEMatch, Triage


@admin.register(CVEEntry)
class CVEEntryAdmin(admin.ModelAdmin):
    list_display = (
        "cve_id",
        "cvss",
        "kev",
        "epss_reached",
        "exploit_db",
        "published_at",
        "title",
    )
    list_filter = ("kev", "epss_reached", "exploit_db", "severity_source")
    search_fields = ("cve_id", "title", "summary")
    ordering = ("-published_at",)
    readonly_fields = ("created_at", "synced_at")


@admin.register(CVEMatch)
class CVEMatchAdmin(admin.ModelAdmin):
    list_display = (
        "cve_entry",
        "subdomain",
        "matched_product",
        "matched_version",
        "version_in_range",
        "confidence",
        "ai_verdict",
    )
    list_filter = ("source", "version_in_range", "ai_verdict")
    search_fields = ("cve_entry__cve_id", "matched_product", "subdomain__name")
    ordering = ("-confidence",)
    readonly_fields = ("created_at", "updated_at")


@admin.register(Triage)
class TriageAdmin(admin.ModelAdmin):
    list_display = ("kind", "host", "classification", "status", "validation_status", "last_seen")
    list_filter = ("kind", "status", "classification", "validation_status")
    search_fields = ("host",)
    readonly_fields = ("created_at", "updated_at")
