"""Admin registrations for the scanEngine app."""

from django.contrib import admin

from scanEngine.models import EngineType, Notification, VulnerabilityReportSetting

for _model in (
    EngineType,
    Notification,
    VulnerabilityReportSetting,
):
    admin.site.register(_model)
