"""Admin registrations for the startScan app."""

from django.contrib import admin

from startScan.models import (
    CountryISO,
    CveId,
    CweId,
    DirectoryFile,
    DirectoryScan,
    Dork,
    Email,
    Employee,
    EndPoint,
    IpAddress,
    MetaFinderDocument,
    Port,
    ScanActivity,
    ScanHistory,
    SubScan,
    Subdomain,
    Technology,
    Vulnerability,
    VulnerabilityReference,
    VulnerabilityTags,
    Waf,
)

for _model in (
    ScanHistory,
    SubScan,
    Subdomain,
    ScanActivity,
    EndPoint,
    Vulnerability,
    CweId,
    CveId,
    VulnerabilityReference,
    VulnerabilityTags,
    Port,
    IpAddress,
    DirectoryFile,
    DirectoryScan,
    Technology,
    MetaFinderDocument,
    Email,
    Employee,
    Dork,
    Waf,
    CountryISO,
):
    admin.site.register(_model)
