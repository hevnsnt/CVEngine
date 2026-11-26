"""Admin registrations for the targetApp app."""

from django.contrib import admin

from targetApp.models import (
    Domain,
    DomainInfo,
    DomainRegistration,
    Registrar,
    RelatedDomain,
)

for _model in (
    Domain,
    RelatedDomain,
    Registrar,
    DomainRegistration,
    DomainInfo,
):
    admin.site.register(_model)
