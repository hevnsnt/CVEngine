from rest_framework.filters import BaseFilterBackend

from tenancy.scope import scope_queryset


class ProjectScopeFilterBackend(BaseFilterBackend):
    """Scope every DRF viewset queryset to the caller's projects (covers import-time querysets)."""

    def filter_queryset(self, request, queryset, view):
        return scope_queryset(queryset)
