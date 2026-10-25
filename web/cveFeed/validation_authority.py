"""Recheck the delegated authority of explicit validation requests at execution."""
from django.utils import timezone


def require_authority(job):
    from django.contrib.auth import get_user_model
    from agentapi.services import ApiError, Ctx, get_one_project
    from dashboard.models import ApiToken, Project
    from tenancy.middleware import TenancyMiddleware

    if job.source == 'automatic':
        return
    if job.source != 'manual':
        raise ApiError(403, 'legacy validation authority is unavailable; submit a new request')
    user = get_user_model().objects.filter(pk=job.requested_by_id, is_active=True).first()
    project = Project.objects.filter(pk=job.project_id).first()
    if user is None or project is None:
        raise ApiError(403, 'validation requester or project is no longer active')
    if TenancyMiddleware.must_enrol_mfa(user):
        raise ApiError(403, 'MFA enrollment is required')
    profile = getattr(user, 'tenancy_profile', None)
    if profile and profile.must_change_password:
        raise ApiError(403, 'change the temporary password before validating findings')
    token = None
    if job.requested_token_id is not None:
        token = ApiToken.objects.filter(pk=job.requested_token_id, user=user, revoked=False).first()
        if token is None or (token.expires_at and token.expires_at <= timezone.now()):
            raise ApiError(403, 'validation token is revoked or expired')
    get_one_project(Ctx(user, token), project.slug, write=True)
