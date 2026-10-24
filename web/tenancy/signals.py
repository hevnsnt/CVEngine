from django.contrib.auth.models import User
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from tenancy import roles, scope


@receiver(post_save, sender='dashboard.Project')
def place_new_project(sender, instance, created, **kwargs):
    """A new project joins the creator's admin org (else the default org); the creator becomes its admin."""
    if not created:
        return
    from dashboard.models import Org, OrgMembership, ProjectMembership
    user = scope.current_user()
    org = None
    if instance.org_id is None:
        if user and not user.is_superuser:
            org = Org.objects.filter(
                memberships__user=user, memberships__role=roles.ADMIN).first()
        org = org or Org.objects.order_by('id').first()
        if org:
            type(instance)._base_manager.filter(pk=instance.pk).update(org=org)  # unscoped: the new project is not in the caller's set yet
    if user and not user.is_superuser:
        ProjectMembership.objects.get_or_create(
            user=user, project=instance, defaults={'role': roles.ADMIN})
        scope.allow(instance.pk)  # visible for the rest of this request


@receiver([post_save, post_delete], sender='dashboard.OrgMembership')
@receiver([post_save, post_delete], sender='dashboard.ProjectMembership')
def keep_global_role_in_sync(sender, instance, **kwargs):
    if User.objects.filter(pk=instance.user_id).exists():
        roles.sync_global_role(instance.user)
