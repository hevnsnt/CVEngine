from rest_framework.permissions import BasePermission
from rest_framework.exceptions import PermissionDenied
from rolepermissions.checkers import has_permission

class HasPermission(BasePermission):
	"""
		This is a custom permission class for DRF that checks if the user 
		has the required permission.
		Usage in drf views:
		permission_classes = [HasPermission]
		permission_required = PERM_MODIFY_SCAN_CONFIGURATIONS
	"""

	def has_permission(self, request, view):
		permission_code = getattr(view, 'permission_required', None)
		if not permission_code:
			raise PermissionDenied(detail="Permission is not specified for this view.")

		if not has_permission(request.user, permission_code):
			raise PermissionDenied(detail="This user does not have enough permissions")
		return True

MAX_LEGACY_BATCH = 100
LEGACY_SUBSCAN_TYPES = frozenset({
    'port_scan', 'http_crawl', 'fetch_url', 'screenshot',
    'dir_file_fuzz', 'vulnerability_scan',
})


def require_project_write(user, project):
    from tenancy import roles
    if not user.is_authenticated or not user.is_active:
        raise PermissionDenied('Authentication required')
    if project is None:
        if not user.is_superuser:
            raise PermissionDenied('System records require a superuser')
    elif roles.effective_role(user, project) not in (roles.ADMIN, roles.USER, roles.PENTESTER):
        raise PermissionDenied('Project write access required')
    return project


def object_project(obj):
    from dashboard.models import Project
    if isinstance(obj, Project):
        return obj
    if hasattr(obj, 'project_id'):
        return obj.project
    if hasattr(obj, 'target_domain_id'):
        if obj.target_domain_id is None:
            raise PermissionDenied('No project binding for this resource')
        return obj.target_domain.project
    if hasattr(obj, 'domain_id'):
        if obj.domain_id is None:
            raise PermissionDenied('No project binding for this resource')
        return obj.domain.project
    if hasattr(obj, 'scan_history_id'):
        if obj.scan_history_id is None or obj.scan_history.domain_id is None:
            raise PermissionDenied('No project binding for this resource')
        return obj.scan_history.domain.project
    raise PermissionDenied('No project binding for this resource')


def writable_batch(user, model, ids):
    from rest_framework.exceptions import ValidationError, NotFound
    if not isinstance(ids, list) or not ids or len(ids) > MAX_LEGACY_BATCH:
        raise ValidationError('Provide between 1 and 100 IDs')
    parsed = set()
    for pk in ids:
        value = str(pk)
        if (type(pk) not in (int, str) or not value.isascii() or not value.isdigit()
                or len(value) > 19):
            raise ValidationError('Invalid ID')
        numeric = int(value)
        if not 0 < numeric <= 9223372036854775807:
            raise ValidationError('Invalid ID')
        parsed.add(numeric)
    ids = parsed
    objects = list(model.objects.filter(pk__in=ids))
    if len(objects) != len(ids):
        raise NotFound('Resource not found')
    for obj in objects:
        require_project_write(user, object_project(obj))
    return objects


def validate_subscan_types(scan_types):
    from rest_framework.exceptions import ValidationError
    if (not isinstance(scan_types, list) or not scan_types
            or len(scan_types) > len(LEGACY_SUBSCAN_TYPES)
            or any(not isinstance(s, str) or s not in LEGACY_SUBSCAN_TYPES for s in scan_types)):
        raise ValidationError('Unsupported subscan type')
    return list(dict.fromkeys(scan_types))
