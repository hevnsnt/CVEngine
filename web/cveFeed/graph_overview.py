"""Which group of the asset graph a target belongs to."""
from targetApp.target_types import apex_domain


def root_for(domain):
    """Use the bundled Public Suffix List; an explicitly host-scoped tenant stays its own group."""
    return domain.name.lower() if domain.is_host_scoped() else (apex_domain(domain.name) or 'IP assets')
