"""Bridge between the DB-stored AI settings and reNgine.ai_providers."""
from dashboard.models import AIProviderSettings
from reNgine.ai_providers import get_provider


def get_configured_provider():
	"""Return the provider the user configured, or None if AI is off/unconfigured."""
	cfg = AIProviderSettings.objects.filter(enabled=True).first()
	if not cfg:
		return None
	return get_provider(
		cfg.provider,
		model=cfg.model or None,
		api_key=cfg.api_key or None,
		base_url=cfg.base_url or None)
