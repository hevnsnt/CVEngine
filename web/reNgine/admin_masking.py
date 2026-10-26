"""Keep stored secrets out of the Django admin.

The encrypting fields hand the admin their plaintext, so a model registered with ``admin.site.register(...)`` would show an API key,
a webhook URL or a token in a form (and to anyone with admin access or an over-the-shoulder view). Every registered model with such a
field has those fields left out of its admin forms; secrets are set in Settings, which never shows them either."""
from django.contrib import admin

from reNgine.crypto_fields import encrypted_fields


def mask_secret_fields(site=None):
    site = site or admin.site
    secret_names = {model: names for model, names in encrypted_fields()}
    masked = 0
    for model, model_admin in site._registry.items():
        names = secret_names.get(model)
        if not names:
            continue
        model_admin.exclude = tuple(dict.fromkeys([*(model_admin.exclude or ()), *names]))
        model_admin.list_display = tuple(f for f in model_admin.list_display if f not in names) or ('__str__',)
        masked += 1
    return masked
