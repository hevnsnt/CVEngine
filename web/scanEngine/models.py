import yaml
from reNgine.crypto_fields import ENCRYPTED_COLUMN_LENGTH, EncryptedCharField, EncryptedTextField
from django.db import models


class hybrid_property:
    def __init__(self, func):
        self.func = func
        self.name = func.__name__
        self.exp = None

    def __get__(self, instance, owner):
        if instance is None:
            return self
        return self.func(instance)

    def __set__(self, instance, value):
        pass

    def expression(self, exp):
        self.exp = exp
        return self

class EngineType(models.Model):
    id = models.AutoField(primary_key=True)
    engine_name = models.CharField(max_length=200)
    yaml_configuration = models.TextField()
    default_engine = models.BooleanField(null=True, default=False)

    def __str__(self):
        return self.engine_name

    @hybrid_property
    def tasks(self):
        if not self.yaml_configuration or not yaml.safe_load(self.yaml_configuration):
            return []
        return list(yaml.safe_load(self.yaml_configuration).keys())


class Notification(models.Model):
    id = models.AutoField(primary_key=True)
    send_to_slack = models.BooleanField(default=False)
    send_to_lark = models.BooleanField(default=False)
    send_to_discord = models.BooleanField(default=False)
    send_to_telegram = models.BooleanField(default=False)

    slack_hook_url = EncryptedCharField(max_length=ENCRYPTED_COLUMN_LENGTH, null=True, blank=True)
    lark_hook_url = EncryptedCharField(max_length=ENCRYPTED_COLUMN_LENGTH, null=True, blank=True)
    discord_hook_url = EncryptedCharField(max_length=ENCRYPTED_COLUMN_LENGTH, null=True, blank=True)
    telegram_bot_token = EncryptedCharField(max_length=ENCRYPTED_COLUMN_LENGTH, null=True, blank=True)
    telegram_bot_chat_id = models.CharField(max_length=100, null=True, blank=True)

    send_scan_status_notif = models.BooleanField(default=True)
    send_interesting_notif = models.BooleanField(default=True)
    send_vuln_notif = models.BooleanField(default=True)
    send_subdomain_changes_notif = models.BooleanField(default=True)

    send_scan_output_file = models.BooleanField(default=True)
    send_scan_tracebacks = models.BooleanField(default=True)


class Proxy(models.Model):
    id = models.AutoField(primary_key=True)
    use_proxy = models.BooleanField(default=False)
    proxies = EncryptedTextField(blank=True, null=True)  # one proxy URL per line; a line may carry a password, so it is encrypted at rest


class VulnerabilityReportSetting(models.Model):
    id = models.AutoField(primary_key=True)
    primary_color = models.CharField(max_length=10, null=True, blank=True, default='#FFB74D')
    secondary_color = models.CharField(max_length=10, null=True, blank=True, default='#212121')
    company_name = models.CharField(max_length=100, null=True, blank=True)
    company_address = models.CharField(max_length=200, null=True, blank=True)
    company_email = models.CharField(max_length=100, null=True, blank=True)
    company_website = models.CharField(max_length=100, null=True, blank=True)
    show_rengine_banner = models.BooleanField(default=True)
    show_executive_summary = models.BooleanField(default=True)
    executive_summary_description = models.TextField(blank=True, null=True)
    show_footer = models.BooleanField(default=False)
    footer_text = models.CharField(max_length=200, null=True, blank=True)
