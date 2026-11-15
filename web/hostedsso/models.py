"""Single sign-on tables. Both stay empty on a server that does not use SSO."""
from django.contrib.auth.models import User
from django.db import models


class SsoIdentity(models.Model):
    """Links one local user to one subject of the identity provider. The link is by subject, never by email."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='sso_identity')
    issuer = models.CharField(max_length=255)
    subject = models.CharField(max_length=64, unique=True)
    email_seen = models.CharField(max_length=254, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    last_login_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f'{self.user_id} <- {self.issuer}#{self.subject}'


class SsoJti(models.Model):
    """An assertion id that was already used. A repeat inside its short lifetime is refused; rows are dropped once expired."""
    jti = models.CharField(max_length=64, unique=True)
    expires_at = models.DateTimeField(db_index=True)

    def __str__(self):
        return self.jti
