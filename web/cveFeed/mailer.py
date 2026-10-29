"""Outgoing mail: the SMTP server an App Admin sets under Settings, Email, and the messages cvENGINE sends through it.

Today that is the onboarding email (a new person's username and a link to choose their password) and a test message. Sending is
best effort and never raises: every sender returns ``(ok, error)``, where ``error`` is a short sentence safe to show an
administrator. It never contains the server password, and the stored password never leaves the server.
"""
import logging
import re
import smtplib
import socket
import ssl
from email.utils import formataddr, make_msgid
from urllib.parse import urlsplit

from django.conf import settings
from django.core.mail import EmailMultiAlternatives, get_connection
from django.core.mail.backends.smtp import EmailBackend
from django.template.loader import render_to_string
from django.urls import reverse

logger = logging.getLogger(__name__)

TIMEOUT = 15
EMAIL_RE = re.compile(r'^[^@\s<>",;:()\[\]\\]+@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\.[A-Za-z0-9-]{2,63}$')
HOST_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$|^[0-9A-Fa-f:]{2,45}$')
LINK_BASE_RE = re.compile(r'^https?://[A-Za-z0-9.-]+(?::\d{1,5})?$|^https?://\[[0-9A-Fa-f:]+\](?::\d{1,5})?$')


class _Backend(EmailBackend):
    """Django's SMTP backend, with certificate checking switched off only when the settings say so (a relay with its own CA)."""

    verify = True

    @property
    def ssl_context(self):
        if self.verify:
            return ssl.create_default_context()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context


def row():
    from cveFeed.models import SmtpSettings
    return SmtpSettings.current()


def ready(cfg=None):
    """True when an App Admin has switched outgoing mail on and filled in the server and the sender address."""
    cfg = cfg or row()
    return bool(cfg.enabled and cfg.host and cfg.from_address)


def base_url(cfg=None):
    """The address links in a message start with: the one set under Settings, Email, else ``https://`` and ``DOMAIN_NAME``. Never
    taken from a request, so a forged Host header cannot point a link at another site."""
    cfg = cfg or row()
    return (cfg.link_base or f'https://{settings.DOMAIN_NAME}').rstrip('/')


def _sender(cfg):
    return formataddr((cfg.from_name, cfg.from_address)) if cfg.from_name else cfg.from_address


def _connection(cfg):
    backend = get_connection(f'{__name__}._Backend', host=cfg.host, port=cfg.port, username=cfg.username, password=cfg.password,
                             use_tls=cfg.security == 'starttls', use_ssl=cfg.security == 'ssl', timeout=TIMEOUT)
    backend.verify = bool(cfg.verify_certificate)
    return backend


def explain(exc):
    """A sentence for the administrator about why a send failed, from the kind of failure only (a server's own reply can carry
    addresses or banners, and an error string must never carry the password)."""
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return 'the mail server refused the user name or password'
    if isinstance(exc, ssl.SSLCertVerificationError):
        return ('the mail server\'s certificate is not trusted; fix the certificate, or turn off "Verify the server certificate" '
                'for a relay you trust')
    if isinstance(exc, ssl.SSLError):
        return 'the secure connection to the mail server failed; check the port and the Security choice (port 465 is SSL/TLS, 587 is STARTTLS)'
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return 'the mail server refused the recipient address'
    if isinstance(exc, smtplib.SMTPSenderRefused):
        return 'the mail server refused the sender address; use an address it allows'
    if isinstance(exc, (smtplib.SMTPNotSupportedError, smtplib.SMTPHeloError)):
        return 'the mail server does not support what was asked (try another Security choice)'
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return 'the mail server did not answer in time'
    if isinstance(exc, socket.gaierror):
        return 'the mail server name does not resolve'
    if isinstance(exc, (ConnectionError, smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected)):
        return 'could not connect to the mail server; check the address, the port and any firewall'
    if isinstance(exc, smtplib.SMTPException):
        return 'the mail server rejected the message'
    if isinstance(exc, OSError):
        return 'could not reach the mail server'
    return 'the message could not be sent'


def send(message, cfg=None):
    """Send one prepared message through the configured server. Returns ``(ok, error)``; ``error`` is '' on success."""
    cfg = cfg or row()
    if not ready(cfg):
        return False, 'outgoing mail is not set up (Settings, Email)'
    try:
        message.connection = _connection(cfg)
        message.send(fail_silently=False)
        return True, ''
    except Exception as exc:  # noqa: BLE001 - mail is best effort; the caller shows ``error`` and falls back
        logger.warning('mail send failed (%s)', type(exc).__name__)
        return False, explain(exc)


def _message(cfg, to, subject, text, html):
    message = EmailMultiAlternatives(subject=subject, body=text, from_email=_sender(cfg), to=[to])
    message.attach_alternative(html, 'text/html')
    # Django's own Message-ID would carry this container's host name; use the sender's domain instead
    message.extra_headers['Message-ID'] = make_msgid(domain=cfg.from_address.rsplit('@', 1)[-1])
    message.extra_headers['X-Auto-Response-Suppress'] = 'All'
    return message


def _instance(cfg):
    return urlsplit(base_url(cfg)).netloc


def _access_lines(user):
    from dashboard.models import OrgMembership, ProjectMembership
    from tenancy import roles
    if user.is_superuser:
        return ['App Admin: everything on this server']
    lines = [f'{roles.ROLE_LABELS.get(("org", m.role), m.role)} in {m.org.name}'
             for m in OrgMembership.objects.filter(user=user).select_related('org').order_by('org__name')]
    lines += [f'{roles.ROLE_LABELS.get(("project", m.role), m.role)} in {m.project.name}'
              for m in ProjectMembership.objects.filter(user=user).select_related('project').order_by('project__name')]
    return lines[:10]


def onboarding_message(user, actor, cfg=None):
    """The welcome message for a person just added: their user name and a single-use link to choose a password."""
    from tenancy import invite
    cfg = cfg or row()
    days = invite.valid_days()
    link = f'{base_url(cfg)}{reverse("invite", args=[invite.make_token(user)])}'
    context = {'name': user.first_name or user.username, 'username': user.username, 'link': link, 'days': days,
               'by': actor.get_full_name() or actor.username, 'instance': _instance(cfg), 'access': _access_lines(user),
               'sign_in': f'{base_url(cfg)}{reverse("login")}'}
    subject = f'You have been added to cvENGINE on {context["instance"]}'
    return _message(cfg, user.email, subject, render_to_string('cveFeed/email/onboarding.txt', context),
                    render_to_string('cveFeed/email/onboarding.html', context))


def send_onboarding(user, actor, cfg=None):
    cfg = cfg or row()
    if not EMAIL_RE.match(user.email or ''):
        return False, 'this account has no valid email address'
    if not ready(cfg):
        return False, 'outgoing mail is not set up (Settings, Email)'
    return send(onboarding_message(user, actor, cfg), cfg)


def send_test(to, actor, cfg=None):
    cfg = cfg or row()
    if not EMAIL_RE.match(to or ''):
        return False, 'that does not look like an email address'
    context = {'by': actor.get_full_name() or actor.username, 'instance': _instance(cfg), 'host': cfg.host, 'port': cfg.port}
    return send(_message(cfg, to, f'cvENGINE test message from {context["instance"]}',
                         render_to_string('cveFeed/email/test.txt', context), render_to_string('cveFeed/email/test.html', context)), cfg)
