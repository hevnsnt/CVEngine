from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.db.models.functions import Lower

from hostedsso.models import SsoIdentity
from tenancy import audit


class Command(BaseCommand):
    help = ("Link an existing local user to a cvengine.live subject (the site's user id), by email. Idempotent. Refuses an inactive user, and a user "
            "or subject that is already linked to something else, unless --force. Used by the hosted provisioner; changes nothing else.")

    def add_arguments(self, parser):
        parser.add_argument('--email', required=True)
        parser.add_argument('--subject', required=True)
        parser.add_argument('--issuer', default=None, help='default: CVENGINE_SSO_ISSUER')
        parser.add_argument('--force', action='store_true', help='replace an existing link of this user or of this subject')

    @transaction.atomic
    def handle(self, *args, **options):
        from django.conf import settings
        from hostedsso.verify import SUBJECT
        email, subject = options['email'].strip(), options['subject'].strip()
        issuer = (options['issuer'] or settings.CVENGINE_SSO_ISSUER).strip()
        if not SUBJECT.match(subject):
            raise CommandError('the subject is not a valid identifier')
        users = list(User.objects.annotate(lower_email=Lower('email')).filter(lower_email=email.lower()))
        if len(users) != 1:
            raise CommandError('no user has that email' if not users else 'more than one user has that email; link by a unique email')
        user = users[0]
        if not user.is_active:
            raise CommandError('that user is inactive; refusing to link it')
        existing = SsoIdentity.objects.filter(user=user).first()
        owner = SsoIdentity.objects.filter(subject=subject).exclude(user=user).select_related('user').first()
        if existing and existing.subject == subject and existing.issuer == issuer:
            self.stdout.write('already linked')
            return
        if (existing or owner) and not options['force']:
            raise CommandError('the user is already linked to a different subject' if existing else
                               'that subject is already linked to a different user; pass --force to move it')
        if owner:
            owner.delete()
        if existing:
            existing.issuer, existing.subject = issuer, subject
            existing.save(update_fields=['issuer', 'subject'])
        else:
            SsoIdentity.objects.create(user=user, issuer=issuer, subject=subject, email_seen=email)
        audit.record_for_user(user, 'sso.link', user, subject=subject, issuer=issuer, forced=bool(options['force']))
        self.stdout.write('linked')
