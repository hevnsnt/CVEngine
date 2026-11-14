"""Seed for tests/e2e_keep_open.py. THROWAWAY database only (it sets a known password). Run: manage.py shell < web/tests/e2e_keep_open_seed.py"""
# seed for the keep-open proof (throwaway DB only). Idempotent. Run: manage.py shell < this
from datetime import timedelta
from django.contrib.auth.models import User
from django.utils import timezone
from agentapi.auth import create_token
from agentapi.models import Agent
from cveFeed.models import AIUsage, OpenvasOrg, OpenvasProject, OpenvasSettings
from dashboard.models import AIProviderSettings, Org, Project
from targetApp.models import Domain
from tests.test_agentapi import call
from django.conf import settings; settings.ALLOWED_HOSTS.append('testserver')
now = timezone.now()
u, _ = User.objects.get_or_create(username='keeper', defaults={'is_superuser': True, 'is_staff': True})
u.is_superuser = u.is_staff = True; u.set_password('keeper-pass-123'); u.save()
org, _ = Org.objects.get_or_create(slug='one', defaults={'name': 'One'})
proj, _ = Project.objects.get_or_create(slug='keep-a', defaults={'name': 'Keep A', 'insert_date': now, 'org': org})
Domain.objects.get_or_create(name='a.example.com', project=proj, defaults={'insert_date': now})
s = OpenvasSettings.current(); s.enabled = True; s.save()
OpenvasOrg.objects.update_or_create(org=org, defaults={'enabled': True})
link, _ = OpenvasProject.objects.get_or_create(project=proj)
link.enabled = True
link.hosts = [f'h{i:02d}.example.com' for i in range(33)]
link.save()
tok = create_token(u, 'keeper')[1]
for name in ('keep-sentinel-1', 'keep-sentinel-2'):
    st, out = call(tok, 'PUT', '/api/v1/sentinel', {'name': name, 'scope': {'projects': ['keep-a']}, 'capabilities': ['nmap', 'naabu', 'nuclei_light']})
    print(name, st, out.get('status'))
    Agent.objects.filter(name=name).update(status='active')
AIProviderSettings.objects.get_or_create(provider='anthropic', defaults={'model': 'claude-test', 'api_key': 'x', 'enabled': True})
if not AIUsage.objects.exists():
    for i in range(60):
        AIUsage.objects.create(provider='anthropic', model='claude-test', actual_model='claude-test', stage=['triage', 'review', 'explain'][i % 3],
                               status='failed' if i % 7 == 0 else 'succeeded', error_category='timeout' if i % 7 == 0 else '',
                               input_tokens=100 + i, output_tokens=20 + i, duration_ms=500 + i * 10, started_at=now - timedelta(hours=i * 2))
print('seeded', AIUsage.objects.count())
