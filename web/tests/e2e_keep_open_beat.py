"""Server-side data mover for tests/e2e_keep_open.py. Not a test. Run on a THROWAWAY stack (seeded as the e2e docstring says):

  manage.py shell < web/tests/e2e_keep_open_beat.py       # KEEP_BEAT_DIR=<dir> names the control directory

Every 1.5 s it moves every Sentinel's last check-in (so the live list changes and the Sentinels page repaints at each poll, as it does on a busy
install) and, when the file <dir>/bump appears, adds one AI attempt and one OpenVAS host (so the page can prove new data still arrives); it exits when
<dir>/stop appears."""
import os
import time

from django.core.cache import cache
from django.utils import timezone

from agentapi.models import Agent
from cveFeed.models import AIUsage, OpenvasProject

d = os.environ['KEEP_BEAT_DIR']
os.makedirs(d, exist_ok=True)
while not os.path.exists(os.path.join(d, 'stop')):
    Agent.objects.filter(name__startswith='keep-sentinel').update(last_seen=timezone.now())
    bump = os.path.join(d, 'bump')
    if os.path.exists(bump):
        os.remove(bump)
        AIUsage.objects.create(provider='anthropic', model='claude-test', actual_model='claude-test', stage='triage', status='succeeded',
                               input_tokens=10, output_tokens=5, duration_ms=300)
        link = OpenvasProject.objects.get(project__slug='keep-a')
        link.hosts = link.hosts + [f'h{len(link.hosts):02d}.example.com']
        link.save()
        cache.delete(f'openvas-explain:{link.project_id}')
        print('bumped', len(link.hosts), flush=True)
    time.sleep(1.5)
print('beat stopped', flush=True)
