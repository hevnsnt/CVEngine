from django.core.management.base import BaseCommand

from cveFeed import web_shot


class Command(BaseCommand):
    help = ("Start the screenshot browser once, as the screenshot worker does, and record whether Chromium's sandbox engaged. The celery container "
            'runs it before its workers start; while it fails, screenshots stay off and the host page and get_system_status say why '
            '(see cveFeed.web_shot.check_sandbox). Exit status 1 when the sandbox is required and did not engage.')

    def handle(self, *args, **options):
        if not web_shot.enabled() or not web_shot.browser_installed():
            self.stdout.write(f'Screenshot sandbox: not checked. {web_shot.unavailable_reason()}')
            return
        if not web_shot.sandbox_wanted():
            self.stdout.write("Screenshot sandbox: OFF (CVENGINE_SCREENSHOT_SANDBOX=0). The screenshot browser runs without Chromium's sandbox: unsafe.")
            return
        state = web_shot.check_sandbox()
        if state is None:
            self.stdout.write('Screenshot sandbox: the check did not finish; every capture still checks it before it loads a page.')
        elif state['engaged']:
            self.stdout.write(f"Screenshot sandbox: engaged (Chromium {state.get('version') or '?'}: its renderer runs in its own user and PID namespace "
                              'under its own seccomp filter).')
        else:
            self.stderr.write(f"Screenshot sandbox: FAILED, web screenshots are off. {state['reason']}")
            raise SystemExit(1)
