"""Whether an operating system guess made from this server's network can be believed.

nmap's OS detection reads how a host answers crafted TCP, UDP and ICMP packets. On Docker Desktop (macOS, and Windows) a container's traffic
leaves through the VM's user-space network stack, which answers for itself, so every host gets a guess that describes that stack (one install
saw Google Fuchsia on an Ubuntu server and a NAS, and an Apple OS X release on an iDRAC). The open ports and services are right; the OS guess
is not. A Linux host, or a Sentinel on the network, measures the real host.

``unreliable()`` is True when this server runs on Docker Desktop (its VM kernel is named linuxkit). ``CVENGINE_OS_DETECTION`` overrides the
check: ``trust`` believes the guesses anyway (a setup known to pass packets through unchanged), ``distrust`` never believes them.
"""
import os
import platform

REASON = ("the operating system guess was measured through Docker Desktop's network, which answers for itself and not for the host; "
          "run on a Linux host or add a Sentinel to measure the host")


def _kernel():
    try:
        with open('/proc/sys/kernel/osrelease', encoding='ascii') as handle:
            return handle.read().strip()
    except OSError:
        return platform.release()


def unreliable():
    mode = os.environ.get('CVENGINE_OS_DETECTION', 'auto').strip().lower()
    if mode == 'trust':
        return False
    if mode == 'distrust':
        return True
    return 'linuxkit' in _kernel().lower()
