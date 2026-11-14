"""Run an external scanner under the resource gate (``reNgine.resources.heavy_job``), as nmap, naabu and nuclei already do.

``subprocess.run(timeout=)`` kills only the direct child, knows nothing of a global pause, a stopped scan or memory pressure, and
leaves the child's own children behind. ``run`` starts the tool in its own session, hands it
to the gate so a pause, a stop or a low-memory kill reaches the whole process group, and on a timeout stops the group, not just the
leader. It raises what the gate raises (``ScanAborted``, ``MemoryBusy``, ``MemoryKill``) and ``subprocess.TimeoutExpired``.
"""
import subprocess


def run(kind, argv, timeout, label='', env=None, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, on_start=None):
    """``subprocess.CompletedProcess`` of ``argv`` (no stdin) run as the heavy job ``kind``. ``stdout`` and ``stderr`` are ``DEVNULL`` or
    ``PIPE`` (the text then comes back on the result). ``on_start()`` is called once the job is let start (after its memory wait), right
    before the process: the egress ledger counts a run there, so a run refused at the wait is not counted as sent."""
    from reNgine import resources
    with resources.heavy_job(kind, label=label) as job:
        if on_start is not None:
            on_start()
        proc = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, text=True, start_new_session=True)
        job.attach(proc)
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            resources.terminate_group(proc, grace=5)
            proc.communicate()
            raise
        job.raise_if_killed()
        return subprocess.CompletedProcess(argv, proc.returncode, out, err)
