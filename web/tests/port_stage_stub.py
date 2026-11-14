"""A double for the Sentinel behind the port stage, for the tests of what comes before and after it in the pipeline.

``discovery._run_stages(port_stage_run=...)`` takes a function in place of ``cveFeed.port_stage.run_for_scan``. ``port_double(report)`` is that
function with the Sentinel's side replaced: the real stage runs (the ledger, the targets, the activity lines) and what it hands to a scanner
(``sentinel_dispatch.try_nmap``) is answered by ``report(targets)``, the raw XML a Sentinel would send, read and stored the way the server reads a real
one (``port_inventory.parse_xml`` and ``persist_inventory``). ``port_double()`` answers with an empty report. Nothing here runs a tool.
"""
from unittest import mock

from cveFeed import port_inventory, port_stage

EMPTY_REPORT = '<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>'


def port_double(report=None):
    def run(scan_id, force=False):
        def try_nmap(project, scan, targets, org_id=None, timeout=None):
            text = report(list(targets)) if report is not None else EMPTY_REPORT
            return port_inventory.persist_inventory(port_inventory.parse_xml(text or EMPTY_REPORT), org_id=org_id, os_reliable=True)
        with mock.patch('agentapi.sentinel_dispatch.try_nmap', try_nmap), mock.patch('cveFeed.port_stage.enabled', return_value=False):
            return port_stage.run_for_scan(scan_id, force=force)
    return run
