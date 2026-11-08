"""What a failed scan stage's stored message says about its cause, shared with the auto-tuner's measurements (cveFeed.autotune_signals).

This module once held the three-hour review of scanner capacity, which ran with the three-hour AI assessment review. The auto-tuner
(cveFeed.autotune) owns the scanner limits, and the assessment review is retired (the AI reviewer's operations check replaces it,
docs/AI-REVIEWER.md), so only the classification of failures is left: ``failure_cause`` and the patterns behind it.
"""
import re

# Only stage names that identify the scanner kind can support a per-tool
# failure adjustment. Generic discovery errors cannot justify lowering an
# unrelated scanner's concurrency.
STAGE_KINDS = {'nmap_scan': 'nmap', 'nuclei_light_scan': 'nuclei',
               'nuclei_targeted_scan': 'nuclei', 'route_auth_scan': 'route-probe'}
# What a failed stage's stored message says about its cause (the texts the scanners raise: see resources.MemoryBusy, the nmap and Nuclei
# wrappers, route_auth). Only a failure that points at load can justify a lower admission cap; one that points at configuration (a missing
# template library, a policy refusal, an invalid argument, a missing key) will fail again at any concurrency, and a message that says
# neither is not acted on.
CAPACITY_PATTERN = (r'waited too long for memory|timed out|timeout|exceeded its total time budget|out of memory|cannot allocate memory|'
                    r'too many open files|resource temporarily unavailable|exited with status (-9|-11|137|139)( |:|$)|killed')
CONFIGURATION_PATTERN = (r'unavailable|not installed|not found|no such file|passed the read-only policy|permission denied|invalid|'
                         r'unknown flag|unrecognized|missing|api key|unauthori[sz]ed|forbidden|not scanned:|is excluded|prohibited|'
                         r'is not allowed|not permitted|unsupported')
# resources.ScannerUnavailable (a MemoryBusy): "no scanner could run <kind> work ...". Work that waits for a scanner says nothing about this server's memory.
SCANNER_UNAVAILABLE_PATTERN = r'no scanner could (run|take)'


def failure_cause(message):
    """``capacity``, ``configuration`` or ``other`` for a failed stage's stored message. A message that matches both reads as capacity
    (the stage ran out of something), because lowering a cap on a misjudged configuration error costs less than missing a real overload."""
    text = str(message or '')
    if re.search(SCANNER_UNAVAILABLE_PATTERN, text, re.I):  # no scanner could take it (a Sentinel's own text may say "timed out"): that is not this server's load
        return 'other'
    if re.search(CAPACITY_PATTERN, text, re.I):
        return 'capacity'
    if re.search(CONFIGURATION_PATTERN, text, re.I):
        return 'configuration'
    return 'other'
