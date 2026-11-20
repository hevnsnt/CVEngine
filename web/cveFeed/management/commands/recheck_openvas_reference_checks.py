"""The upgrade step of issue 414's follow-up: ``recheck_openvas_generic_checks`` with the policy-check rule (``openvas_scan.reference_check``).

A Greenbone policy check (a protocol, cipher or end-of-life detection, or one whose detected CPE is a protocol's) lists CVEs as references:
"SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection" (QoD 98) confirmed BEAST and FREAK on a host where neither applies. The same
command now un-confirms those too; it runs under its own name so an install that already ran the narrower recheck runs it again.

    python3 manage.py recheck_openvas_reference_checks            # dry run
    python3 manage.py recheck_openvas_reference_checks --apply    # un-confirm them
"""
from cveFeed.management.commands.recheck_openvas_generic_checks import Command  # noqa: F401
