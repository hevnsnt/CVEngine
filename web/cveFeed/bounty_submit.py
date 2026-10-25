"""Sending a report to HackerOne with the submitting user's own account. The one outbound call of the bug bounty feature that
carries a person's words, so it is narrow: a fixed address, no redirects, a timeout, the user's own credential, and nothing from the
response is trusted beyond a report id."""
import logging
import re

logger = logging.getLogger(__name__)

HACKERONE_REPORTS = "https://api.hackerone.com/v1/hackers/reports"
HACKERONE_ME = "https://api.hackerone.com/v1/hackers/me/reports"
TIMEOUT = (10, 30)


class SubmitError(Exception):
    """``uncertain`` is True when the request may have reached the platform (a timeout): the report might exist."""

    def __init__(self, message, status=None, uncertain=False):
        super().__init__(message)
        self.message, self.status, self.uncertain = message, status, uncertain


def _errors(response):
    """A short, safe description of a platform error body: titles and details only, cut to a length."""
    try:
        body = response.json()
    except ValueError:
        return ""
    items = body.get("errors") if isinstance(body, dict) else None
    parts = []
    for item in (items if isinstance(items, list) else [])[:3]:
        if isinstance(item, dict):
            parts.append(" ".join(str(item.get(k, "")) for k in ("title", "detail") if item.get(k)))
    return re.sub(r"\s+", " ", "; ".join(p for p in parts if p))[:300]


def submit_hackerone(payload, username, token, post=None):
    """POST the payload; returns ``{"id", "url"}``. Raises SubmitError. ``post`` is injectable for tests."""
    import requests
    try:
        resp = (post or requests.post)(HACKERONE_REPORTS, auth=(username, token), json=payload, timeout=TIMEOUT, allow_redirects=False,
                                       headers={"Accept": "application/json", "Content-Type": "application/json"})
    except requests.Timeout:
        raise SubmitError("HackerOne did not answer in time. The report may or may not have been created: look at your reports on "
                          "HackerOne before you try again.", uncertain=True)
    except requests.RequestException:
        raise SubmitError("Could not reach HackerOne. Nothing was sent.")
    if resp.status_code == 201:
        try:
            rid = str(resp.json()["data"]["id"])
        except (ValueError, KeyError, TypeError):
            raise SubmitError("HackerOne accepted the report but the answer was not understood. Check your reports on HackerOne.",
                              status=201, uncertain=True)
        if not re.fullmatch(r"\d{1,12}", rid):
            raise SubmitError("HackerOne returned an unexpected report id. Check your reports on HackerOne.", status=201, uncertain=True)
        return {"id": rid, "url": f"https://hackerone.com/reports/{rid}"}
    detail = _errors(resp)
    hint = {401: "HackerOne refused the API credentials; check them in My accounts.", 403: "Your HackerOne account may not submit to this program.",
            404: "HackerOne does not know this program handle.", 422: "HackerOne rejected the report."}.get(resp.status_code, "HackerOne refused the report.")
    raise SubmitError(f"{hint}" + (f" ({detail})" if detail else "") + f" [HTTP {resp.status_code}]", status=resp.status_code)


def check_hackerone(username, token, get=None):
    """True when the credentials are accepted (a one-item read of the user's own reports), False when refused, None when unreachable."""
    import requests
    try:
        resp = (get or requests.get)(HACKERONE_ME, auth=(username, token), params={"page[size]": 1}, timeout=TIMEOUT, allow_redirects=False,
                                     headers={"Accept": "application/json"})
    except requests.RequestException:
        return None
    return True if resp.status_code == 200 else False if resp.status_code in (401, 403) else None
