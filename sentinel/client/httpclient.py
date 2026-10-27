"""A small, typed wrapper over ``requests`` for the handful of REST calls the Sentinel client makes
(``docs/AGENT-API.md``): bootstrap, heartbeat, tasks/next, accept, result, release. No retry logic lives here; the
daemon's own poll loop decides when to back off (see ``daemon.Daemon._poll_once``), so one place owns that policy.
"""
import json
import logging

import requests

logger = logging.getLogger('sentinel.http')


class ApiError(Exception):
    """The server answered with a 4xx/5xx. ``status`` and ``message`` are set; the message is already a short string
    the server chose to show, never a raw response body (which could be arbitrarily large or not be JSON at all)."""

    def __init__(self, status, message):
        super().__init__(f'{status}: {message}')
        self.status = status
        self.message = message


class Client:
    """One Sentinel's connection to one CVEngine instance. ``token`` is optional only for the very first call
    (``sentinels/bootstrap``, which needs none); every other call requires it."""

    def __init__(self, server_url, token=None, timeout=30, session=None):
        self.base = server_url.rstrip('/') + '/api/v1/'
        self.token = token
        self.timeout = timeout
        self.session = session or requests.Session()

    def _headers(self):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        return headers

    def call(self, method, path, body=None, timeout=None):
        """One REST call; returns the decoded JSON body. Raises ``ApiError`` on a 4xx/5xx, or ``requests.RequestException``
        on a network failure (connection refused, DNS, timeout): the caller (``daemon``) decides how to back off from
        each, never this method."""
        url = self.base + path.lstrip('/')
        data = json.dumps(body).encode('utf-8') if body is not None else None
        response = self.session.request(method, url, data=data, headers=self._headers(),
                                        timeout=timeout if timeout is not None else self.timeout)
        try:
            payload = response.json() if response.content else {}
        except ValueError:
            payload = {}
        if response.status_code >= 400:
            message = (payload.get('error') if isinstance(payload, dict) else None) or f'HTTP {response.status_code}'
            raise ApiError(response.status_code, str(message)[:300])
        return payload if isinstance(payload, dict) else {}
