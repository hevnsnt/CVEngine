# hostedsso: single sign-on from cvengine.live (hosted mode only)

Everything here is **off by default** and inert unless `CVENGINE_HOSTED` is on as well. The settings are in `docs/CONFIGURATION.md`; the design is
the "Interface contract" of the hosted SSO plan. A normal install and a hosted install without `CVENGINE_SSO` behave exactly as before (the app's two
tables stay empty, `/sso/*` answers 404, the middleware does nothing, cookie names are Django's).

| File | What |
| --- | --- |
| `verify.py` | Compact JWS, Ed25519 only (`cryptography`). Exact header (`alg` `EdDSA`, `typ` `cvl-sso+jwt` or `cvl-logout+jwt`, `kid`; any other member refused), key by `kid` from the local JWKS only (statuses current, next, retiring; reloaded when the file changes; an empty, half-written or unreadable file means no keys and is not cached, so it is read again on the next call), claim checks (iss, aud, exp/nbf/iat with 30 s leeway, lifetime at most 120 s, `mfa` true, `amr` has `otp` or `hwk`, `auth_time` within `CVENGINE_SSO_MAX_AUTH_AGE`, id shapes). Every failure is one `SsoError`; the reason code is logged, never token content. |
| `views.py` | `POST /sso/exchange` (assertion in, 204 with the session cookie out) and `POST /sso/backchannel-logout`. 404 when SSO is off, `X-CVL-Edge-Verified` is not `1` or `X-CVL-SSO-Exchange` is not `1`, 405 for other methods, 401 `invalid_assertion` for any verification failure, 403 `not_linked` for an unknown subject or inactive user. Refusals are throttled to 20 per address per 10 minutes. A `jti` is used once (table `SsoJti`, rows dropped after 10 minutes on each exchange). |
| `middleware.py` | After `AuthenticationMiddleware`. A session born from an exchange must carry matching `X-CVL-SSO-Sub` / `X-CVL-SSO-Sid` (trusted only with `X-CVL-Edge-Verified: 1`) on every request, else it is flushed (401 for API and non-GET, a redirect to `/_cvl/sso?next=` for pages: the one place besides step-up that uses that route). Also the step-up rule below. Sessions that did not come from SSO and API tokens are never touched. |
| `gating.py`, `common.py` | Login gating and the break-glass window; the `next` validation (Django's `url_has_allowed_host_and_scheme` plus the contract regex). |
| `management/commands/link_sso_identity.py` | `manage.py link_sso_identity --email E --subject S [--issuer I] [--force]`. Idempotent; refuses an inactive user and a user or subject already linked elsewhere unless `--force`. |

## User mapping

`SsoIdentity` links a local user to `(issuer, subject)`; lookup is by that pair only, never by email. An unknown subject is refused with 403 and an
`sso.not_linked` audit row; there is no just-in-time creation. Assertions carry identity, not authority: roles stay in cvENGINE. The site's email
becomes the account's email at the next sign-in and a change is audited (`sso.email_changed`, old and new).

## Sessions

`login()` is called for the linked user (the session key is rotated and any earlier session data dropped); the session stores `sso_sub`, `sso_sid`,
`sso_auth_time`, `sso_amr` and lasts `min(sexp - now, CVENGINE_SSO_MAX_AUTH_AGE)`. A session with `otp` or `hwk` in `sso_amr` satisfies an
organization's "require MFA" rule; enrolling a local factor stays possible. The back-channel logout deletes the matching SSO sessions (by `sid`
and/or `sub`) through the hashed-session store; repeating it is harmless.

Switching `CVENGINE_SSO` on or off renames the session and CSRF cookies (`__Host-cve_s`, `__Host-cve_csrf`), so **existing sessions are dropped** at
that moment.

## Login gating (`CVENGINE_SSO_ENFORCE`)

With SSO and enforcement on, `GET`/`POST /login/`, `/admin/login/`, the second-step page and an invite link's automatic sign-in answer with a 302 to
`/_cvl/start?next=<validated next>` (the edge sets the browser nonce there), unless break-glass is open: `CVENGINE_SSO_BREAKGLASS_UNTIL` in the future and at most 3600 s ahead, the request
carries `X-CVL-Edge-Verified: 1`, the local password is right and the account has local MFA (an account without it is refused). Each break-glass
step writes an audit row (`sso.breakglass_attempt`, `sso.breakglass_login`, `sso.breakglass_refused`) and a log line. With SSO on but not enforced the
login page shows a "Sign in with cvengine.live" link to the same `/_cvl/start?next=...`.

## Step-up (recent sign-in)

`has_recent_auth(request, max_age=None)`, `require_recent_auth(request, max_age=None)` (None, or the 403 response) and the decorator
`recent_auth_required` live in `middleware.py`. They only constrain sessions born from SSO (a local session and API tokens are unaffected) and
compare `sso_auth_time` with `CVENGINE_SSO_STEPUP_AGE` (900 s).

The sensitive actions are not wrapped view by view: the middleware applies the table `STEP_UP_RULES` (method and path) so no existing view is edited.
It covers user and membership management, organization API keys, project and organization delete, API token create/revoke, Sentinel/fleet enrollment
secrets, AI provider / key / mail / reviewer settings, Tailscale settings, exports (`/export/`) and the seed and egress downloads. A refusal is a 403
(`recent_auth_required` with `reauth_url` = `/_cvl/sso?prompt=stepup&next=<urlencoded validated path>`, or an error page; a POST returns to the landing page), never a redirect, so it cannot loop. **Follow-up for the edge:** the contract has no
step-up route; `/_cvl/sso` only re-mints when the site session is still fresh enough, so the site must offer a re-authentication that raises
`auth_time` (TOTP again) before this refusal can be cleared without signing in again.

## Tests

`web/tests/test_hosted_sso.py` (keys are generated in the tests; the site repository's fixed vector is checked too: a copy is kept in
`web/tests/fixtures/sso/`, test data only, and the vector tests fail rather than skip when it is missing; `CVENGINE_SSO_VECTOR` names another copy) and
`web/tests/test_hosted_sso_integration.py` (the real scripts' output through the real settings, gating, verifier and `link_sso_identity`). Run like
the rest of the suite: `python manage.py test tests.test_hosted_sso tests.test_hosted_sso_edge tests.test_hosted_sso_integration`. The review guide is
`docs/HOSTED-SSO-REVIEW.md`.
