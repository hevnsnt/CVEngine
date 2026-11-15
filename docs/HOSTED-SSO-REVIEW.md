# Hosted single sign-on: security review guide

For a human reviewer of branch `feat/sso-product` (the Django app, nginx, the hosted scripts and their tests merged). The frozen cross-repository contract is the "Interface contract" section of `docs/SSO-PLAN.md` in the cvengine-live repository (branch `feat/sso`); the product side is described in `web/hostedsso/README.md`, `hosted/README.md` and `docs/CONFIGURATION.md`. Everything is off by default.

## 1. What to read, in order

| Order | File | What to check |
| --- | --- | --- |
| 1 | `web/hostedsso/verify.py`: `_verify`, `_check_claims`, `_b64d`, `_no_duplicates`, `public_keys`, `_load_keys` | Exact header (alg `EdDSA`, `typ` per purpose, `kid`; no other member), canonical base64url, duplicate JSON members refused, key only from the local file by `kid`, every claim of the contract checked (iss, aud, exp/nbf/iat with 30 s leeway, lifetime at most 120 s, `mfa` is `true`, `amr` has `otp` or `hwk`, `auth_time` age, `sexp`, `jti` 32 hex, `nonce` 64 hex, `sid` 32 hex, `sub` of `[A-Za-z0-9_-]{1,64}`), one `SsoError` for everything, reason only in the log. `public_keys` fails closed and does not cache a failed read. |
| 2 | `web/hostedsso/views.py`: `_gate`, `exchange`, `_sign_in`, `_note_email`, `backchannel_logout`, `end_sessions` | 404 unless SSO is on and `X-CVL-Edge-Verified` is `1` and `X-CVL-SSO-Exchange` is `1`; POST only; failure throttle; `jti` insert inside a transaction (unique, replay refused); lookup by `(issuer, subject)` only; session flushed then `login()`; lifetime `min(sexp - now, MAX_AUTH_AGE)`; audit rows. |
| 3 | `web/hostedsso/middleware.py`: `SsoBindingMiddleware._bind`, `_step_up`, `STEP_UP_RULES`, `require_recent_auth` | Every request of an SSO-born session must carry nginx's `X-CVL-Edge-Verified: 1` plus `X-CVL-SSO-Sub` and `X-CVL-SSO-Sid` equal (constant time) to the stored values, else the session is flushed. Step-up table: is anything sensitive missing? The refusal is 403 with `reauth_url` `/_cvl/sso?prompt=stepup&next=...`. |
| 4 | `web/hostedsso/common.py`, `gating.py` | `sso_active`, `enforcing`, `edge_verified`, `exchange_header_ok`, `safe_next` (contract regex plus Django host check), `sso_url` (`/_cvl/start`), `stepup_url`, `breakglass_active` (integer, future, at most 3600 s ahead), `local_login_allowed`. |
| 5 | `web/tenancy/views.py` (the `gating.*` calls in `MFALoginView`, `admin_login_redirect`, `verify_view`, `invite_view`), `web/tenancy/middleware.py` (`_sso_second_factor`, `must_enrol_mfa`) | Under enforcement no local session can be opened except in a break-glass window that came through the edge; break-glass still needs local MFA; an SSO session counts as MFA only with `otp`/`hwk` in `amr`. |
| 6 | `web/hostedsso/management/commands/link_sso_identity.py` | Lookup by email must be unique, inactive users refused, a user or subject linked elsewhere refused without `--force`, retry for the same pair prints `already linked`. |
| 7 | `web/reNgine/settings.py` (block "Hosted single sign-on"), `web/reNgine/urls.py` (`sso/`), `MIDDLEWARE` order | `CVENGINE_SSO = HOSTED and flag`, `ENFORCE = SSO and flag`; cookie names and `Secure` only when SSO is on; binding middleware sits right after `AuthenticationMiddleware`. |
| 8 | `config/nginx/rengine.conf`: maps `$cvl_edge_ok_flag`, `$cvl_sso_sub`, `$cvl_sso_sid`, `$cvl_sso_exchange`, `underscores_in_headers off`, the `proxy_set_header` lines in the three proxied locations | The flag and the three SSO headers are functions of `$cvl_edge_ok`; client copies are overwritten or blanked; shapes are checked before forwarding. |
| 9 | `docker-compose.hosted.yml` (web `environment` and key-file mount) | Read-only single-file mount at `/etc/cvl/sso-keys.json`; settings passed only when defined in `.env`. |
| 10 | `hosted/cvl-set-sso-keys.sh`, `hosted/cvl-sso-mode.sh`, `hosted/cvl-personalize.sh`, `hosted/cvl-firstboot.sh`, `hosted/lib/common.sh` (`cvl_write_in_place`, env helpers) | Validation before any change; only public keys; no key material in output or logs; `--enforce on` refused without SSO and a key; break-glass is Unix seconds, 1 to 60 minutes. |
| 11 | Tests: `web/tests/test_hosted_sso.py`, `test_hosted_sso_edge.py`, `test_hosted_sso_integration.py`, `test_hosted_mode.py`, fixture `web/tests/fixtures/sso/` | See section 4. |

## 2. Trust boundaries

1. **Internet to edge (Cloudflare Worker, other repository).** The only party that can mint an assertion is the site (Ed25519 private key in a Worker secret). The edge refuses browser requests to `/sso/*` and `/_cvl/*` upstream paths and deletes client copies of the `X-CVL-*` headers.
2. **Edge to nginx on the server.** The edge secret (`X-CVL-Edge-Auth`) is the only proof that a request came from the edge. nginx compares it against `/etc/nginx/edge-auth.conf`, sets `X-CVL-Edge-Verified: 1|0` itself, and forwards `X-CVL-SSO-Sub`, `X-CVL-SSO-Sid` and `X-CVL-SSO-Exchange` only when the secret matched and the value has the expected shape. Anyone holding the secret can speak as the edge: the secret is the root of trust of the per-request binding, but not of the assertion (the signature is).
3. **nginx to Django (internal Docker network).** Django believes `X-CVL-Edge-Verified` because only nginx can reach it; `CVENGINE_TRUSTED_PROXIES` governs the client address as before. A container that can reach `web:8000` directly could forge these headers; the compose network keeps that to the stack's own services.
4. **Assertion trust.** Django trusts the local JWKS file (`/etc/cvl/sso-keys.json`, written by root-run scripts only, mounted read-only) and the `aud` it derives from its own settings. Authority (roles, projects) stays in cvENGINE; the assertion only selects a pre-linked local user. No just-in-time creation.
5. **Provisioner to server.** `cvl-sso-mode.sh`, `cvl-set-sso-keys.sh` and `cvl-personalize.sh` run as root over SSH; they edit `.env` and the key file. Whoever can run them can enable, enforce, rotate or open break-glass: that is the owner's control plane.

## 3. Default-off proofs

* `web/tests/test_hosted_sso.py::DefaultOffSettingsTests`: clean interpreters show that a stock install, a hosted install without `CVENGINE_SSO`, SSO variables without hosted mode, and enforcement without SSO all leave `CVENGINE_SSO`, `CVENGINE_SSO_ENFORCE` false and the cookie names `sessionid` / `csrftoken`.
* `DefaultOffBehaviourTests`: `/sso/exchange` and `/sso/backchannel-logout` answer 404 (with and without the edge header), the login form and admin redirect are stock, the binding middleware and step-up ignore a session that carries SSO keys, an SSO flag in a session does not satisfy "require MFA" when SSO is off, a hosted install with `CVENGINE_SSO=False` and `ENFORCE=True` is unchanged.
* `web/tests/test_hosted_sso_edge.py::StockSsoProxyTests` (real nginx): with the stock empty edge file the flag is `0` and no SSO header is ever forwarded; `SsoComposeTests`: the stock compose file knows nothing about SSO, and the overlay passes variables only when `.env` defines them; `SsoFirstbootTests`: first boot writes `CVENGINE_SSO=0`, `CVENGINE_SSO_ENFORCE=0` and an empty key set; `SsoPersonalizeTests`: without SSO the subject is ignored and the output is unchanged.
* Read `web/reNgine/settings.py` yourself: two lines decide it (`CVENGINE_SSO = CVENGINE_HOSTED and env.bool(...)`, `ENFORCE = SSO and ...`). `hostedsso` adds two empty tables and one URL prefix; migrations only create them.

## 4. What the tests prove (cross-side)

| Point | Test |
| --- | --- |
| nginx forwards exactly what Django accepts: flag `1`, sub (UUID text) and sid (32 lowercase hex), exchange `1` | `test_hosted_sso.py::EdgeContractTests`, `test_hosted_sso_edge.py::HostedSsoProxyTests` |
| exchange requires `X-CVL-SSO-Exchange` exactly `1` on both endpoints | `EdgeContractTests.test_the_exchange_header_must_be_exactly_one_on_both_endpoints` |
| Set-Cookie is `__Host-cve_s`, Secure, HttpOnly, SameSite=Lax, Path=/, no Domain, with the settings a hosted server really computes | `SessionCookieTests` |
| key file empty, half written, invalid JSON, wrong shape or unreadable: nothing verifies and the failure is not cached | `VerifyTests.test_an_empty_key_file...`, `test_a_half_written_key_file...`, `test_an_unreadable_key_file...`, `test_a_key_file_that_is_not_an_object...` |
| the site's fixed vector verifies (not skipped) | `FixedVectorTests` with `web/tests/fixtures/sso/vector.json`; `test_hosted_sso_integration.py::KeyFileThroughTheScriptsTests` pushes its JWKS through the real `cvl-set-sso-keys.sh` and verifies it |
| break-glass: the script's Unix seconds are the integer the settings read and the gating honours (1, 30, 60 minutes; closed at the stated second; login page open only through the edge) | `BreakGlassEndToEndTests` |
| `cvl-personalize.sh`'s exact argv goes through the real `link_sso_identity`; a retry is idempotent; a different subject is refused | `LinkThroughThePersonalizeScriptTests` |
| login redirects go to `/_cvl/start?next=`; only the step-up `reauth_url` uses `/_cvl/sso?prompt=stepup&next=` | `GatingTests`, `StepUpTests.test_the_refusal_names_the_step_up_route_with_the_validated_path` |

## 5. Remaining risks (known, accepted for now, to be judged by the reviewer)

1. **In-place rewrite of the key file is not atomic.** The single-file bind mount needs the same inode, so `cvl_write_in_place` truncates and writes. A reader can see an empty or partial file. Handling: the verifier treats it as no keys (refuses everything) and does not cache the failure, so the next call re-reads; the cost is a failed sign-in during the write. A signature of `(mtime_ns, size, inode)` is used to detect changes; a rewrite with an identical size and an identical mtime within one timestamp tick would not be noticed.
2. **Back-channel logout scans sessions linearly.** `end_sessions` decodes every unexpired session row to match `sid` or `sub`. Fine for one owner's server; a large session table makes the call slow (the endpoint is throttled only on failures).
3. **`jti` cleanup happens only on exchange.** Expired rows are deleted when the next exchange runs; a quiet server keeps up to ten minutes of rows plus the last batch. Harmless, but not a scheduled job.
4. **nginx map comparison is not constant time and is case-insensitive.** The edge secret match is an nginx `map` lookup (case-insensitive for plain strings), so a secret that differs only in case would also match, and timing is not constant. Mitigated by 256-bit random secrets, the network path, and the fact that the secret alone cannot create a session (a signed assertion is also needed; the secret alone only lets a caller impersonate the edge for already bound sessions whose sub and sid it knows).
5. **Break-glass changes need a restart.** `CVENGINE_SSO_BREAKGLASS_UNTIL` is read from the environment at process start; `cvl-sso-mode.sh` recreates `web` (a short outage) for every change. A window open at the time of a crash restart stays open until it expires; it is never longer than 60 minutes from the script run, and settings treat a value more than an hour ahead as closed.
6. **Step-up cannot actually be raised yet.** The edge ignores the `prompt=stepup` parameter of `/_cvl/sso`; it only re-mints while the site session is fresh. A step-up refusal after 15 minutes therefore needs a fresh site login (TOTP) before it clears. Needs the site's re-authentication route; not a weakening, a usability gap.
7. **Switching `CVENGINE_SSO` renames the session and CSRF cookies**: every session is dropped at that moment, in both directions.
8. **Anyone holding the edge secret and a valid `sub`/`sid` pair** can keep an SSO-born session alive from outside the edge; `sid` is a hash of the site's session family id, not a secret by itself.
9. **Email changes follow the site.** A linked user's local email is replaced by the site's email at the next sign-in (audited). If the site lets an owner change email without verification, local email-based flows follow it.
10. **Fixture key.** `web/tests/fixtures/sso/vector.json` contains the documented test-only Ed25519 seed (`01 02 ... 20`). It is not a real key; secret scanners may flag the PKCS8 field.
11. **The failure throttle lives in the shared Redis cache** (`tenancy.throttle`, atomic counters): it is only as available as that cache, and an unreachable cache raises on the refusal path (the request fails, it is never accepted).

## 6. Manual test checklist for staging

Prepare: one staging hosted server with a real site customer who has MFA, a second owner account without a link, `CVENGINE_SSO=0`, cvl-set-sso-keys.sh run with the site's current public key, `timedatectl show -p NTPSynchronized --value` is `yes`.

Default off
- [ ] With `CVENGINE_SSO=0`: browse to the scanner, sign in locally as before; cookies are `sessionid` and `csrftoken`; `curl -i -X POST https://<origin>/sso/exchange` is 404 (also with a guessed `X-CVL-SSO-Exchange: 1` header).

Phase A
- [ ] `cvl-sso-mode.sh --sso on`: output `{"ok":true,"sso":true,"enforce":false,"breakglass_until":null}`; everyone is signed out once; cookies are now `__Host-cve_s` and `__Host-cve_csrf`.
- [ ] Open the scanner URL: you are sent to `/_cvl/start`, then cvengine.live, then back signed in without a second password; the `Set-Cookie` in DevTools has Secure, HttpOnly, SameSite=Lax, Path=/, no Domain.
- [ ] The login page (`/login/`, open in a private window) shows "Sign in with cvengine.live" and its link starts with `/_cvl/start?next=`; local login still works.
- [ ] A site login completed with a recovery code (no assertion) falls back to the second, local login.
- [ ] An owner with no linked identity gets `not_linked` (the edge shows its fallback) and an `sso.not_linked` audit row; no account is created.
- [ ] Suspend the customer on the site: the scanner session ends within 15 s (back-channel logout; check `sso.backchannel_logout` audit row).
- [ ] Log out on the site: the scanner session ends.
- [ ] Log in as a different site user in another browser profile with the same cookies pasted: the session is flushed (binding mismatch) and you are redirected to `/_cvl/sso?next=` or get 401 on API calls.
- [ ] `curl -H 'X-CVL-Edge-Verified: 1' -H 'X-CVL-SSO-Exchange: 1' -X POST https://<origin>/sso/exchange` from outside: no 204 (404 or 403 from nginx, the secret is missing).
- [ ] Create an API token (or change a user): with a sign-in older than 15 minutes you get 403 `recent_auth_required` whose `reauth_url` is `/_cvl/sso?prompt=stepup&next=%2F...`; with a fresh sign-in it works.

Keys
- [ ] Push `next` key, switch the site to it, push `current` plus `retiring`: sign-ins keep working at every step with no restart. Push without the old key: tokens signed by it fail.
- [ ] Emergency revoke: push a set without the current kid: sign-in fails at once; the existing sessions continue until their expiry or logout.
- [ ] `cvl-set-sso-keys.sh --check` lists kids only; `/etc/cvl/sso-keys.json` is mode 600; the container sees it read-only (`docker compose exec web ls -l /etc/cvl/sso-keys.json`); `docker compose exec web sh -c ': > /etc/cvl/sso-keys.json'` fails.

Phase B
- [ ] `cvl-sso-mode.sh --enforce on` is refused when the key file is empty; with a key it succeeds.
- [ ] `/login/` and `/admin/login/` answer 302 to `/_cvl/start?next=...` (also with `next=//evil.example`, which is replaced by `/cve/`); POSTing the password form sets no session.
- [ ] `cvl-personalize.sh` on a new server (with `sso_subject`) leaves the password out of its JSON and the owner can sign in only through SSO.
- [ ] Re-run `cvl-personalize.sh` for the same customer: success, `already linked`, no duplicate.

Break-glass and rollback
- [ ] `cvl-sso-mode.sh --breakglass 5`: output has a Unix-seconds `breakglass_until`; `web` restarted; through the edge the local form is offered and needs password and TOTP; an account without local MFA is refused; audit rows `sso.breakglass_*` exist; after five minutes the form redirects again.
- [ ] Same form reached directly on the server without the edge secret: still redirected.
- [ ] `cvl-sso-mode.sh --breakglass off`: the variable is gone from `.env`.
- [ ] `--enforce off` brings the local login back; `--sso off` turns enforcement and break-glass off and everyone signs in once more with the stock cookie names.

Hygiene
- [ ] `docker compose logs web proxy` and the audit log contain no assertion, no key material and no edge secret.
- [ ] `python manage.py test tests.test_hosted_sso tests.test_hosted_sso_edge tests.test_hosted_sso_integration tests.test_hosted_mode tests.test_tunnel_client_address` is green on the release commit.
