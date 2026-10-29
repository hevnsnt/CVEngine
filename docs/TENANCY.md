# Organizations, roles, and two-step sign-in

The hierarchy is **Organization, then Project**. A role can be granted on an organization, which covers every project in it, or on a single project, and a project role overrides the organization role for that project.

## Roles

| Role | Can do |
| --- | --- |
| admin | Everything a user can do. An organization admin also manages that organization's people and projects on the Administration page. |
| user | Add targets, scan, validate, and build reports |
| audit | Read only. Changes are refused, except to your own account and two-step sign-in. |
| pentester | The same as user |

Superusers (App Admins) are admin everywhere, and only they open instance-wide settings: everything under **Settings** (AI model, Tailscale, OpenVAS, notifications, email, scan policy, IP allowlist, proxy, reports, resources, updates, factory reset, and the API keys tab), and `/admin/`. A new user has no access until you assign some. Manage people on the **Administration** page: organization roles admin, user, and audit, and project roles user and audit. The pentester role and a project admin are set in the Django admin at `/admin/`. A project goes into the organization chosen when it is created, otherwise the creator's admin organization, else the first organization (the Default one), and a creator who is not a superuser becomes its project admin.

**Organization admin limits.** Only App Admins create or delete organizations, delete accounts, or grant bug bounty access. An organization admin manages only non-superusers who belong to an organization they administer. Resetting a password or two-step sign-in, or deactivating an account, is refused (403) when the account also belongs to an organization they do not administer or holds bug bounty access. They may add a membership only for a brand-new user, a user who has never signed in and has no memberships, or one whose memberships are all in organizations they administer. They cannot lower their own role or disable their own account, and lifting a host exclusion needs organization admin.

**Passwords.** A password an App Admin or organization admin sets, and the generated one `make admin` prints, must be replaced at the next sign-in: until then pages redirect to My account and API calls answer 403 "choose your own password first". A password you chose yourself is not forced to change.

The bug bounty page is available to App Admins and to users an App Admin authorizes on **Administration, People, Manage**, whatever their role ([BUG-BOUNTY.md](BUG-BOUNTY.md)).

## How projects are isolated

1. The tenancy middleware works out which projects the user may see on every request.
2. The default queryset of the main project-owned models (`SCOPES` in `tenancy/scope.py`) is filtered to those projects, for views, lookups by id, and templates. Child rows such as ports are reached through their scoped host.
3. A project the user cannot see returns 404, the same as one that does not exist.
4. Roles are checked per project before the view runs, when the project is in the address or query string. A route that names its project only in the body or by an object id is checked against the user's best role anywhere, so its handler must check the role again for the project it resolves (the agent API does, in its service layer).
5. Targets and IP rows (with their ports) belong to an organization. Two organizations can track the same name separately, and within one a name is held once across its projects. Host exclusions, organization API keys, and the two-step policy are organization wide.
6. The slug `_all` is reserved. It is the read-only combined view over every project the user can see, and writes on it return 400.

**Scan files (`/media/...`).** Screenshots and other scan artifacts are served by an authenticated view and nginx's internal redirect, never straight from the volume. A user who is not an App Admin gets a file only from the `<domain>_<scan id>/` folder of a scan in a project they can see; anything else answers 404, the same as a missing file. Behaviour change: a bare `<domain>/` folder (the layout of the upstream project, which cvENGINE never writes) used to be served to anyone who could see a target of that name and is now served to App Admins only, because it is not tied to a scan and so cannot be attributed to a project. Files created by an older upstream-style install under such a folder need an App Admin, or moving into a `<domain>_<scan id>/` folder.

Background tasks and management commands run unscoped. When a model gains a project owner, add it to `SCOPES`, or to `UNSCOPED` in the same file with the reason; `tests/test_sentinel_hardening.py` fails for a model with a project, domain, scan or organization owner that is in neither. Sentinel tasks, stored sign-ins, finding comments and audit events, internal ranges, project settings and the like are scoped; an organization's own API credentials (no project) stay visible to the organization.

## Two-step sign-in

Time-based codes (TOTP: 30 seconds, 6 digits) and 8 single-use recovery codes, managed under Two-step sign-in on **My account** (`/cve/account/`). A code cannot be reused, and a code from one step either side is accepted. Five wrong codes, counted from the first failure, lock two-step sign-in (and turning it off) for five minutes. The sign-in field accepts a code or a recovery code. Recovery codes are 80 bits, stored as HMACs keyed with `web/secret`, so losing that file invalidates codes made in 1.2 or later. The seed is encrypted in the database. An organization can require it for all members, including users assigned only to one of its projects (`Org.require_mfa`): those members are sent to My account until they enroll, cannot turn it off, and are refused by the REST API and MCP endpoint (with any token they own) until they do. An administrator can reset a user's two-step sign-in on the Administration page, which also revokes that user's API tokens.

## Onboarding email

An App Admin sets the outgoing mail server under **Settings, Email**. With it on, adding a person on **Administration, People** (an App Admin, or an organization admin for their own organizations) with an email address and no typed password creates the account with no usable password and sends them a welcome email: their username, what they can reach, and a **Set your password** button. Nothing is handed over by hand and no password exists until they choose one.

- **The link** is signed with the site's secret key and names one account. It works once: it is tied to the account's current credentials, so choosing a password, or an administrator resetting the password, ends it. It expires after `CVENGINE_INVITE_DAYS` days (7 by default, 1 to 30). Opening it only shows the form; the password is set by submitting the form, so a mail scanner that follows links cannot spend it. The page is not cached, sends no referrer, and counts unreadable links per address (20 in ten minutes, then 429). Choosing a password does not sign anyone in; they sign in with the username and the new password, and an organization that requires two-step sign-in still sends them to enroll.
- **Where the link points** comes from **Settings, Email, Link address** (for example `https://scanner.example.com`), else `https://` plus `DOMAIN_NAME`. It is never taken from the request, so a forged Host header cannot point an email at another site.
- **When no email is sent**, the add-person dialog shows a temporary password as before: mail is off, the person has no address, an administrator typed a password, or the send failed (the dialog then says why). **Manage, Send invitation again** sends a fresh link to a person who has not chosen a password yet and ends the earlier ones; **Reset password** still issues a temporary password.
- **The mail server** is addressed over SMTP with STARTTLS, SSL/TLS or no encryption (no encryption only without a login) and verifies its certificate unless **Verify the server certificate** is turned off for a relay with a private certificate. The stored password is encrypted and never shown. Errors shown to the administrator describe the kind of failure (login refused, certificate not trusted, no answer) and never carry the server's own text or the password.

## Sign-in limits and sessions

Wrong passwords at sign-in are limited to 5 per address and name, 30 per address, and 50 per name, each counted from the first failure within five minutes. Past a limit the form answers 429 before it checks the password, and a right password clears the pair's count. Names are normalized (NFKC, case-folded), so spelling variants share a counter. Changing your password has its own limit (5 wrong current passwords in 10 minutes), and so does the factory reset. Sessions are stored under a keyed hash of the cookie, not the cookie itself, so a copy of the session table is not a list of working logins. Changing your password ends your other sessions, and every response carries a partial Content-Security-Policy (`base-uri`, `object-src`, `frame-ancestors`, `form-action`).

## Audit log

An App Admin sees every row; an organization admin sees the rows tagged with an organization they administer. The page shows the last 200 rows and factory reset clears the log. Credential events are written once for each organization of the user.

| Seen by organization admins | Events |
| --- | --- |
| People and organizations | `user.create`, `user.update`, `user.delete`, `user.reset_password`, `user.reset_mfa`, `user.bugbounty_grant`, `user.bugbounty_revoke`, `membership.set`, `membership.remove`, `org.create`, `org.update`, `project.create`, `project.delete`, and the `org.api_key.*` and `project.api_key.*` events |
| Hosts | `host.archive`, `host.restore`, `host.pin`, `host.delete`, `host.exclude`, `host.unexclude` |
| Accounts and tokens | `account.password_change`, `account.mfa_enable`, `account.mfa_disable`, `account.mfa_locked`, `account.login_locked`, `token.create`, `token.revoke` (never the token or its name) |
| Bug bounty | `bounty.project_create`, `bounty.engagement_create`, `bounty.automated_ok`, `bounty.policy_ack`, `bounty.import_targets`, `bounty.submit` |
| Sentinels and agents | `agent.register`, `agent.update`, `agent.unregister`, `agent.status`, `agent.limits`, `agent.settings`, `agent.update_requested`, `agent.task.*`, `sentinel.enroll.generate` (project and organization scope), `sentinel.task.*` |
| Networks, credentials and integrations | `internal_range.add`, `internal_range.delete`, `internal_range.discover`, `target.auth_credential.set`, `target.auth_credential.remove`, `report.export`, `inventory.report`, `inventory.adopt`, `inventory.delete`, `tailscale.link.*`, `tailscale.sync`, `project.runzero.settings`, `project.runzero.sync`, `openvas.org.update`, `openvas.project.update`, `openvas.project.remove` |

App Admins alone see `targets.delete`, `org.delete`, `scan_policy.nuclei_all_templates`, `openvas.enable`, `openvas.disable`, `openvas.update`, `sentinel.defaults`, `sentinel.enroll.generate` for an instance-wide secret, the update events (`update.mode_changed`, `update.approved`, `update.approval_cancelled`, `update.available`), `scanning.pause`, `scanning.resume`, `timings.update`, `system.factory_reset`, the bug bounty catalogue and credential events, and the abuse events (`abuse.superuser_flagged`, `abuse.account_disabled`, `abuse.ip_banned`).

A token can also be a **reporter token** (`scope: inventory`), bound to one project and able to do nothing except post that project's host inventory reports; it acts with its creator's role, so it needs a write role in the project and stops working when the creator is removed or disabled ([HOST-INVENTORY.md](HOST-INVENTORY.md)). Anyone with a write role in the project can mint one, from a signed-in session only (a token cannot mint a token), and it expires after 365 days.

## Newer surfaces

Who may read and who may change the features added in 1.3. "Write role" means admin, pentester or user (never audit), with a token that is not read only. "Project admin" means the admin role on the project, which an organization admin and an App Admin also hold. Every row is checked per project, `_all` is refused for anything that changes data, and a project the caller cannot see answers 404.

| Surface | Read | Change |
| --- | --- | --- |
| Sentinels, in a project (the Sentinels tab) | Any role in the project sees the Sentinels whose scope covers it and their task counts for it. | Cancel a queued or running task: a write role. Approve, suspend, revoke, limit or change the settings of a Sentinel: an administrator who manages the Sentinel's owner, never for their own Sentinel unless an App Admin (see Agents below). |
| Sentinel enrollment (the one-time secret that provisions a Sentinel, 30 minutes, single use) | Not readable again. | Project scope: project admin. Organization scope (every project of it, present and future): an admin of that organization or an App Admin. Instance scope: an App Admin. Each is audited as `sentinel.enroll.generate`. |
| Sentinels page and instance defaults | Each person sees the Sentinels they manage: an App Admin all of them, an organization admin those of users in their organizations, everyone else their own. | The instance-wide self-update default: an App Admin. |
| Internal ranges (private networks declared internal to a project) | Project admin only, including the list. | Project admin only. A range never opens a public address, and only an internal Sentinel scans inside one: the server grants `network:internal` (at provisioning, or when an administrator changes the Sentinel's network), and a Sentinel's own claim is ignored. |
| OpenVAS | **Settings, OpenVAS** is for App Admins. **Administration, OpenVAS** lists the organizations the person administers and their projects. Members and auditors have no access. | Switching the add-on on or off, and the Sentinel only choice: an App Admin. Choosing which organizations and projects to scan: an App Admin, or an organization admin for the organizations they administer, and only while the add-on is on. Audited as `openvas.*`. |
| Saved searches | Private to the person who saved them: another member, another project or a guessed id answers 404. | Create, change, delete or run one (a run can notify): a write role. |
| PDF reports | Any role that can read the project, the audit role and a read-only token included. A report is made for one named project (or one host of it), and only the person who asked can read its state and download it, until it expires (24 hours by default). | Asking is the same as reading, capped per user and for the installation (the API answers 429 over a cap). Audited as `report.export`. |
| Authenticated-check credentials (stored headers and cookie a scan sends to a target) | An App Admin or the organization admin of the project's organization, listing included. A project admin who is not also an organization admin, and every other role, gets 403. | The same. Values are write-only and shown masked, and every change is audited (`target.auth_credential.set`, `.remove`). |
| Host inventory reports | Any role in the project. | Adopt, delete: a write role. Posting a report: a reporter token of the project (see above). |
| Suppliers | Any role in the project. | Add or remove a supplier, accept a finding: project admin. |
| runZero sync | Project admin. | Project admin (settings, Sync now). |
| Tailscale connection (per project) | Project admin, secrets never returned. | Project admin through the API. In the app it is set under **Settings, Tailscale**, which is for App Admins. |
| API keys for outside services | Any role that can see the project sees which keys are set, never the values. | Organization keys: an organization admin or an App Admin. A project's own key: a project or organization admin or an App Admin, through the API and through the pages in the app (**Settings, API keys** and **Administration**). |

## Agents

An agent registers the organizations, projects and hosts it is responsible for, and can claim only what its token's user can reach. Work is handed to it only in projects where that user has the user or admin role (the audit role and read-only tokens get none), and the check is repeated at every assignment. A new agent waits for an administrator's approval (an administrator's own is active at once), and the role is checked again on every heartbeat, accept and report, so a demoted user's agent stops at once. An App Admin sees and administers every agent; an organization admin sees the agents of users in their organizations, with other tenants' projects left out, and administers only users who belong to no organization they do not administer. Nobody approves or limits their own agent but an App Admin. Everyone else sees their own agents and cannot change their limits. See [Agents and assigned work](AGENT-API.md#agents-and-assigned-work).

See also: [AGENT-API.md](AGENT-API.md) for how API tokens inherit roles, [documentation index](README.md).
