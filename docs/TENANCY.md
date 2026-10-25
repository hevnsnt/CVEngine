# Organizations, roles, and two-step sign-in

The hierarchy is **Organization, then Project**. In code the organization model is `dashboard.Org`.

## Roles

| Role | Can do |
| --- | --- |
| admin | Everything a user can do. An organization admin also manages that organization's members and projects on the Administration page. |
| user | Add targets, scan, and build reports |
| audit | Read only. Anything other than GET, HEAD, or OPTIONS is refused, except changes to your own account and two-step sign-in. |
| pentester | Everything a user can do |

A role can be granted on an organization, which covers every project in it, or on a single project. A project role overrides the organization role for that project. Superusers are admin everywhere, and only they can open instance-wide settings (AI key, API vault, scan engines, `/admin/`). Organization admins manage the accounts and memberships of their own organizations on the Administration page.

Manage memberships on the **Administration** page (organization roles admin, user, and audit; project roles user and audit). The pentester role and a project admin are set in the Django admin at `/admin/`. A new user has no access until you assign one. A project goes into the organization chosen when it is created, otherwise the creator's admin organization, else the oldest one. A creator who is not a superuser becomes its project admin.

Bug bounty features are refused unless the user is an App Admin or an App Admin authorized that user (`UserProfile.bugbounty_enabled`, set on **Administration, Users, Manage** and written to the audit log). The role does not matter, and an organization admin cannot authorize anyone. See [BUG-BOUNTY.md](BUG-BOUNTY.md).

## How projects are isolated

1. `TenancyMiddleware` works out which projects the user may see on every request.
2. The default queryset of the main project-owned models (`SCOPES` in `tenancy/scope.py`) is filtered to those projects. This covers views, lookups by id, and templates. Child rows such as ports and IPs are reached through their scoped host.
3. A project slug the user cannot see returns 404, the same as a missing project. The slug `_all` is reserved (a project can never be created with it): it names the read-only combined view over every project the user can see. The services resolve the user's allowed project ids once, filter by them explicitly, and the scoped managers stay underneath; a write on `_all` is a 400, so it never replaces a project's own role check.
4. Roles are checked per project before the view runs, when the project is in the URL or query. The agent API checks them in its service layer.

When a model gains a project owner, add it to `SCOPES`. Background tasks and management commands run unscoped.

## Two-step sign-in

Time-based codes (TOTP: 30 seconds, 6 digits) with 8 single-use recovery codes. Turn it on at `/mfa/setup/` and off at `/mfa/disable/`. A password alone never signs in a user who has it on. Codes cannot be reused, five wrong codes lock the account's two-step sign-in for five minutes, and an organization can require it for all members (`Org.require_mfa`). A member of such an organization is sent to setup until enrolled and cannot turn it off; the REST API and MCP endpoint refuse that member (and any token they own) with a 403 until they enrol. An administrator can reset a user's two-step sign-in on the Administration page.

See also: [AGENT-API.md](AGENT-API.md) for how API tokens inherit roles, [DEPLOYMENT.md](DEPLOYMENT.md), [documentation index](README.md).
