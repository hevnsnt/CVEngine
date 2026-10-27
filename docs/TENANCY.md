# Organizations, roles, and two-step sign-in

The hierarchy is **Organization, then Project**. A role can be granted on an organization, which covers every project in it, or on a single project, and a project role overrides the organization role for that project.

## Roles

| Role | Can do |
| --- | --- |
| admin | Everything a user can do. An organization admin also manages that organization's people and projects on the Administration page. |
| user | Add targets, scan, validate, and build reports |
| audit | Read only. Changes are refused, except to your own account and two-step sign-in. |
| pentester | The same as user |

Superusers (App Admins) are admin everywhere, and only they open instance-wide settings: the AI key, API vault, scan engines, and `/admin/`. A new user has no access until you assign some. Manage people on the **Administration** page: organization roles admin, user, and audit, and project roles user and audit. The pentester role and a project admin are set in the Django admin at `/admin/`. A project goes into the organization chosen when it is created, otherwise the creator's admin organization, and a creator who is not a superuser becomes its project admin.

The bug bounty page is available to App Admins and to users an App Admin authorizes on **Administration, People, Manage**, whatever their role ([BUG-BOUNTY.md](BUG-BOUNTY.md)).

## How projects are isolated

1. The tenancy middleware works out which projects the user may see on every request.
2. The default queryset of the main project-owned models (`SCOPES` in `tenancy/scope.py`) is filtered to those projects, for views, lookups by id, and templates. Child rows such as ports are reached through their scoped host.
3. A project the user cannot see returns 404, the same as one that does not exist.
4. Roles are checked per project before the view runs. The agent API checks them in its service layer.
5. The slug `_all` is reserved. It is the read-only combined view over every project the user can see, and writes on it return 400.

Background tasks and management commands run unscoped. When a model gains a project owner, add it to `SCOPES`.

## Two-step sign-in

Time-based codes (TOTP: 30 seconds, 6 digits) and 8 single-use recovery codes, managed under Two-step sign-in on **My account** (`/cve/account/`). A code cannot be reused, and five wrong codes lock two-step sign-in for five minutes. An organization can require it for all members (`Org.require_mfa`): those members are sent to My account until they enroll, cannot turn it off, and are refused by the REST API and MCP endpoint (with any token they own) until they do. An administrator can reset a user's two-step sign-in on the Administration page.

A token can also be a **reporter token** (`scope: inventory`), bound to one project and able to do nothing except post that project's host inventory reports; it acts with its creator's role, so it needs a write role in the project and stops working when the creator is removed or disabled ([HOST-INVENTORY.md](HOST-INVENTORY.md)).
## Agents

An agent registers the organizations, projects and hosts it is responsible for, and can claim only what its token's user can reach. Work is handed to it only in projects where that user has the user or admin role (the audit role and read-only tokens get none), and the check is repeated at every assignment. An App Admin sees and administers every agent; an organization admin sees and administers the agents of users in their organizations, and cannot reach another organization's. Everyone else sees their own agents and cannot change their limits. See [Agents and assigned work](AGENT-API.md#agents-and-assigned-work).

See also: [AGENT-API.md](AGENT-API.md) for how API tokens inherit roles, [documentation index](README.md).
