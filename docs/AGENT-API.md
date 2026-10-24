# Agent API: REST and MCP

Two interfaces share one service layer, so both get the same project isolation, role checks, and read-only token rules.

- **REST** at `/api/v1/`, JSON, with an OpenAPI spec at `/api/v1/openapi.json`.
- **MCP** at `/mcp/`, Streamable HTTP (JSON-RPC 2.0 over POST), protocol versions 2025-06-18, 2025-03-26, and 2024-11-05.

## Connect

Create a token on the **API tokens and MCP** page (`/cve/agents/`) and send `Authorization: Bearer <token>`. The secret (`cve_...`) is shown once and only its SHA-256 is stored. A token acts as its user, with the same memberships and roles. **Read only** tokens can call GET endpoints and read-only tools. Revoke a token on the same page. Bearer requests skip CSRF.

When an organization requires two-step sign-in and a member has not enrolled, that member's session and tokens get `403` until they enroll at `/mfa/setup/`. Tokens are not revoked and work again afterward.

Connect Claude Code:

```bash
claude mcp add --transport http cvengine https://<your-host>/mcp/ --header "Authorization: Bearer <token>"
```

## Endpoints and tools

Paths are relative to `/api/v1/`. `{slug}` is a project slug.

| Area | REST | MCP tool |
| --- | --- | --- |
| identity | `GET me`, `projects`, `engines` | `whoami`, `list_projects`, `list_engines` |
| targets | `GET/POST projects/{slug}/targets`, `GET .../targets/{id}` | `list_targets`, `add_target` |
| bulk add | `POST projects/{slug}/targets/bulk`, `POST targets/bulk-org` | `add_targets`, `add_targets_by_org` |
| delete | `POST projects/{slug}/targets/delete` (`ids`, or `all_matching` and `q`) | `delete_targets` |
| scope | `POST projects/{slug}/targets/{id}/scope` (`auto`, `host`, `parent`) | `set_target_scope` |
| scans | `GET/POST projects/{slug}/scans`, `GET .../scans/{id}` | `list_scans`, `get_scan`, `start_scan` |
| discover | `POST projects/{slug}/targets/{id}/discover` (`mode`) | `discover_target` |
| rescan | `POST projects/{slug}/targets/{id}/rescan-hosts` (`hosts`) | `rescan_hosts` |
| stop | `POST projects/{slug}/scans/{id}/stop`, `POST projects/{slug}/scans/stop` | `stop_scan`, `stop_all_scans` |
| scan detail | `GET .../scans/{id}/subdomains`, `endpoints`, `vulnerabilities`, `activity` | `list_scan_subdomains`, `list_scan_endpoints`, `list_scan_vulnerabilities`, `get_scan_activity` |
| inventory | `GET projects/{slug}/hosts` | `list_hosts` |
| search | `GET projects/{slug}/search?q=...` | `search_hosts` |
| routes | `GET projects/{slug}/routes` | `list_routes` |
| changes | `GET projects/{slug}/changes?since=7d` | `list_changes` |
| activity | `GET projects/{slug}/activity` | `list_activity` |
| findings | `GET projects/{slug}/vulnerabilities` | `list_vulnerabilities` |
| finding detail | `GET projects/{slug}/findings/{match,vulnerability,route,hygiene}/{id}` | `get_finding` |
| triage | `GET projects/{slug}/triage`, `POST .../findings/{kind}/{id}/retriage` | `list_triage`, `retriage_finding` |
| hygiene | `GET projects/{slug}/hygiene`, `certificates`, `POST .../hygiene/run` | `list_hygiene_findings`, `list_certificates`, `run_hygiene_checks` |
| CVEs | `GET cves?tier=fire`, `GET cves/{id}` | `list_cves`, `get_cve` |
| matches | `GET projects/{slug}/matches`, `PATCH .../matches/{id}` | `list_cve_matches`, `update_remediation_status` |
| assess a host | `POST projects/{slug}/host-assessments` (`host_id`), `GET .../host-assessments?host_id=`, `GET .../host-assessments/{id}`, `POST .../host-assessments/{id}/stop` | `assess_host`, `get_host_assessment`, `stop_host_assessment` |
| archive a host | `POST projects/{slug}/hosts/{host}/archive` (`reason`), `.../restore`, `.../pin` (`pinned`) | `archive_host`, `restore_host`, `pin_host` |
| validate a match | `POST projects/{slug}/matches/{id}/validate`, `GET .../matches/{id}/validate/{request_id}` | `validate_cve_match`, `get_validation_request` |
| remediation | `PUT assets`, `GET projects/{slug}/work` | `register_assets`, `get_remediation_work` |
| host info | `POST` or `PATCH projects/{slug}/hosts/{host}/profile` (`owner`, `purpose`, `criticality`) | `set_host_profile` |
| delete host | `POST projects/{slug}/hosts/{host}/delete` | `delete_host` |
| exclude host | `POST projects/{slug}/hosts/{host}/exclude`, `GET projects/{slug}/exclusions`, `DELETE projects/{slug}/exclusions/{host}` | `exclude_host`, `list_exclusions`, `remove_exclusion` |
| API keys | `GET/PUT/DELETE projects/{slug}/api-keys[/{service}]` | none |

Lists take `page` and `page_size` (up to 200). Writes need any role except audit in the project and a token that is not read only. A project you cannot see returns 404, the same as one that does not exist.

## Targets and scans

`targets/bulk-org` takes `{"text": "##Organization\n#Project\nexample.com\n10.0.0.0/28\n#Project2\n...", "current_project": "slug"}`. A line `#Name` (no space after the hash) opens a project, and the lines under it are domains, IPs, CIDRs, ranges, or URLs. `# a note` is a comment. A `##Organization` line is optional. Without one, or with a name the caller cannot see, the caller's current organization is used, and `organization_note` says so when a name did not resolve. Missing projects are created, which needs the admin role in the organization. Each project is checked on its own, so a section the caller cannot write to is reported in `projects[].error` and the rest still go in.

Bulk adds start discovery by default. A single add starts it only when `discover` is true. `mode` is `standard` (default), `deep`, or `passive`. Targets queue first in, first out, and a target that already has a queued or running scan keeps it. A queued scan has `status` -1 and a `queue_position` (0 is next). `GET .../scans` lists running scans first, then queued, then the rest newest first. Stopping a scan marks it aborted and ends its scanner processes so the next queued scan can proceed.

Each target carries `scope_mode` and `host_scoped`. See [Shared provider domains](PIPELINE.md#shared-provider-domains).

## All projects

The reserved slug `_all` means every project you can see. The list endpoints and tools accept it in place of a project slug and return one combined, read-only list: `targets`, `scans`, `hosts`, `search`, `vulnerabilities`, `matches`, `changes`, `activity`, `hygiene`, `certificates`, and `routes`. Every row carries `project` (use this slug for anything you do next) and `project_name`. Only your own projects contribute rows, and `count` is the total. A write or a per-item call with `_all` is a `400` that asks you to pick a project.

## Host management

`profile` records who owns a host, what it is for, and how much it matters (`criticality`: `unknown`, `low`, `medium`, `high`, `critical`), per project. Only the fields you send change.

`delete` removes one host's data from this project only: its findings, CVE matches, routes, changes, triage, certificates, and asset information. A later scan can find the host again.

`exclude` is organization wide. It records the host as excluded, deletes its data from every project of the organization you can write to, and from then on no scan stage touches it in any project of the organization. It needs an organization-level role, and `DELETE exclusions/{host}` lifts it (organization admins only). Both match the whole host name, case-insensitively, never a suffix: excluding `provider.example` leaves `www.provider.example` alone, and wildcards are a `400`. Each removal needs write access and is written to the audit log.

## Hosts and search

Hosts carry `score` (0 to 100) and `score_detail`, and come highest score first (`sort=name` for name order). A hostname is one host, so the list returns one row per name that covers all its current rows. `labels` holds short informational detections such as a WAF or federated sign-in. See [Host score](PIPELINE.md#host-score).

`search?q=...` returns hosts with `matched` showing what each query hit. Terms are separated by spaces and ANDed.

| Term | Matches |
| --- | --- |
| `php` | a bare word in hostname, IP, technology, port product, service, version, CPE, OS, finding name, CVE id, or page title |
| `tech:nginx`, `product:nginx`, `service:mysql`, `os:linux` | technology, port product, service, OS |
| `port:3306` | open port number |
| `cve:CVE-2024-1234` | CVE match |
| `ip:10.0.0.5`, `ip:10.0.0.0/24` | an IP, or any IP in a CIDR range |
| `host:www` | hostname |
| `vuln:rce`, `sev:high` | finding name, severity |
| `auth:open`, `auth:login`, `auth:session_required`, `auth:sso` | hosts with a web route in that state |
| `sensitive:any`, `sensitive:credentials`, `sensitive:pii`, `sensitive:internal` | hosts with a route serving that kind of sensitive data |
| `zombie:yes`, `zombie:no` | hosts whose name is gone but whose last address answers |
| `-term`, `"apache tomcat"` | negate a term, or match a phrase |

Ports are stored per IP, so `product:nginx` finds only hosts whose own IP runs it.

## Routes, changes, and activity

- **`routes`** lists web routes with `auth_state` (`open`, `login`, `session_required`, `sso`, `redirect`, `not_found`, `error`), `redirect_to`, and `evidence` (markers, never page content). `sensitive` holds `{type: {count, sample}}` with the sample already masked, and `sensitive_score` runs 0 to 25. Raw values are never stored or returned. `retired_at` and `zombie_since` mark route lifecycle, and `sensitive=1` or `zombie=1` filter.
- **`changes`** lists inventory changes newest first. `since` is an ISO 8601 datetime or `24h`, `7d`, `4w`. `kind` is one of the kinds in [Changes](PIPELINE.md#changes), and `host` matches part of a hostname. Each row has `before` and `after`.
- **`activity`** is the AI activity log for the project plus system-wide entries. `kind` is `feed`, `inventory`, `target`, `confirm`, `write_check`, `run_check`, `validate`, `discovery`, `scan`, `hygiene`, or `changes`.

## Triage and remediation

List endpoints (`vulnerabilities`, `matches`, `routes`, `hygiene`, `work`) carry a `triage` object with `classification` (`confirmed`, `likely`, `needs_validation`, `likely_false_positive`, `not_applicable`), `status`, `validation_status`, `overridden`, `first_seen`, and `last_seen`. `vulnerabilities` and `matches` accept `?classification=`, and `vulnerabilities` accepts `?severity=actionable` to skip info rows. `ai_verdict` on a match is the older view: `confirmed` and `likely` are `affected`, `needs_validation` is `uncertain`, and the false-positive classes are `not_affected`. See [Triage and validation](PIPELINE.md#triage-and-validation).

`findings/{kind}/{id}` returns one finding in full: why it matters, how it was found (with request and response excerpts capped at 4 KB, returned only here), its history, the AI's classification and whether a rule overrode it, remediation, and every validation check with the command a person can repeat. A CVE match also includes the feed description, affected products and ranges, HTTPS advisory links, feed sources, and nullable exploitation signals. Those signals describe the CVE; they do not prove a particular host is vulnerable.

**Validate a match.** `POST projects/{slug}/matches/{id}/validate` queues the same workflow as **Validate now**: an AI plan, the checks it chose from those the scope and template policy allow, and an AI review of the evidence. Without a provider, the policy-approved checks run on their own. An AI-drafted template runs on the host only after a reviewed positive fixture proves it. `GET .../validate/{request_id}` returns `queued`, `running`, `completed`, or `failed`, with the plan, its reason, the checks that ran, and the resulting classification. Requests are deduplicated and bounded per user, project, and day. `retriage` routes a CVE match through the same queue, and queues other findings for one check on the validation worker.

**Diagnostics.** When an AI call fails, the finding keeps a retriable `error` status and an `ai.diagnostic` object (also shown as **Copy diagnostic**). It names the stage and a category such as `provider_auth` (check the key), `output_truncated` (check the model's output limit), or `schema_invalid` (the reply did not fit the triage format). It never contains credentials, prompts, model output, or target content, so it is safe to share.

`validation_status=observed` means a check read a banner or version without running a CVE-specific detector. It records what was seen, not a verdict.

**Remediation loop**

1. `register_assets` with the hosts, IPs, or CIDRs the agent is responsible for.
2. `get_remediation_work` returns open CVE-on-host items for those assets, fire first, with the host's IPs and the CVE's fixed versions. Fixed, accepted-risk, and closed matches are left out, and `?include_fp=0` also drops likely false positives.
3. `update_remediation_status` sets `in_progress`, `fixed`, or `accepted_risk` with a note.

Matches also carry `distro_status` (`patched`, `vulnerable`, `unknown`, `no_data`), `distro_label`, `evidence`, and the template test result (`vulnerable`, `no_match`, `error`).

## Limits

Domain names are unique across the instance. A range or CIDR target is capped at 10,000 addresses per call (`CVENGINE_MAX_TARGETS_PER_ADD`). Loopback and link-local addresses cannot be added, and private ranges need `CVENGINE_ALLOW_PRIVATE_TARGETS=1`. A bulk request takes up to 50 projects, a delete up to 5,000 ids, a rescan up to 200 hosts, and `register_assets` up to 500 assets.

The API does not expose instance settings, the AI key, bug bounty features, or user management. It can set a project's own OSINT service keys (write-only) and read which services are configured.

See also: [TENANCY.md](TENANCY.md) for roles, [PIPELINE.md](PIPELINE.md) for what a scan does, [documentation index](README.md).


### Validation request authority and accounting

Manual validation persists its requesting user and, for bearer requests, the token ID. Workers recheck active user status, current project write access, required MFA/password setup, and token expiry/revocation before checks and fresh AI review. Deleting a requester or token does not turn the request into automatic work. Automatic background validation retains its separate scheduling authority.

Migration `0060_validation_request_authority` expires old queued/running requests whose original bearer identity was not recorded. Submit a new manual request after the upgrade; background scheduling can create fresh automatic jobs. Migration `0059_validationbudget` adds durable daily check reservations. Refreshing a finding or deleting its freshness marker does not reset daily usage, and failed attempts still count. The initial upgrade-day count seeds from remaining historical freshness records, so earlier erased usage cannot be reconstructed.

CVE detail keeps the original advisory description separately from the feed summary and retains unknown exploit signals as unknown. Links include CVE Program and NVD records, plus the CISA catalog for known-exploited entries.
