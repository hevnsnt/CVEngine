# Agent API: REST and MCP

Two interfaces share one service layer, so both get the same project isolation, role checks, and read-only token rules.

- **REST** at `/api/v1/`, JSON, with an OpenAPI spec at `/api/v1/openapi.json`.
- **MCP** at `/mcp/`, Streamable HTTP (JSON-RPC 2.0 over POST), protocol versions 2025-06-18, 2025-03-26, and 2024-11-05.

## Connect

Create a token on the **API tokens and MCP** page (`/cve/agents/`) and send `Authorization: Bearer <token>`. The secret (`cve_...`) is shown once and only its SHA-256 is stored. A token acts as its user, with the same memberships and roles. **Read only** tokens can call GET endpoints and read-only tools. Revoke a token on the same page. Bearer requests skip CSRF.

When an organization requires two-step sign-in and a member has not enrolled, that member's session and tokens get `403` until they turn it on under **My account**. Tokens are not revoked and work again afterward. MCP requests are limited to 256 KiB, 20 batched messages, and 4 MiB of response.

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
| tokens | `GET/POST tokens`, `DELETE tokens/{id}` (session only; a token cannot create tokens), `GET assets` | none |
| scan detail | `GET .../scans/{id}/subdomains`, `endpoints`, `vulnerabilities`, `activity` | `list_scan_subdomains`, `list_scan_endpoints`, `list_scan_vulnerabilities`, `get_scan_activity` |
| inventory | `GET projects/{slug}/hosts` | `list_hosts` |
| search | `GET projects/{slug}/search?q=...` | `search_hosts` |
| routes | `GET projects/{slug}/routes` | `list_routes` |
| changes | `GET projects/{slug}/changes?since=7d` | `list_changes` |
| activity | `GET projects/{slug}/activity` | `list_activity` |
| all findings | `GET projects/{slug}/findings?type=&heat=&severity=&status=&host=` | `list_findings` |
| scanner findings | `GET projects/{slug}/vulnerabilities` | `list_vulnerabilities` |
| finding detail | `GET projects/{slug}/findings/{match,vulnerability,route,hygiene}/{id}` | `get_finding` |
| triage | `GET projects/{slug}/triage`, `POST .../findings/{kind}/{id}/retriage` | `list_triage`, `retriage_finding` |
| hygiene | `GET projects/{slug}/hygiene`, `certificates`, `POST .../hygiene/run` | `list_hygiene_findings`, `list_certificates`, `run_hygiene_checks` |
| CVEs | `GET cves?tier=fire`, `GET cves/{id}` | `list_cves`, `get_cve` |
| matches | `GET projects/{slug}/matches`, `PATCH .../matches/{id}` | `list_cve_matches`, `update_remediation_status` |
| remediation status | `PATCH projects/{slug}/findings/{match,vulnerability,hygiene}/{id}`, `POST .../findings/status` (bulk) | `update_finding_status`, `bulk_update_finding_status` |
| assess a host | `POST projects/{slug}/host-assessments` (`host_id`), `GET .../host-assessments?host_id=`, `GET .../host-assessments/{id}`, `POST .../host-assessments/{id}/stop` | `assess_host`, `get_host_assessment`, `stop_host_assessment` |
| archive a host | `POST projects/{slug}/hosts/{host}/archive` (`reason`), `.../restore`, `.../pin` (`pinned`) | `archive_host`, `restore_host`, `pin_host` |
| validate a match | `POST projects/{slug}/matches/{id}/validate`, `GET .../matches/{id}/validate/{request_id}` | `validate_cve_match`, `get_validation_request` |
| remediation | `PUT assets`, `GET projects/{slug}/work` | `register_assets`, `get_remediation_work` |
| host info | `POST` or `PATCH projects/{slug}/hosts/{host}/profile` (`owner`, `purpose`, `criticality`) | `set_host_profile` |
| delete host | `POST projects/{slug}/hosts/{host}/delete` | `delete_host` |
| exclude host | `POST projects/{slug}/hosts/{host}/exclude`, `GET projects/{slug}/exclusions`, `DELETE projects/{slug}/exclusions/{host}` | `exclude_host`, `list_exclusions`, `remove_exclusion` |
| API keys | `GET/PUT/DELETE projects/{slug}/api-keys[/{service}]` | none |

Lists take `page` and `page_size` (up to 200), except `work` and `cves?tier=`, which return one page of at most 200 rows (`count` can be higher), and `findings`, which pages through its first 2,000 and reports `total`, `truncated`, and `counts`. Writes need any role except audit in the project and a token that is not read only. A project you cannot see returns 404, the same as one that does not exist.

## Targets and scans

`targets/bulk-org` takes `{"text": "##Organization\n#Project\nexample.com\n10.0.0.0/28\n#Project2\n...", "current_project": "slug"}`. A line `#Name` (no space after the hash) opens a project, and the lines under it are domains, IPs, CIDRs, ranges, or URLs. `# a note` is a comment. A `##Organization` line is optional. Without one, or with a name the caller cannot see, the caller's current organization is used, and `organization_note` says so when a name did not resolve. Missing projects are created, which needs the admin role in the organization. Each project is checked on its own, so a section the caller cannot write to is reported in `projects[].error` and the rest still go in.

Bulk adds start discovery by default. A single add starts it only when `discover` is true. `mode` is `standard` (default), `deep`, or `passive`. Targets queue first in, first out, and a target that already has a queued or running scan keeps it. A queued scan has `status` -1 and a `queue_position` (0 is next). `GET .../scans` lists running scans first, then queued, then the rest newest first. Stopping a scan marks it aborted and ends its scanner processes so the next queued scan can proceed.

Each target carries `scope_mode` and `host_scoped`. See [Shared provider domains](PIPELINE.md#shared-provider-domains).

## All projects

The reserved slug `_all` means every project you can see. The list endpoints and tools accept it in place of a project slug and return one combined, read-only list: `targets`, `scans`, `hosts`, `search`, `findings`, `vulnerabilities`, `matches`, `changes`, `activity`, `hygiene`, `certificates`, and `routes`. Every row carries `project` (use this slug for anything you do next) and `project_name`. Only your own projects contribute rows, and `count` is the total. Everything else needs a real project: a write or a per-item call with `_all` is a `400`.

## Host management

`profile` records who owns a host, what it is for, and how much it matters (`criticality`: `unknown`, `low`, `medium`, `high`, `critical`), per project. Only the fields you send change.

`delete` removes one host's data from this project only: its findings, CVE matches, routes, changes, triage, certificates, and asset information. A later scan can find the host again.

`exclude` is organization wide: it deletes the host's data from every project of the organization you can write to, and no stage touches it again in any of them. It needs an organization-level role, and organization admins lift it with `DELETE exclusions/{host}`. Names match whole and case-insensitively: excluding `provider.example` leaves `www.provider.example` alone, and wildcards are a `400`. Removals are audit logged.

## Hosts and search

Hosts carry `score` (0 to 100) and `score_detail`, and come highest score first (`sort=name` for name order). A hostname is one host, so the list returns one row per name that covers all its current rows. `labels` holds short informational detections such as a WAF or federated sign-in. See [Host score](PIPELINE.md#host-score).

`search?q=...` returns hosts with `matched` showing what each query hit. Terms are separated by spaces and ANDed. A bad value for `sev:`, `auth:`, `sensitive:`, or `zombie:` is a 400. The full syntax, with examples, is in [SEARCH.md](SEARCH.md).

| Term | Matches |
| --- | --- |
| `php` | a bare word in hostname, IP, technology, headers, cookie names, port product, service, version, CPE, banner and script output, OS, finding name, CVE id, or page title |
| `tech:nginx` | anything the host runs: technology, `Server` and `X-Powered-By` headers, product, version, CPE, banner, script output, cookie names |
| `product:nginx`, `service:mysql`, `os:linux` | port product, service name, OS guess |
| `banner:"anonymous"` | service banner, script output, or extra info on an open port |
| `port:3306` | open port number (a number only; `port:ssh` is a 400) |
| `cve:CVE-2024-1234` | CVE match |
| `ip:10.0.0.5`, `ip:10.0.0.0/24`, `ip:10.0.` | an IP, any IP in a CIDR range, or an address prefix |
| `host:www` | hostname |
| `vuln:rce`, `sev:high` | finding name, severity |
| `auth:<state>` | hosts with a web route in that state (any state listed under Routes) |
| `sensitive:any`, `sensitive:credentials`, `sensitive:pii`, `sensitive:internal` | hosts with a route serving that kind of sensitive data |
| `zombie:yes`, `zombie:no` | hosts whose name is gone but whose last address answers |
| `-term`, `"apache tomcat"` | negate a term, or match a phrase |

`?heat=fire|smoke|ice|clean|unscanned` narrows the page to that heat, the same value each host's own `heat` field carries. The response's `facets.heat` always counts every one of those five values over the whole match of `q`, ignoring `heat` itself, so a UI's heat chips keep their real totals while one is selected. Both the filter and the facet count stop after 5,000 matched hosts (`facets.truncated: true`); a search that wide needs narrowing with `q` regardless.

Ports are stored per IP, so `product:nginx` finds only hosts whose own IP runs it.

## Routes, changes, and activity

- **`routes`** lists web routes with `auth_state` (`open`, `login`, `session_required`, `sso`, `redirect`, `not_found`, `error`), `redirect_to`, and `evidence` (markers, never page content). `sensitive` holds `{type: {count, sample}}` with the sample already masked, and `sensitive_score` runs 0 to 25. Raw values are never stored or returned. `retired_at` and `zombie_since` mark route lifecycle, and `sensitive=1` or `zombie=1` filter.
- **`changes`** lists inventory changes newest first. `since` is an ISO 8601 datetime or `24h`, `7d`, `4w`. `kind` is one of the kinds in [Changes](PIPELINE.md#changes), and `host` matches part of a hostname. Each row has `before` and `after`.
- **`activity`** is the AI activity log for the project plus system-wide entries. `kind` is `feed`, `inventory`, `target`, `confirm`, `write_check`, `run_check`, `validate`, `discovery`, `scan`, `hygiene`, `changes`, or `remediation`.

## Triage and remediation

List endpoints (`vulnerabilities`, `matches`, `routes`, `hygiene`, `work`) carry a `triage` object with `classification` (`confirmed`, `likely`, `needs_validation`, `likely_false_positive`, `not_applicable`), `status`, `validation_status`, `overridden`, `first_seen`, and `last_seen`. `vulnerabilities` and `matches` accept `?classification=`, and `vulnerabilities` accepts `?severity=actionable` to skip info rows. `ai_verdict` on a match is the older view: `confirmed` and `likely` are `affected`, `needs_validation` is `uncertain`, and the false-positive classes are `not_affected`. See [Triage and validation](PIPELINE.md#triage-and-validation).

`findings/{kind}/{id}` returns one finding in full: why it matters, how it was found (with request and response excerpts capped at 4 KB, returned only here), its history, the AI's classification and whether a rule overrode it, remediation, and every validation check with the command a person can repeat. A CVE match also includes the feed description, affected products and ranges, HTTPS advisory links, feed sources, and nullable exploitation signals. Those signals describe the CVE; they do not prove a particular host is vulnerable.

**Validate a match.** `POST projects/{slug}/matches/{id}/validate` queues the same workflow as **Validate now**: an AI plan, the checks it chose from those the scope and template policy allow, and an AI review of the evidence. Without a provider, the policy-approved checks run on their own. `GET .../validate/{request_id}` returns `queued`, `running`, `completed`, or `failed`, with the plan, the checks that ran, and the resulting classification. A match with an active request, or one finished in the last 5 minutes, returns that request. Each project allows 10 in progress and each user 20 requests an hour (429). The worker rechecks the requester's current access before it runs anything, and `retriage` uses the same queue.

**Diagnostics.** When an AI call fails, the finding keeps a retriable `error` status and an `ai.diagnostic` object (also shown as **Copy diagnostic**). It names the stage and a category such as `provider_auth` (check the key), `output_truncated` (check the model's output limit), or `schema_invalid` (the reply did not fit the triage format). It never contains credentials, prompts, model output, or target content, so it is safe to share.

`validation_status=observed` means a check read a banner or version without running a CVE-specific detector: it records what was seen, not a verdict.

**Remediation loop**

1. `register_assets` with the hosts, IPs, or CIDRs the agent is responsible for.
2. `get_remediation_work` returns open CVE-on-host items for those assets, fire first, with the host's IPs and the CVE's fixed versions. Fixed, accepted-risk, and closed matches are left out, and `?include_fp=0` also drops likely false positives.
3. `update_remediation_status` sets `open`, `in_progress`, `fixed`, or `accepted_risk` with a note.

Matches also carry `distro_status` (`patched`, `vulnerable`, `unknown`, `no_data`), `distro_label`, `evidence`, and the template test result (`vulnerable`, `no_match`, `error`).

**Remediation status on scanner and hygiene findings.** CVE matches, scanner findings, and hygiene findings each carry the same `remediation_status` (`open`, `in_progress`, `fixed`, `accepted_risk`), `remediation_note`, and `remediation_updated` fields, driven entirely by people or agents, never by a scan. They are independent of the finding's own auto-managed liveness signal (a CVE match's `ai_verdict`, a scanner finding's `open`, a hygiene finding's `status`): a scan re-detecting a finding never undoes a `fixed` or `accepted_risk` mark, and marking one of those statuses drops the finding out of `findings?status=actionable` (and the host's heat) immediately, whether or not the underlying check still finds it.

`PATCH projects/{slug}/findings/{kind}/{id}` (`update_finding_status`, `kind` one of `match`, `vulnerability`, `hygiene`) sets one finding's status and note; `kind=match` is identical to `PATCH .../matches/{id}`, kept as its own endpoint for the simpler single-kind case. `POST projects/{slug}/findings/status` (`bulk_update_finding_status`) sets the same status and note on up to 200 findings in one call, `{items: [{kind, id}, ...], status, note}`, and answers `{updated, failed: [{kind, id, error}]}` so one bad id never blocks the rest. A web route has no remediation workflow (its `auth_state` already says what it needs), so `kind=route` is a `400`. Every write here is logged to `activity` as `kind=remediation`.

`note` on every one of these routes, `update_remediation_status` included, is a true partial-update field: leave it out of the body and the stored note is untouched; send `""` (or any string) and it replaces it. Earlier, an omitted `note` was treated the same as an explicit `""` and silently cleared it.

## Limits

Domain names are unique across the instance. A range or CIDR target is capped at 10,000 addresses per call, and a bulk request at 10,000 lines or expanded rows (`CVENGINE_MAX_TARGETS_PER_ADD`). Loopback and link-local addresses cannot be added, and private ranges need `CVENGINE_ALLOW_PRIVATE_TARGETS=1`. A bulk request takes up to 50 projects, a delete up to 5,000 ids, a rescan up to 200 hosts, and `register_assets` up to 500 assets.

The API does not expose instance settings, the AI key, bug bounty actions, or user management. It can set a project's own OSINT service keys (write-only) and read which services are configured.

See also: [TENANCY.md](TENANCY.md) for roles, [PIPELINE.md](PIPELINE.md) for what a scan does, [documentation index](README.md).
