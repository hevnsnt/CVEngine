"""The review of every capability that changes something (an MCP tool that writes, a REST route that is not a GET), for an API token or an agent.

Each one answers four questions: can it widen what is scanned, raise spend, raise autonomy, or send credentials? The verdicts:

- ``refuse``: a token is refused (403) with a reason saying a person does it in the web interface.
- ``narrow``: a token may use it to lower or narrow, never to raise or widen; the rule is in the code named in the reason.
- ``allow``: it can do none of the four, or it does what the role of the token's owner is for (a write token may add targets), with the reason.

A capability that is in no list is refused by ``tests.test_agent_rules_b`` until someone decides here, so a new tool or route cannot reach tokens unreviewed.
The runtime rules themselves live where the change is made (``settings_bridge``, ``tuning``, ``agent_broker``, ``sentinel_settings``, ``services``, ...).
"""
import re


def route_key(method, pattern):
    """``METHOD path`` of a REST route with the project and any other named group made short: ``POST P/targets/{target_id}/scope``."""
    short = pattern.replace('projects/(?P<slug>[-\\w]+)/', 'P/')
    short = re.sub(r'\(\?P<(\w+)>[^)]*\)', r'{\1}', short)
    return f'{method} {short}'


# (verdict, reason, [MCP tool names and REST route keys])
REVIEW = [
    ('refuse', 'a person decides this in the web interface', [
        'apply_tuning_suggestion', 'revert_tuning_decision', 'release_tuning_pin',
        'POST tuning/decisions/{decision_id}/apply', 'POST tuning/decisions/{decision_id}/revert', 'POST tuning/release',
        'remove_exclusion', 'DELETE P/exclusions/{host}',
    ]),
    ('narrow', 'allowed to lower or narrow, refused when it raises or widens (the rule is in the handler)', [
        'set_tuning_mode', 'PUT tuning/mode',
        'change_setting',  # the settings bridge: AGENT_* tables in settings_bridge.py
        'set_sentinel_defaults', 'PUT sentinels/defaults',
        'update_agent', 'PATCH agents/{agent_id}', 'suspend_sentinel', 'revoke_sentinel',  # approve and reinstate refused, limits and settings narrow-only
        'set_target_scope', 'POST P/targets/{target_id}/scope', 'set_target_discovery_mode', 'POST P/targets/{target_id}/discovery-mode',
        'set_runzero_sync', 'PUT P/runzero',
        'set_project_settings', 'PUT P/settings',  # host review mode lower-only, inventory create_hosts cannot be switched on
        'PUT P/secrets/settings',  # validation cannot be switched on
        'POST P/internal-ranges',  # refused to a token; removing a range stays open
        'PUT P/api-keys/{service}',  # storing a key switches a paid outside service on: refused; removing one is open
        'PUT P/targets/{target_id}/auth-credential',  # a stored sign-in makes the scanners send credentials: refused; deleting one is open
        'generate_sentinel_enrollment', 'POST P/sentinels/enroll', 'POST orgs/{org}/sentinels/enroll', 'POST sentinels/enroll',  # an internal Sentinel is a person's
    ]),
    ('allow', 'adds or removes a target or what a write role may do to its own project: the role and project scope were chosen by the person who made the token', [
        'add_target', 'add_targets', 'add_targets_by_org', 'POST P/targets', 'POST P/targets/bulk', 'POST targets/bulk-org',
    ]),
    ('allow', 'only narrows what is scanned or removes data', [
        'delete_targets', 'POST P/targets/delete', 'exclude_host', 'POST P/hosts/{host}/exclude', 'archive_host', 'POST P/hosts/{host}/archive', 'delete_host',
        'POST P/hosts/{host}/delete', 'stop_scan', 'stop_all_scans', 'POST P/scans/stop', 'POST P/scans/{scan_id}/stop', 'stop_host_assessment',
        'POST P/host-assessments/{assessment_id}/stop', 'cancel_agent_task', 'POST P/agent-tasks/{task_id}/cancel', 'cancel_sentinel_task', 'POST P/sentinel-tasks/{task_id}/cancel',
        'delete_saved_search', 'DELETE P/saved-searches/{search_id}', 'remove_supplier', 'DELETE P/suppliers/{supplier_id}', 'delete_auth_credential',
        'DELETE P/auth-credentials/{credential_id}', 'DELETE P/internal-ranges/{range_id}', 'DELETE P/inventory/{inventory_id}', 'POST P/inventory/delete-unmatched',
        'DELETE P/api-keys/{service}', 'DELETE agent', 'DELETE sentinel', 'unregister_agent', 'unregister_sentinel', 'delete_agent', 'DELETE agents/{agent_id}',
        'dismiss_host_review_step', 'POST P/hosts/{host_id}/review/dismiss', 'DELETE tokens/{token_id}',
    ]),
    ('allow', 'runs work on targets and hosts already in scope, with the same effect as a person with a write role; AI calls are bounded by the daily caps a person set (429 at the limit)', [
        'discover_target', 'POST P/targets/{target_id}/discover', 'rescan_hosts', 'POST P/targets/{target_id}/rescan-hosts', 'start_scan', 'POST P/scans',
        'assess_host', 'POST P/host-assessments', 'request_host_review', 'POST P/hosts/{host_id}/review', 'start_host_review_step', 'POST P/hosts/{host_id}/review/step',
        'screenshot_host', 'POST P/hosts/{host_id}/screenshot', 'run_hygiene_checks', 'POST P/hygiene/run', 'run_runzero_sync', 'POST P/runzero/sync', 'sync_tailscale',
        'POST P/tailscale/sync', 'validate_cve_match', 'POST P/matches/{match_id}/validate', 'retriage_finding', 'POST P/findings/{kind}/{finding_id}/retriage',
        'retest_finding', 'POST P/findings/{kind}/{finding_id}/retest', 'run_saved_search', 'POST P/saved-searches/{search_id}/run', 'POST P/reports',
        'POST P/internal-ranges/{range_id}/discover', 'queue_agent_work', 'POST P/agent-tasks',
        'request_secret_validation', 'POST P/secrets/{secret_id}/validate',  # only in a project where a person switched validation on
    ]),
    ('allow', 'labels, notes, statuses, comments, assignments and heat: they change no scan, no spend, no autonomy and send nothing', [
        'set_target_private_ca', 'POST P/targets/{target_id}/private-ca', 'set_target_profile', 'POST P/targets/{target_id}/profile', 'PATCH P/targets/{target_id}/profile',
        'set_host_profile', 'POST P/hosts/{host}/profile', 'PATCH P/hosts/{host}/profile', 'restore_host', 'POST P/hosts/{host}/restore', 'pin_host', 'POST P/hosts/{host}/pin',
        'bulk_host_action', 'POST P/hosts/bulk', 'move_host', 'POST P/hosts/{host}/move', 'create_saved_search', 'POST P/saved-searches', 'update_saved_search',
        'PATCH P/saved-searches/{search_id}', 'set_secret_status', 'POST P/secrets/{secret_id}/status', 'POST P/secrets/{secret_id}/assign', 'update_remediation_status',
        'PATCH P/matches/{match_id}', 'update_finding_status', 'PATCH P/findings/{kind}/{finding_id}', 'bulk_update_finding_status', 'POST P/findings/status',
        'set_finding_assignee', 'set_finding_heat', 'POST P/findings/{kind}/{finding_id}/heat', 'POST P/findings/heat', 'add_finding_comment',
        'POST P/findings/{kind}/{finding_id}/comments', 'add_supplier', 'POST P/suppliers', 'set_supplier_finding_status', 'PATCH P/suppliers/findings/{finding_id}',
        'update_cve_detection', 'PUT cves/{cve_id}/detection', 'PUT secrets/rules',
    ]),
    ('allow', 'host-reported data, or the protocol of the agent or Sentinel that holds the token (its own registration, heartbeat and tasks); a new agent is pending until a person approves it', [
        'POST P/inventory', 'POST P/inventory/{inventory_id}/adopt', 'register_assets', 'PUT assets', 'register_agent', 'PUT agent', 'agent_heartbeat', 'POST agent/heartbeat',
        'get_next_task', 'POST agent/tasks/next', 'accept_task', 'POST agent/tasks/{task_id}/accept', 'report_task_result', 'POST agent/tasks/{task_id}/result', 'release_task',
        'POST agent/tasks/{task_id}/release', 'register_sentinel', 'PUT sentinel', 'sentinel_heartbeat', 'POST sentinel/heartbeat', 'get_next_sentinel_task',
        'POST sentinel/tasks/next', 'accept_sentinel_task', 'POST sentinel/tasks/{task_id}/accept', 'report_sentinel_task_result', 'POST sentinel/tasks/{task_id}/result',
        'POST sentinel/tasks/{task_id}/partial', 'POST sentinel/tasks/{task_id}/secret', 'release_sentinel_task', 'POST sentinel/tasks/{task_id}/release',
        'POST sentinels/bootstrap',
    ]),
    ('allow', 'the AI reviewer container\'s own token only (the routes refuse every other token and any session), or a session-only route', [
        'POST reviewer/findings/{ref}/verdict', 'POST reviewer/findings/{ref}/refusal', 'POST reviewer/ops/report', 'POST reviewer/usage', 'POST reviewer/jobs/{job_id}/result',
        'POST tokens',
    ]),
]
