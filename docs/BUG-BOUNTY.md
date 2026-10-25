# Bug bounty

The **Bug bounty** page helps a person find programs, check what is in scope, work them with the scanner's results, and send reports a program can act on. It is off for everyone except App Admins until an App Admin authorizes a user.

## Who can use it

- An **App Admin** (a Django superuser) always can.
- Any other user only after an App Admin authorizes that user: **Administration, Users, Manage, Bug bounty**. The role (admin, user, audit) does not matter; an organization admin is not authorized by being an admin and cannot authorize anyone, including herself. Audit users who are authorized can read but not change anything.
- The grant is `PUT /cve/api/admin/users/<id>/bug-bounty` with `{"enabled": true}`. It refuses everyone but an App Admin and writes `user.bugbounty_grant` or `user.bugbounty_revoke` to the audit log with the old and new value. The older route to the same flag, the Django admin, still works for an App Admin.
- Withdrawing access takes effect on the next request.

Why it is gated: the feature sends data to outside platforms, and the report text and a person's platform account are theirs.

## What it does

| Tab | What it gives you |
| --- | --- |
| Overview | Counts of drafts, open and resolved reports, bounties received, and what needs attention (scope that changed after you read a policy, reports stuck waiting) |
| Programs | Search and filter programs on HackerOne, Bugcrowd, Intigriti and YesWeHack by reward, safe harbor, new programs, recent scope changes and payout, with the scope list of each and a host checker |
| Scope changes | Every scope entry or program that appeared, left or moved between in and out of scope since the catalogue was first loaded |
| Your targets | Domain targets in the project that a program lists, with the verdict of each |
| Engagements | A program the project works: policy acknowledgement, a switch for "the policy allows automated scanning", notes, and scope import |
| Reports | Drafts from scanner findings, the checks, copy-ready fields, submission, and a timeline per report |
| Playbook | How to take part and report, from the platforms' own published guidance, with sources |
| My accounts | Your own HackerOne API credentials: your HackerOne **username** (the name in `hackerone.com/<username>`, not your email) and an API token from Settings, API Token on hackerone.com. HackerOne shows no separate identifier. **Test** says why HackerOne refused, if it did. |

## Where the program data comes from

[bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) (MIT) publishes one JSON file per platform, refreshed about every 30 minutes from the platforms' public program pages. CVEngine reads them from `raw.githubusercontent.com` with an ETag, so an unchanged file costs one small request, and nothing about your targets or findings is sent.

- Nothing is fetched until someone with access presses **Load the catalogue** once. After that the `sync_bounty_catalogue` task runs hourly. The load runs on the CVE feed worker. The page follows it ("queued", then "loading") and fills in the table when it finishes; the activity log records the outcome. A load still queued after two minutes is waiting for that worker: it is busy, or scanning was paused on a version before the pause stopped applying to bookkeeping.
- `CVENGINE_BOUNTY_CATALOGUE=0` turns the fetch off completely, including the button.
- A file that does not parse, is far smaller than the stored one (under half the programs), is empty, or is over 120 MB is refused and the stored catalogue stays; the Overview tab shows the error.
- The data holds public programs only. Private and invitation-only programs are not in it.

## How scope is matched

A host is checked against one program's entries. The result is one of:

- **in scope**: an entry names the host exactly, or a wildcard covers it (`*.example.com` covers `a.example.com` and `a.b.example.com`), or an IP lies in a listed address or range.
- **out of scope**: an out-of-scope entry names the host or any parent of it. This beats every in-scope entry.
- **unclear**: the apex of a wildcard (`*.example.com` does not name `example.com`), a host named only with a path, a pattern such as `api-*.example.com`, or a program whose scope is described in prose. A person must read the policy. It is never treated as in scope.
- **not listed**: nothing names it. A listed domain does not cover its subdomains unless a wildcard says so.

Address ranges written as `a.b.c.d - e.f.g.h` are converted to the CIDR blocks that cover them exactly. A block wider than /8 (IPv4) or /24 (IPv6) is treated as unreadable, not as scope.

## Working a program

1. **Work this program** creates an engagement in the current project.
2. **I read the policy** records who read it and when, and the program's scope at that time. If the scope changes later, the engagement shows it and reports to that program warn.
3. **Import scope as targets** previews first. Wildcards become their base domain, URLs their host. A block of more than 64 addresses, mobile apps, source code and prose entries are listed as not imported with the reason. Importing needs the acknowledgement. Discovery starts only if you also ticked that the policy allows automated scanning; otherwise targets are only added. Targets the organization excluded stay excluded, and addresses the scanner may not touch are refused as everywhere else.

## Reports

A report starts from a scanner finding or blank. A draft from a finding carries the request and, never invented, leaves the impact empty. Credentials and tokens in requests and responses are masked (a short prefix stays). Checks run on every save:

- **Blockers** stop marking ready and submitting: a short title, no steps, a TODO in the steps, no impact, no asset, an out-of-scope or unlisted asset, a removed program, an unacknowledged policy, an unticked checklist item, something that looks like a live key still in the text or an attachment.
- **Warnings**: a generic title, unnumbered steps, a thin impact, no evidence, a severity that disagrees with the CVSS score, scope that is unclear or changed, no confirmation that scanning is allowed, a category Bugcrowd's taxonomy rates priority 5, another report on the same asset with the same title.

The text of a submitted report is final here (Bugcrowd does not allow editing after submission either). Move a report through the program's states by hand as it answers and record any bounty.

### Submitting

- **HackerOne**: **Submit to HackerOne** posts to `https://api.hackerone.com/v1/hackers/reports` with the **caller's own** HackerOne API credentials from My accounts. There is no shared key: a report is attributed to the account that sends it. The caller types the program handle back to confirm, the row is locked so two clicks cannot send twice, and a timeout is recorded as uncertain: the next attempt needs the caller to confirm they looked on HackerOne first. Credentials are encrypted at rest, never returned by the API, and used only at that moment.
- **Bugcrowd, Intigriti, YesWeHack**: there is no submit button. **Fields for the platform** gives each field named as that platform names it for pasting; then **I sent it on the platform** locks the report and records the address.
- States are not read back from a platform; they are moved by hand.

The older HackerOne auto-report setting (a global key in Settings) is unchanged and unrelated: it still exists for scans, and none of this page uses it.

## Free text and the input guard

A report is about attack strings. On `/cve/api/bounty/reports` and `/cve/api/bounty/engagements` only, the free-text fields (title, summary, steps, impact, remediation, references, evidence, notes, location URL, CWE, CVSS vector) are not scanned by the input guard, because a report on a path traversal finding would otherwise strike its author and, at the threshold, disable the account. They are stored as text, shown with `textContent`, exported as Markdown and sent as JSON, and never reach a shell, a query or a template. Every other field on those endpoints (host, project, value, ids) and every other endpoint keep the full rules.

## Data model

`BountyProgram`, `BountyAsset`, `BountyScopeChange` and `BountySource` are the public catalogue and belong to no project. `BountyEngagement`, `BountyEngagementTarget`, `BountyReport` and `BountyReportEvent` belong to one project and are listed in `tenancy.scope.SCOPES`. `BountyCredential` belongs to one user. The Bugcrowd taxonomy is bundled as `web/cveFeed/data/vrt.json` (Apache-2.0, release shown on the report form).

## Rolling back

Withdraw access per user on the Users tab, or stop the feature for everyone with `CVENGINE_BOUNTY_CATALOGUE=0` and by authorizing nobody. Migrations `0062` (tables) and `0063` (the hourly schedule) can be reversed with `manage.py migrate cveFeed 0061`, which drops the bug bounty tables and the schedule.
