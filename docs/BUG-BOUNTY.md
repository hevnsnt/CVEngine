# Bug bounty

The **Bug bounty** page helps you find programs, check what is in scope, work them with the scanner's results, and send reports a program can act on. It is off for everyone except App Admins until an App Admin authorizes a user.

## Who can use it

- An **App Admin** (a Django superuser) always can.
- Anyone else only after an App Admin authorizes them: **Administration, People, Manage, Authorize bug bounty**. The role does not matter, and an organization admin cannot authorize anyone. An authorized audit user can read but not change anything.
- The grant is `PUT /cve/api/admin/users/<id>/bug-bounty` with `{"enabled": true}`, App Admins only (409 for an App Admin, who always has access). Grants and withdrawals are audit logged, as are catalogue refreshes, engagements, policy acknowledgements, imports, submissions, and credential changes. Withdrawing access takes effect on the next request.

It is gated because the feature sends data to outside platforms, and a report and a platform account belong to a person.

## What it does

| Tab | What it gives you |
| --- | --- |
| Overview | Live status of the targets your engagements imported: hosts checked against each program's scope (out-of-scope hosts are listed so nobody tests them), scans, potential findings (open scanner findings of low severity or worse that no report covers yet, each with a Draft report button), CVE matches to validate, drafts, reports, bounties, and what needs attention. Refreshes every 8 seconds. |
| Programs | Search and filter HackerOne, Bugcrowd, Intigriti, and YesWeHack programs by reward, safe harbor, new programs, recent scope changes, and payout, with each program's scope and a host checker |
| Scope changes | Scope entries and programs that appeared, left, or moved in or out of scope, over the last day, 7, 30, or 90 days (the API goes to 180), with filters for change kind, platform, "Pays a bounty", and "Only programs I work" |
| Your targets | Domain targets in the project that a program lists, with the verdict of each |
| Engagements | A program the project works (its own project in the Bug Bounty org): policy acknowledgement, a switch for "the policy allows automated scanning", notes, and scope import |
| Reports | Drafts from scanner findings, the checks, copy-ready fields, submission, and a timeline per report |
| Playbook | How to take part and report, from the platforms' own published guidance, with sources |
| My accounts | Your own HackerOne API credentials: your HackerOne **username** (the name in `hackerone.com/<username>`, not your email) and an API token from Settings, API Token on hackerone.com. **Test** says why HackerOne refused, if it did. |

## Where the program data comes from

[bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) (MIT) publishes one JSON file per platform from the platforms' public program pages. cvENGINE reads them from `raw.githubusercontent.com` with an ETag, and nothing about your targets or findings is sent. The Bugcrowd taxonomy is bundled from [bugcrowd/vulnerability-rating-taxonomy](https://github.com/bugcrowd/vulnerability-rating-taxonomy).

- Nothing is fetched until someone with access presses **Load the catalogue** once, which runs on the CVE feed worker. After that the `sync_bounty_catalogue` task runs hourly. The refresh button has a 5 minute cooldown.
- `CVENGINE_BOUNTY_CATALOGUE=0` turns the fetch off completely.
- A file that does not parse, is empty, is over 120 MB, or holds under half the stored programs is refused, and the stored catalogue stays.
- The data holds public programs only.

## How scope is matched

A host is checked against one program's entries:

- **in scope**: an entry names the host, a wildcard covers it (`*.example.com` covers `a.b.example.com`), or an IP lies in a listed address or range.
- **out of scope**: an out-of-scope entry names the host or any parent of it. This beats every in-scope entry.
- **unclear**: the apex of a wildcard, a host named only with a path, a pattern such as `api-*.example.com`, or scope described in prose. A person must read the policy. It is never treated as in scope.
- **not listed**: nothing names it.

Address ranges are converted to the CIDR blocks that cover them exactly. A block wider than /8 (IPv4) or /24 (IPv6) is treated as unreadable.

## Working a program

1. **Work this program** creates the engagement in that program's own project, inside a **Bug Bounty** organization (created the first time one is worked): one project per engagement, named after the program (`bb-<platform>-<handle>`), never mixed into a client's project. The page then moves to that project. A creator who is not an App Admin becomes its admin (an App Admin sees everything and gets no membership); another authorized user who works the same program is told which project it is in (`409`, also when the project is still there after its engagement was removed) and needs a member to add them, so nobody is silently shown someone else's drafts. An App Admin sees every one. The audit role cannot create one. Engagements made before this stay in the project they were made in and keep working.
2. **I read the policy** records who read it, when, and the scope at that time. If the scope changes later, the engagement and its reports warn, and the project is not scanned on its own again until you acknowledge the changed scope (the same block as an engagement that never confirmed automated testing).
3. **Import scope as targets** (into the engagement's project) previews first, then needs the acknowledgement, and imports up to 200 targets. Wildcards become their base domain and URLs their host. Blocks over 64 addresses, mobile apps, source code, and prose entries are listed as not imported, with the reason. Discovery starts only if you ticked that the policy allows automated scanning. Excluded hosts stay excluded.

### The scan gate

An engagement is also a gate on automatic scanning, so a program's assets are never scanned in the background without your confirmation. One shared check (`cveFeed.bounty_gate`) decides, for every scan the system starts on its own and for every host a scanner is aimed at:

- **The project**: a project whose engagement has not acknowledged the policy, has not confirmed that automated scanning is allowed, is paused or done, or whose program scope changed since the acknowledgement, is not scanned on its own. That covers the work conductor, certificate-transparency watching, archived-host rediscovery, host assessments and the new-hosts and re-test pipelines the system queues, the full TCP port sweep, UDP, the weekly deep nuclei lane, the thorough WPScan pass, OpenVAS, template tests, the validation and hygiene sweeps and the other slow sweeps. A scan you start yourself (Scan, Rescan, Assess host) is your decision and is not held to this.
- **The host**: whoever starts a scan, a host the program lists as out of scope, or does not list at all (only `example.com` is listed, not its subdomains), is never scanned. A host that is only ambiguous (the apex of an in-scope wildcard, a path-only entry, a pattern entry, a program whose scope is prose) is scanned once you add or import it as a target of the project: that is the confirmation. An address found behind an allowed name is refused only if an out-of-scope entry names it.
- The weekly deep discovery never adds a parent domain to a bug bounty project: the program's scope names what may be tested.

In short, a project with an engagement is scanned on its own only while you recorded that you read the policy (**I read the policy**), ticked that the policy allows automated scanning (which needs the first), and the engagement's status is `watching` or `active` (not `paused` or `done`); marking an engagement `active` also needs the policy to have been read. A project with no engagement is never blocked, and the host page counts the checks the gate holds back as not applicable. See [Pipeline](PIPELINE.md#the-bug-bounty-gate).

## Reports

A report starts from a scanner finding or blank. A draft copies the scanner's impact text if it has any and never writes impact for you. Credentials and tokens in requests and responses are masked. Checks run on every save:

- **Blockers** stop marking a report ready and stop **Submit to HackerOne**: a short title, no steps, a TODO in the steps, no impact, no asset, an out-of-scope or unlisted asset, a removed program, an unacknowledged policy, an unticked checklist item, or something that looks like a live key. They do not stop **I sent it on the platform**.
- **Warnings**: a generic title, unnumbered steps, thin impact, no evidence, a severity that disagrees with CVSS, unclear or changed scope, no confirmation that scanning is allowed, a category Bugcrowd rates priority 5, or a duplicate on the same asset.

A submitted report is final here. Move it through the program's states by hand as it answers and record any bounty.

### Submitting

- **HackerOne**: **Submit to HackerOne** posts to `https://api.hackerone.com/v1/hackers/reports` with **your own** credentials from My accounts. There is no shared key, so a report is attributed to the account that sends it. You type the program handle back to confirm, two clicks cannot send twice, and a timeout is recorded as uncertain until you confirm you looked on HackerOne. The API token is encrypted at rest, never returned, and used only when you submit or press **Test**, which makes one read of your own reports.
- **Bugcrowd, Intigriti, YesWeHack**: **Fields for the platform** names each field as that platform does, for pasting. **I sent it on the platform** then locks the report and records the address. States are not read back from any platform.

Report and engagement free-text fields are exempt from the attack-string input guard, because a report on a path traversal would otherwise strike its author. They are stored and shown as plain text. Every other field keeps the full rules.

To stop using the feature, withdraw access and set `CVENGINE_BOUNTY_CATALOGUE=0`.

See also: [TENANCY.md](TENANCY.md), [documentation index](README.md).
