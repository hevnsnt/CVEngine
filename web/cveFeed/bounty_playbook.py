"""The Playbook tab of the bug bounty page: how to take part and how to report, from the platforms' own published guidance.

Every statement below traces to one of SOURCES (read in October 2026). Where a platform's guidance does not say something, this
page does not say it either. Plain data so a test can hold it to that: every section names its sources, and every source is https.
"""

SOURCES = {
    "h1_quality": {"label": "HackerOne: Quality Reports", "url": "https://docs.hackerone.com/en/articles/8475116-quality-reports"},
    "h1_states": {"label": "HackerOne: Report States", "url": "https://docs.hackerone.com/en/articles/8475030-report-states"},
    "h1_api": {"label": "HackerOne: Hacker API (Create Report)", "url": "https://api.hackerone.com/hacker-resources/"},
    "bc_report": {"label": "Bugcrowd: Reporting a Bug", "url": "https://docs.bugcrowd.com/researchers/reporting-managing-submissions/reporting-a-bug/"},
    "bc_harbor": {"label": "Bugcrowd: Disclose.io and Safe Harbor", "url": "https://docs.bugcrowd.com/researchers/disclosure/disclose-io-and-safe-harbor/"},
    "dio_harbor": {"label": "disclose.io: Safe Harbor terms (CC0)", "url": "https://disclose.io/framework/terms/safe-harbor/"},
    "vrt": {"label": "Bugcrowd Vulnerability Rating Taxonomy (Apache-2.0)", "url": "https://github.com/bugcrowd/vulnerability-rating-taxonomy"},
    "first_cvss": {"label": "FIRST: CVSS v4.0 Specification, Table 22 (qualitative severity scale)", "url": "https://www.first.org/cvss/specification-document"},
    "btd": {"label": "bounty-targets-data (scope data used by this page)", "url": "https://github.com/arkadiyt/bounty-targets-data"},
}

PLAYBOOK = {
    "updated": "2026-10-25",
    "sections": [
        {"id": "start", "title": "Before you test anything",
         "summary": "Scope and policy decide whether your work is authorized, and whether a report is read at all.",
         "points": [
             "A program's policy is the authorization. disclose.io's safe harbor text covers research \"conducted under this policy\" only, "
             "and says the safe harbor applies to legal claims under the control of the organization, not to independent third parties.",
             "If you are unsure whether something is covered, disclose.io's wording is to ask through the program's official channel before going further.",
             "Bugcrowd grants full safe harbor to programs that commit to a defined scope, rewards, official channels and a disclosure policy; a "
             "program missing some of that gets partial safe harbor, which is not the same commitment. This page shows the flag where the data has one (Bugcrowd).",
             "Check the scope list for the exact host. A wildcard such as *.example.com names the subdomains, not example.com itself; this page "
             "marks that case as unclear instead of in scope.",
             "An out-of-scope entry beats any in-scope entry that would otherwise cover the host.",
             "HackerOne and Bugcrowd both tell you to check scope and for duplicates before you submit.",
             "Programs may forbid automated tools or set rate limits. Their policy text decides; the engagement asks you to confirm it.",
         ],
         "sources": ["dio_harbor", "bc_harbor", "h1_quality"]},
        {"id": "choose", "title": "Choosing a program",
         "summary": "Signals this page shows, and what each one does and does not tell you.",
         "points": [
             "Pays or not: a program with no bounty is a disclosure program. It can still be worth it for reputation or practice; it will not pay.",
             "Safe harbor (full, partial, none listed): the strongest legal signal the data carries, but only Bugcrowd's data has it. For the other "
             "platforms the column is empty, which means unknown, not none: look for safe harbor or disclose.io language in the policy itself.",
             "Scope size and recent scope changes: a program whose scope changed in the last days has had the least testing of the new part. "
             "The Scope changes tab lists every addition and removal since the first load.",
             "Response and resolution times: HackerOne publishes averages per program; the data has no equivalent for the other platforms, "
             "and this page shows the number only when it exists.",
             "Your own targets: the Your targets tab lists programs whose scope names domains already in your project.",
         ],
         "sources": ["btd", "bc_harbor"]},
        {"id": "report", "title": "Writing a report a program can act on",
         "summary": "The structure HackerOne and Bugcrowd both ask for.",
         "points": [
             "Title: say the bug class, where it is and what it allows. HackerOne's example: weak \"XSS in web app\", better \"Stored XSS in user "
             "profile field allows script execution on profile view\". Bugcrowd's: \"Remote File Inclusion in Resume Upload Form allows remote code "
             "execution\", not \"RFI Injection found\".",
             "Steps to reproduce: numbered, with URLs, affected parameters and the user role needed.",
             "Expected versus actual behaviour: state both.",
             "Impact: what an attacker could do, to whom, and how. Bugcrowd asks for a documented attack scenario.",
             "Supporting material: screenshots, a recording, a request and response, a proof of concept script.",
             "Suggested fix is welcome and optional (HackerOne).",
             "Common mistakes HackerOne lists: vague reports, no impact explanation, poor formatting, and unnecessary detail.",
             "Use code blocks for requests, logs and code.",
             "Bugcrowd's minimum fields: summary title, target, technical severity (a VRT category), URL or location, and a description with steps, "
             "risk and impact.",
             "Bugcrowd does not let you edit a submission after it is sent, so finish it first. This page locks a report once it is submitted.",
         ],
         "sources": ["h1_quality", "bc_report"]},
        {"id": "scanner", "title": "From a scanner hit to a report",
         "summary": "A finding from a scan is a lead. Programs want a bug someone verified.",
         "points": [
             "Reproduce it yourself, by hand, before you write anything. The report checklist asks you to confirm that.",
             "The draft carries the request the scanner sent. It does not carry an impact: the scanner cannot know what the bug lets an attacker do on "
             "this application, so that field starts empty and blocks submission until you write it.",
             "Bugcrowd's VRT rates some classes priority 5, its lowest, for example outdated software version, fingerprinting or banner disclosure, "
             "missing or misconfigured SPF or DKIM, a descriptive stack trace, and a weak password policy. Many programs close such reports as "
             "informational or list them as exclusions. The report check warns when your category is priority 5; read the program's exclusions.",
             "Credentials and tokens in a request or response are masked before they reach the draft. The check blocks submission if something that "
             "looks like a live key is left.",
         ],
         "sources": ["h1_quality", "bc_report", "vrt"]},
        {"id": "severity", "title": "Severity",
         "summary": "Rate what your impact paragraph supports.",
         "points": [
             "CVSS qualitative ratings: 0.0 none, 0.1 to 3.9 low, 4.0 to 6.9 medium, 7.0 to 8.9 high, 9.0 to 10.0 critical. The check warns when "
             "the severity you picked does not match the score you entered.",
             "Bugcrowd: the severity the VRT suggests is not guaranteed to be the severity applied once impact is considered.",
             "HackerOne's report API accepts severity none, low, medium, high or critical.",
         ],
         "sources": ["first_cvss", "bc_report", "h1_api", "vrt"]},
        {"id": "after", "title": "After you submit",
         "summary": "What each HackerOne state means for you.",
         "table": [
             ["New", "Pending validation. Open."],
             ["Pending Program Review", "HackerOne triage validated it; the program reviews it and severity. Open."],
             ["Triaged", "Validated and escalated for fixing. Treat it as live."],
             ["Needs More Info", "The program needs more from you. After 30 days in this state the report closes as informative with no reputation change."],
             ["Retesting", "A fix is being verified. It may return to Triaged or move to Resolved."],
             ["Resolved", "Fixed. +7 reputation. A bypass or regression is a new report that references the old one."],
             ["Informative", "Valid information that needs no action, often out of scope or accepted risk. No reputation change."],
             ["Duplicate", "Already reported. If you filed the original: +2 when it is resolved, -5 if it ends not applicable, 0 if informative."],
             ["Not Applicable", "Not a valid, reproducible issue. -5 reputation."],
             ["Spam", "Not a legitimate vulnerability report. -10 reputation."],
         ],
         "points": [
             "You can close your own report without a reputation change until it is triaged.",
             "Move a report through these states here by hand as the program answers, and record any bounty. This page does not read states back "
             "from a platform.",
         ],
         "sources": ["h1_states"]},
        {"id": "confidential", "title": "Confidentiality",
         "summary": "Do not share what a program has not released.",
         "points": [
             "Bugcrowd: the existence and details of private or invitation-only programs must not be shared with anyone outside Bugcrowd or the program; "
             "submissions, including duplicates, out-of-scope and not-applicable ones, fall under its standard disclosure terms, and a vulnerability cannot be "
             "shared without permission.",
             "Read each program's disclosure policy before you write about a finding anywhere else.",
             "Reports in this tool belong to one project and are visible to its members. Do not keep another program's private details in a shared project.",
         ],
         "sources": ["bc_report", "bc_harbor"]},
    ],
    "limits": [
        "Program data comes from the bounty-targets-data dump, refreshed about every 30 minutes from each platform's public pages. Private programs and anything the "
        "platforms do not publish are not in it.",
        "Scope matching is exact on host names, wildcards, IP addresses and CIDR blocks. Entries written as prose or as patterns are shown as unclear, "
        "never as in scope.",
        "Only HackerOne has a submit button here. For Bugcrowd, Intigriti and YesWeHack you copy the finished fields into the platform and mark the report submitted.",
        "Nothing on this page replaces reading a program's policy.",
    ],
    "sources": SOURCES,
}
