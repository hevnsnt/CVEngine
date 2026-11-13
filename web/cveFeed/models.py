"""Models for the cve.now feed.

One row per cve.now entry, carrying the merged severity, exploitation
(CISA KEV / EPSS / Exploit-DB) and affected-product data that the AI
correlation engine matches against the discovered asset inventory.
"""
from django.contrib.postgres.fields import ArrayField
from django.db import models
from django.db.models.signals import post_delete
from django.dispatch import receiver
from django.db.models import Value
from django.db.models.functions import Lower, Now

from reNgine.crypto_fields import ENCRYPTED_COLUMN_LENGTH, EncryptedCharField, EncryptedJSONField
from django.utils import timezone
from targetApp.alias_note import ALIAS_MAX, NOTE_MAX
from django.utils.dateparse import parse_datetime


def _clean_affected(value):
    from cveFeed.correlation import clean_affected
    return clean_affected(value)


def _feed_time(value):
    """A feed timestamp, or None when it is missing or not a real date: one malformed entry must not stop the sync."""
    try:
        return parse_datetime(value) if value else None
    except (TypeError, ValueError):
        return None


class CVEEntry(models.Model):
    cve_id = models.CharField(max_length=64, unique=True, db_index=True)
    title = models.TextField(blank=True, default="")
    summary = models.TextField(blank=True, default="")  # model-written plain-English summary
    summary_model = models.CharField(max_length=128, blank=True, default="")
    original_description = models.TextField(blank=True, default="")

    cvss = models.FloatField(null=True, blank=True)
    cvss_vector = models.CharField(max_length=128, blank=True, default="")
    severity_source = models.CharField(max_length=128, blank=True, default="")  # often a 36-character CNA identifier
    stated_severity = models.CharField(max_length=128, blank=True, default="")

    # Exploitation signals (cve.now merges CISA KEV, FIRST EPSS, Exploit-DB).
    kev = models.BooleanField(null=True, blank=True)  # listed in CISA KEV
    epss_reached = models.BooleanField(null=True, blank=True)  # EPSS probability >= 0.1
    exploit_db = models.BooleanField(null=True, blank=True)  # has an Exploit-DB entry

    # Structured match data for correlation:
    # [{"vendor", "product", "package", "ranges": [{"introduced","fixed","lastAffected"}]}]
    affected = models.JSONField(default=list, blank=True)
    references = models.JSONField(default=list, blank=True)
    sources = models.JSONField(default=list, blank=True)

    status = models.CharField(max_length=128, blank=True, default="")
    published_at = models.DateTimeField(null=True, blank=True)
    first_seen_at = models.DateTimeField(null=True, blank=True)

    intel = models.JSONField(default=dict, blank=True)  # per-source exploitation detail (cveFeed.intel): kev, epss, exploits
    needs_recorrelation = models.BooleanField(default=False)
    # A flaw an attacker can only use from the host itself (CVSS attack vector local or physical, or a kernel or operating-system
    # elevation of privilege): an external scan cannot see the software or patch level that decides it, so it is never matched to a
    # host (cveFeed.locality). Computed from the record; ``locality_at`` is when it was last worked out.
    local_only = models.BooleanField(default=False, db_default=False, db_index=True)
    locality_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    synced_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-published_at", "-first_seen_at"]
        verbose_name = "CVE entry"
        verbose_name_plural = "CVE entries"
        indexes = [
            models.Index(fields=["kev"], name="cvefeed_kev_idx"),
            models.Index(fields=["cvss"], name="cvefeed_cvss_idx"),
            models.Index(fields=["published_at"], name="cvefeed_pub_idx"),
        ]

    def __str__(self):
        return f"{self.cve_id} (cvss={self.cvss}, kev={self.kev})"

    @property
    def is_critical(self):
        """cve.now's 'critical' rule: in KEV, or CVSS >= 9, or CVSS >= 7 with EPSS >= 0.1."""
        cvss = self.cvss or 0.0
        return bool(self.kev) or cvss >= 9.0 or (cvss >= 7.0 and bool(self.epss_reached))

    @property
    def attention_tier(self):
        """The legacy fire / smoke / ice rating (KEV, exploit, CVSS, EPSS): what decides which CVEs are looked for and tested, under either
        heat policy (cveFeed.threat.attention_tier)."""
        from cveFeed.threat import attention_tier

        return attention_tier(kev=self.kev, epss_reached=self.epss_reached, exploit_db=self.exploit_db, cvss=self.cvss)

    @property
    def threat_tier(self):
        """CVEngine fire / smoke / ice tier of the CVE in general, under the heat policy (see cveFeed.threat.classify_threat_tier)."""
        from cveFeed.threat import classify_threat_tier

        return classify_threat_tier(
            kev=self.kev,
            epss_reached=self.epss_reached,
            exploit_db=self.exploit_db,
            cvss=self.cvss,
        )

    @classmethod
    def from_api(cls, entry):
        """Upsert a CVEEntry from a full cve.now entry dict. Returns (obj, created)."""
        summary = entry.get("summary") or {}
        if not isinstance(summary, dict):
            summary = {}
        severity = entry.get("severity")
        severity = severity if isinstance(severity, dict) else {}
        exploitation = entry.get("exploitation")
        exploitation = exploitation if isinstance(exploitation, dict) else {}
        exploit_db = exploitation.get("exploitDb")
        defaults = {
            "title": entry.get("title") or "",
            "summary": summary.get("text") or "",
            "summary_model": summary.get("model") or "",
            "original_description": entry.get("originalDescription") or "",
            "cvss": severity.get("cvss"),
            "cvss_vector": severity.get("vector") or "",
            "severity_source": severity.get("source") or "",
            "stated_severity": entry.get("statedSeverity") or "",
            "kev": exploitation.get("kev"),
            "epss_reached": exploitation.get("epssReached"),
            "exploit_db": None if exploit_db is None else bool(exploit_db),
            "affected": _clean_affected(entry.get("affected")),
            "references": entry.get("references") if isinstance(entry.get("references"), list) else [],
            "sources": entry.get("sources") if isinstance(entry.get("sources"), list) else [],
            "status": entry.get("status") or "",
            "published_at": _feed_time(entry.get("publishedAt")),
            "first_seen_at": _feed_time(entry.get("firstSeenAt")),
        }
        # the CVE List's own forms the feed passes on ("unspecified" bounds, a branch in two ranges, Junos' "21.1*" and comma lists of fixes) are
        # made ranges correlation can read, and a block the feed states no range for keeps the ranges the CVE List record gave (issues 205, 210)
        from cveFeed.intel import keep_published_ranges, normalize_feed_ranges, overlay_branch_ranges
        defaults["affected"] = normalize_feed_ranges(defaults["affected"])
        stored = cls.objects.filter(cve_id=str(entry["id"])[:64]).values_list("affected", "sources").first()
        if stored and "CVE List V5" in (stored[1] or []):
            defaults["affected"] = keep_published_ranges(defaults["affected"], stored[0])
            if "CVE List V5" not in defaults["sources"]:  # the label is what lets the next refresh keep them too
                defaults["sources"] = [*defaults["sources"], "CVE List V5"]
        # a branch-by-branch fix list the feed gave with no lower bounds takes the CNA's own bounds from the CVE List record (issue 205)
        defaults["affected"], overlaid = overlay_branch_ranges(str(entry["id"])[:64], defaults["affected"])
        if overlaid and "CVE List V5" not in defaults["sources"]:
            defaults["sources"] = [*defaults["sources"], "CVE List V5"]
        # a bound the structured record states narrower than public sources show (cveFeed.range_corrections, each with its sources)
        from cveFeed import range_corrections
        defaults["affected"], _corrected = range_corrections.apply(str(entry["id"])[:64], defaults["affected"])
        # a feed value longer than its column must never cost the whole CVE: clip text to what the column holds
        for field in cls._meta.get_fields():
            limit = getattr(field, "max_length", None)
            if limit and field.name in defaults and isinstance(defaults[field.name], str):
                defaults[field.name] = defaults[field.name][:limit]
        cve_id = str(entry["id"])[:64]
        intel = cls.objects.filter(cve_id=cve_id).values_list("intel", flat=True).first()
        if intel:  # what the other sources reported stays: cve.now rewriting the entry must not clear it (cveFeed.intel)
            from cveFeed.intel import merged_flags
            defaults["kev"], defaults["epss_reached"], defaults["exploit_db"] = merged_flags(exploitation, intel)
        return cls.objects.update_or_create(cve_id=cve_id, defaults=defaults)


class IntelSource(models.Model):
    """One threat-intelligence source (cveFeed.intel.SOURCES): when it was last read and what it answered."""
    name = models.CharField(max_length=32, primary_key=True)
    etag = models.CharField(max_length=200, blank=True, default="")
    last_modified = models.CharField(max_length=100, blank=True, default="")
    last_checked = models.DateTimeField(null=True, blank=True)
    last_changed = models.DateTimeField(null=True, blank=True)
    last_error = models.CharField(max_length=300, blank=True, default="")
    cves = models.PositiveIntegerField(default=0)

    def __str__(self):
        return self.name


class CVEMatch(models.Model):
    """A discovered asset matched to a cve.now entry.

    Produced by the correlation engine: deterministic candidate generation (a
    discovered Technology / service matched to a CVEEntry's affected product and
    version range), optionally confirmed by the user's chosen AI model.
    """

    cve_entry = models.ForeignKey(CVEEntry, on_delete=models.CASCADE, related_name="matches")
    subdomain = models.ForeignKey(
        "startScan.Subdomain", on_delete=models.CASCADE,
        related_name="cve_matches", null=True, blank=True)
    scan_history = models.ForeignKey(
        "startScan.ScanHistory", on_delete=models.SET_NULL,
        related_name="cve_matches", null=True, blank=True)

    matched_product = models.CharField(max_length=255, blank=True, default="")
    matched_version = models.CharField(max_length=100, blank=True, default="")
    # True = in an affected range, False = out of range, None = version unknown.
    version_in_range = models.BooleanField(null=True, blank=True)
    confidence = models.FloatField(default=0.0)  # 0..1 heuristic, pre-AI
    source = models.CharField(max_length=16, default="tech")  # tech | port | cpe

    # Optional AI confirmation, filled by the correlation AI step.
    ai_verdict = models.CharField(max_length=16, blank=True, default="")  # affected|not_affected|uncertain
    ai_reason = models.TextField(blank=True, default="")
    ai_model = models.CharField(max_length=128, blank=True, default="")

    # What a nuclei template test said about this host for this CVE: vulnerable | no_match | error, or "" when untested. version_only: a
    # version-class template (cveFeed.templategen.template_evidence) matched, which reads the version again and is not hard evidence.
    TEMPLATE_RESULTS = ("vulnerable", "no_match", "error", "version_only")
    template_result = models.CharField(max_length=12, blank=True, default="")
    template_id = models.CharField(max_length=128, blank=True, default="")
    template_tested_at = models.DateTimeField(null=True, blank=True)

    # What the distribution says about this host's package release (cveFeed.distro): patched | vulnerable | unknown | no_data.
    # A patched match is kept (the upstream version is in range, which is a fact) but is not auto-fired and reads as ice.
    distro_status = models.CharField(max_length=12, blank=True, default="no_data")
    distro_fixed_version = models.CharField(max_length=64, blank=True, default="")

    # What the match rests on, so a reviewer need not redo the correlation: {source: "port"|"tech", source_id, raw_version,
    # service_extra, cpe, method, affected_index, range, distro}. Written by correlation.
    evidence = models.JSONField(default=dict, blank=True)
    # When this match was announced as fire on the host (cveFeed.notify: fire_matches when it was made fire, fire_confirmed when evidence turned
    # it fire later, cves_turned_hot when its CVE joined the KEV), or marked as announced without a message (notify.baseline_heat_policy), and
    # under which heat rule (threat.heat_signature: "kev", "legacy:smoke", ...). A match is paged as fire at most once PER RULE: a mark made under
    # one rule never holds back a page that is new under another (notify.unannounced_q).
    fire_notified_at = models.DateTimeField(null=True, blank=True)
    fire_notified_rule = models.CharField(max_length=24, blank=True, default="", db_default="")  # db_default: old code still inserting during an update

    # Remediation workflow, driven by people or agents through the API / MCP. fixed, accepted_risk and false_positive close a finding
    # (cveFeed.closure.CLOSED); remediation_note is the note on why, with who (remediation_by) and when (remediation_updated_at).
    REMEDIATION_STATUSES = ("open", "in_progress", "fixed", "accepted_risk", "false_positive")
    remediation_status = models.CharField(max_length=16, default="open")
    remediation_note = models.TextField(blank=True, default="")
    remediation_updated_at = models.DateTimeField(null=True, blank=True)
    remediation_by = models.ForeignKey(
        "auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    # Who owns triaging this finding. Independent of remediation_by; set through the same API/MCP surface. Same field
    # on startScan.models.Vulnerability and HygieneFinding below.
    assignee = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "CVE match"
        verbose_name_plural = "CVE matches"
        ordering = ["-confidence", "-created_at"]
        indexes = [models.Index(fields=["subdomain", "ai_verdict"], name="cvematch_sub_verdict_idx")]
        constraints = [
            models.UniqueConstraint(
                fields=["cve_entry", "subdomain", "source", "matched_product"],
                name="uniq_cvematch_asset_source_product",
            )
        ]

    def __str__(self):
        return f"{self.cve_entry.cve_id} ~ {self.subdomain} ({self.confidence:.2f})"


class OnDemandValidation(models.Model):
    """One explicit, project-scoped request to review and check a CVE match."""

    match = models.ForeignKey(CVEMatch, on_delete=models.CASCADE, related_name='validation_requests')
    project = models.ForeignKey('dashboard.Project', on_delete=models.CASCADE, related_name='+')
    requested_by = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, related_name='+')
    source = models.CharField(max_length=12, default='automatic')  # automatic | manual | legacy
    requested_token_id = models.PositiveBigIntegerField(null=True, blank=True)  # retained after token deletion
    evidence_signature = models.CharField(max_length=40, blank=True, default='')
    priority = models.PositiveSmallIntegerField(default=3)  # Redis 0 Fire, 3 manual, 6 Smoke
    status = models.CharField(max_length=12, default='queued')  # queued | running | completed | failed
    result = models.JSONField(default=dict, blank=True)
    error = models.CharField(max_length=300, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    attempts = models.PositiveSmallIntegerField(default=1)  # this try for the same evidence (hot_validation.MAX_ATTEMPTS)
    next_attempt_at = models.DateTimeField(null=True, blank=True)  # a failed job: when it may run again; None once exhausted

    class Meta:
        indexes = [models.Index(fields=['project', 'created_at'], name='ondemand_project_created_idx')]
        constraints = [models.UniqueConstraint(fields=['match'], condition=models.Q(status__in=['queued', 'running']),
                                           name='one_active_validation_per_match')]


class BackgroundCursor(models.Model):
    """Durable round-robin position for a bounded background reconciliation."""

    lane = models.CharField(max_length=32, primary_key=True)
    last_pk = models.PositiveBigIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)


class FeedWatermark(models.Model):
    """How far the CVE feed is known to be complete (cveFeed.feed_watermark): every entry the feed lists with a publication time after
    ``covered_through`` has been read. A snapshot (the seed) sets it to what the snapshot covers, and a walk that read back past it
    (with a margin for entries the feed saw late) and stored everything it listed moves it to the head of the feed it read. A walk cut
    short keeps ``resume_cursor`` (the listing's own cursor) and the head it started from, so the next run continues instead of
    starting over; a failure never advances it."""

    source = models.CharField(max_length=32, primary_key=True)
    covered_through = models.DateTimeField(null=True, blank=True)
    resume_cursor = models.TextField(blank=True, default="")
    resume_head = models.DateTimeField(null=True, blank=True)
    checked_at = models.DateTimeField(null=True, blank=True)  # when a walk last reached its floor
    # entries a walk listed but could not read, as {id: attempts}; one that failed ``MAX_ATTEMPTS`` runs in a row is set aside (reported, no longer
    # allowed to keep the window from being declared covered)
    failures = models.JSONField(default=dict, db_default={}, blank=True)
    # set when the first walk had no seed time and no earlier walk to start from: the feed was only read back this many days
    assumed_days = models.PositiveSmallIntegerField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)


class HotValidationCursor(models.Model):
    """Durable round-robin position for one bounded Fire/Smoke finding sweep."""

    lane = models.CharField(max_length=24, primary_key=True)
    last_pk = models.PositiveBigIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)


class AutomaticValidation(models.Model):
    """A queued assessment of a non-CVE finding, keyed by its current evidence signature."""

    triage = models.ForeignKey('cveFeed.Triage', on_delete=models.CASCADE, related_name='automatic_validations')
    project = models.ForeignKey('dashboard.Project', on_delete=models.CASCADE, related_name='+')
    signature = models.CharField(max_length=64)
    priority = models.PositiveSmallIntegerField(default=6)  # Redis transport: 0 Fire, 3 manual, 6 Smoke
    source = models.CharField(max_length=12, default='automatic')  # automatic | manual
    requested_by = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    requested_token_id = models.PositiveBigIntegerField(null=True, blank=True)  # retained after token deletion
    status = models.CharField(max_length=12, default='queued')  # queued | running | completed | failed
    attempts = models.PositiveSmallIntegerField(default=0)
    next_attempt_at = models.DateTimeField(null=True, blank=True)
    result = models.JSONField(default=dict, blank=True)
    error = models.CharField(max_length=300, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=['project', 'status', 'created_at'], name='autoval_project_status_idx')]
        constraints = [models.UniqueConstraint(fields=['triage'], condition=models.Q(status__in=['queued', 'running']),
                                           name='one_active_autoval_per_finding')]


class MatchVerdict(models.Model):
    """One AI verdict for a kind of match, shared by every host that has it.

    Fifty hosts running the same nginx 1.18 for one CVE are one question, not fifty: the verdict is asked once per
    (CVE, product, version, in-range, source), applied to every CVEMatch with that signature, and reused by later
    correlations so a re-run never asks again.

    It has no tenant, so it only ever holds and seeds answers that raise attention (affected, uncertain): a closing answer may rest on
    what one organization's host said and is never stored here or seeded from here (``correlation._seedable``, task 256).
    """

    cve_entry = models.ForeignKey(CVEEntry, on_delete=models.CASCADE, related_name="+")
    matched_product = models.CharField(max_length=255, blank=True, default="")
    matched_version = models.CharField(max_length=100, blank=True, default="")
    version_in_range = models.BooleanField(null=True, blank=True)
    source = models.CharField(max_length=16, default="tech")
    ai_verdict = models.CharField(max_length=16)
    ai_reason = models.TextField(blank=True, default="")
    ai_model = models.CharField(max_length=128, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["cve_entry", "matched_product", "matched_version", "version_in_range", "source"],
                name="uniq_matchverdict_signature", nulls_distinct=False)
        ]

    def __str__(self):
        return f"{self.cve_entry_id} {self.matched_product} {self.matched_version} -> {self.ai_verdict}"


class AutoFireRun(models.Model):
    """Record that the AI engine fired on a FIRE/SMOKE CVE (one per CVE, so it never refires)."""

    cve_entry = models.OneToOneField(CVEEntry, on_delete=models.CASCADE, related_name="autofire")
    tier = models.CharField(max_length=8)
    status = models.CharField(max_length=16, default="done")  # done | no_targets | error
    matches_found = models.IntegerField(default=0)
    targets = models.JSONField(default=list, blank=True)  # domain names a scan was started on
    scan_ids = models.JSONField(default=list, blank=True)
    error = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.cve_entry.cve_id} [{self.tier}] {self.status}"


class GeneratedTemplate(models.Model):
    """An AI-authored nuclei template for a CVE no installed template covers.

    Lifecycle (``cveFeed.templatevalidate``, no person involved): draft (pending) -> static check -> nuclei -validate and the benign
    control on a Sentinel -> a fixture the AI writes from the CVE data, matched offline -> the AI's second-pass critique -> valid |
    invalid, or expired when it could not be validated within the window. Only valid rows are ever run on a host (test_results holds the
    per-host outcome).
    """

    STATUS_DRAFT = "draft"
    STATUS_VALID = "valid"
    STATUS_INVALID = "invalid"
    STATUS_EXPIRED = "expired"  # still a draft after the window, never validated: closed by the system, with the reason

    cve_entry = models.ForeignKey(CVEEntry, on_delete=models.CASCADE, related_name="generated_templates")
    template_id = models.CharField(max_length=128)
    yaml = models.TextField()
    status = models.CharField(max_length=16, default=STATUS_DRAFT)
    validation_output = models.TextField(blank=True, default="")
    test_results = models.JSONField(default=list, blank=True)  # [{host, vulnerable, output}]
    ai_model = models.CharField(max_length=128, blank=True, default="")
    path = models.CharField(max_length=500, blank=True, default="")  # saved template file
    positive_fixture_verified_at = models.DateTimeField(null=True, blank=True)
    positive_fixture_source = models.CharField(max_length=300, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    # the automatic validator's bookkeeping (cveFeed.templatevalidate)
    validation_stage = models.CharField(max_length=24, blank=True, db_default='', default='')  # the next step: '' | fixture | critique | waiting:<step>
    validation_attempts = models.PositiveSmallIntegerField(db_default=0, default=0)  # failed tries that count (a missing Sentinel does not)
    validation_started_at = models.DateTimeField(null=True, blank=True)  # when the validator first looked at it: the expiry clock
    validation_next_at = models.DateTimeField(null=True, blank=True)  # not before this (back-off)
    validation_reason = models.TextField(blank=True, db_default='', default='')  # the plain-language reason of a rejection, an expiry or a wait
    validated_at = models.DateTimeField(null=True, blank=True)  # when it became valid, invalid or expired
    fixture = models.JSONField(null=True, blank=True)  # {vulnerable, not_affected}: the AI-written responses the matchers were tested on

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.template_id} [{self.status}]"


class DistroFix(models.Model):
    """What a distribution says fixes a CVE in one of its packages: the fixed package version per release.

    Filled by ``cveFeed.distro_sync`` (Debian security tracker, OSV for Ubuntu and Debian); read by correlation to tell a
    host running a patched backport from a vulnerable one. ``status``: fixed (``fixed_version`` is the first fixed package
    release; "0" means the release was never affected), vulnerable (affected, no fix yet), not_affected, undetermined."""

    distro = models.CharField(max_length=16)  # ubuntu | debian | rhel | alpine ...
    release = models.CharField(max_length=16)  # 22.04, 12
    package = models.CharField(max_length=128)  # the distro's source package: openssh, apache2
    cve_id = models.CharField(max_length=32)  # CVE-2024-6387
    fixed_version = models.CharField(max_length=128, blank=True, default="")
    status = models.CharField(max_length=16, default="fixed")
    synced_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["distro", "release", "package", "cve_id"], name="uniq_distrofix")]
        indexes = [models.Index(fields=["cve_id", "package"], name="distrofix_cve_pkg_idx")]

    def __str__(self):
        return f"{self.cve_id} {self.distro}:{self.release}/{self.package} {self.fixed_version or self.status}"


class DiscoveryEvent(models.Model):
    """One thing found for a target, kept so the dashboard can replay and live-follow discovery.

    Most come from one bbot run (``scan`` set). Certificate-transparency monitoring (cveFeed.ctmonitor)
    finds hosts between scans, with no scan to attach to, so ``domain`` is set directly instead; it is also
    what tenancy scoping uses, so an event is visible precisely when its domain is.
    """

    scan = models.ForeignKey("startScan.ScanHistory", on_delete=models.CASCADE, related_name="discovery_events",
                             null=True, blank=True)
    domain = models.ForeignKey("targetApp.Domain", on_delete=models.CASCADE, related_name="+")
    type = models.CharField(max_length=32)
    label = models.CharField(max_length=500, blank=True, default="")
    host = models.CharField(max_length=500, blank=True, default="")
    parent_host = models.CharField(max_length=500, blank=True, default="")
    module = models.CharField(max_length=64, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["scan", "id"]), models.Index(fields=["domain", "id"])]
        ordering = ["id"]

    def __str__(self):
        return f"{self.type} {self.label}"


class ServiceRun(models.Model):
    """The last time one scanner finished on one asset, so a host is fingerprinted once, not once per scan.

    ``asset`` is an IP, a hostname, a ``host:port`` or a domain, depending on the service. nmap rows are global (project
    null: an IP's open ports are a public fact and IpAddress/Port have no tenant); nuclei and bbot rows belong to a
    project. Engine-internal bookkeeping, so it is not in the tenancy ``SCOPES`` and keeps a plain manager.
    """

    service = models.CharField(max_length=64)  # nmap-fast | nmap-full | nuclei[:tags] | bbot
    asset = models.CharField(max_length=255)
    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, null=True, blank=True, related_name="+")
    scan = models.ForeignKey("startScan.ScanHistory", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    status = models.CharField(max_length=10, default="done")  # done | failed
    finished_at = models.DateTimeField(default=timezone.now)

    objects = models.Manager()

    class Meta:
        indexes = [
            models.Index(fields=["service", "asset", "project"], name="servicerun_svc_asset_proj_idx"),
            models.Index(fields=["service", "project", "finished_at"], name="servicerun_svc_proj_fin_idx"),
        ]
        constraints = [
            # NULLs are distinct in a unique constraint, so project-less (global) rows need a constraint of their own
            models.UniqueConstraint(fields=["service", "asset", "project"], condition=models.Q(project__isnull=False),
                                    name="uniq_servicerun_project"),
            models.UniqueConstraint(fields=["service", "asset"], condition=models.Q(project__isnull=True),
                                    name="uniq_servicerun_global"),
        ]

    def __str__(self):
        return f"{self.service} {self.asset} [{self.status}]"


class AgentActivity(models.Model):
    """What the AI engine is doing, as a feed: reading the CVE feed, checking the inventory, identifying a
    target, writing / running / validating a check. Global entries (project null) are visible to every member."""

    KINDS = ("feed", "inventory", "target", "confirm", "write_check", "run_check", "validate", "discovery", "scan", "hygiene", "changes",
             "remediation", "saved_search", "runzero")
    kind = models.CharField(max_length=24)
    message = models.CharField(max_length=500)
    status = models.CharField(max_length=10, default="done")  # running | done | failed | waiting (back-pressure) | notice (said once, nothing wrong) | skipped (refused on purpose) | deferred (put off, retried)
    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, null=True, blank=True, related_name="+")
    cve_id = models.CharField(max_length=64, blank=True, default="")
    detail = models.JSONField(default=dict, blank=True)
    repeat = models.PositiveIntegerField(default=1)  # how many times this same line was reported in a row
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-id"]
        indexes = [models.Index(fields=["id"]),
                   # the dashboard and admin feeds read a project's (or the failed) entries newest first; retention reads by age
                   models.Index(fields=["project", "id"], name="agentact_project_id_idx"),
                   models.Index(fields=["status", "id"], name="agentact_status_id_idx"),
                   models.Index(fields=["created_at"], name="agentact_created_idx")]

    def __str__(self):
        return f"[{self.kind}] {self.message}"


class TlsCertificate(models.Model):
    """The certificate a host presented on a TLS port at the last check."""

    domain = models.ForeignKey("targetApp.Domain", on_delete=models.CASCADE, related_name="+")
    host = models.CharField(max_length=500)
    port = models.IntegerField(default=443)
    subject = models.CharField(max_length=500, blank=True, default="")
    issuer = models.CharField(max_length=500, blank=True, default="")
    sans = models.JSONField(default=list, blank=True)
    not_before = models.DateTimeField(null=True, blank=True)
    not_after = models.DateTimeField(null=True, blank=True)
    signature_algorithm = models.CharField(max_length=100, blank=True, default="")
    key_description = models.CharField(max_length=100, blank=True, default="")  # e.g. "RSA 2048"
    protocol = models.CharField(max_length=20, blank=True, default="")
    cipher = models.CharField(max_length=100, blank=True, default="")
    chain_error = models.CharField(max_length=300, blank=True, default="")  # why the system trust store rejected it
    legacy_tls = models.BooleanField(default=False)  # still accepts TLS 1.0 / 1.1
    checked_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("domain", "host", "port")
        ordering = ["not_after"]

    @property
    def days_left(self):
        from django.utils import timezone
        return (self.not_after - timezone.now()).days if self.not_after else None

    def __str__(self):
        return f"{self.host}:{self.port}"


class HygieneFinding(models.Model):
    """A configuration-hygiene finding for a domain or host: TLS, certificates, SPF, DKIM, DMARC, CAA, cleartext services."""

    domain = models.ForeignKey("targetApp.Domain", on_delete=models.CASCADE, related_name="+")
    host = models.CharField(max_length=500)
    # not named `check`: that shadows Model.check(), which Django 5 refuses (models.E020)
    check_name = models.CharField(max_length=40)  # e.g. tls_expired, spf_missing, dmarc_none
    severity = models.IntegerField(default=0)  # 0 info .. 4 critical (same scale as scanner findings)
    title = models.CharField(max_length=300)
    detail = models.TextField(blank=True, default="")
    evidence = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=10, default="open")  # open | resolved
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    # Remediation workflow, driven by people or agents through the API / MCP. Independent of ``status`` above, which the
    # hygiene sweep alone manages (see cveFeed.hygiene): a finding a human marks accepted_risk stays "open" here if the
    # check still finds it, but drops out of the actionable view regardless. Same fields and choices as CVEMatch's.
    REMEDIATION_STATUSES = CVEMatch.REMEDIATION_STATUSES
    remediation_status = models.CharField(max_length=16, default="open")
    remediation_note = models.TextField(blank=True, default="")
    remediation_updated_at = models.DateTimeField(null=True, blank=True)
    remediation_by = models.ForeignKey(
        "auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    assignee = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")

    class Meta:
        unique_together = ("domain", "host", "check_name")
        ordering = ["-severity", "host"]

    def __str__(self):
        return f"{self.host}: {self.title}"


class HostLabel(models.Model):
    """A short informational signal about a host ("WAF", "nginx version", "federated auth"): what bbot detected that is not a
    finding. Shown as a chip on the host. One row per (project, host, label); a repeat only moves ``last_seen``."""

    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    domain = models.ForeignKey("targetApp.Domain", on_delete=models.CASCADE, related_name="+")
    host = models.CharField(max_length=500)  # lowercase
    label = models.CharField(max_length=64)
    kind = models.CharField(max_length=16, blank=True, default="detection")
    source = models.CharField(max_length=32, blank=True, default="bbot")
    detail = models.CharField(max_length=300, blank=True, default="")  # the detection's own text, for the chip's tooltip
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)

    MAX_PER_HOST = 30

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "host", "label"], name="uniq_hostlabel_project_host_label")]
        indexes = [models.Index(fields=["project", "host"], name="hostlabel_proj_host_idx")]

    def __str__(self):
        return f"{self.host}: {self.label}"


class ProbeObservation(models.Model):
    """One fact a version or identity probe (cveFeed.probes) found, or looked for and did not find, about a host: a product's version,
    which of several look-alike products runs there, the edge in front of it, whether it is WordPress. One row per
    (project, host, probe, port, kind, product); a repeat updates it. ``outcome`` says whether the probe found the fact, found that the host
    hides it (``hidden``: the product answers and states no version), saw only a CDN or WAF edge (``edge``), was refused by the edge
    (``challenged``) or found nothing of the kind (``absent``). Never a guess: a version is stored only when the response states it."""

    OUTCOMES = ("found", "hidden", "edge", "challenged", "absent")
    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    domain = models.ForeignKey("targetApp.Domain", on_delete=models.CASCADE, related_name="+")
    host = models.CharField(max_length=500)  # lowercase
    probe = models.CharField(max_length=48)
    kind = models.CharField(max_length=16)  # version | identity | edge | wordpress | wp-plugin | wp-theme | vhost | subapp
    product = models.CharField(max_length=120, blank=True, default="")
    version = models.CharField(max_length=100, blank=True, default="")
    variant = models.CharField(max_length=60, blank=True, default="")  # identity: nginx, ingress-nginx, nginx-ui ...
    port = models.IntegerField(default=0)  # 0: not specific to one port
    url = models.CharField(max_length=500, blank=True, default="")  # the path or URL that answered, host name removed
    outcome = models.CharField(max_length=12, default="found")
    confidence = models.FloatField(default=0.0)
    source = models.CharField(max_length=48, blank=True, default="")  # header:server, body:regex, nmap:-sV ...
    evidence = models.JSONField(default=dict, blank=True)
    first_seen = models.DateTimeField(default=timezone.now)
    observed_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "host", "probe", "port", "kind", "product"], name="uniq_probeobs_host_probe_port_kind_product")]
        indexes = [models.Index(fields=["project", "host"], name="probeobs_proj_host_idx")]

    def __str__(self):
        return f"{self.host}: {self.probe} {self.product} {self.version}".strip()


class HostProfile(models.Model):
    """Editable asset information for one host of a project: who owns it, what it is for and how much it matters, and the alias (a short
    display name) and note a person gave it. One row per (project, host); the host name is stored lowercase. Never read by a scanner.
    It is keyed by the host's name, not by a scan row or an address set, so it survives rescans, and when other names resolve to the same
    addresses the Hosts page shows one host and takes the alias and note from whichever of its names has them (agentapi.services._host)."""

    CRITICALITY = ("unknown", "low", "medium", "high", "critical")
    CRITICALITY_CHOICES = [(c, c) for c in CRITICALITY]

    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    host = models.CharField(max_length=500)  # lowercase
    owner = models.CharField(max_length=200, blank=True, default="")
    purpose = models.CharField(max_length=500, blank=True, default="")
    criticality = models.CharField(max_length=16, choices=CRITICALITY_CHOICES, default="unknown")
    alias = models.CharField(max_length=ALIAS_MAX, blank=True, default="", db_default="")  # display only: the address and discovered names stay
    note = models.CharField(max_length=NOTE_MAX, blank=True, default="", db_default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "host"], name="uniq_hostprofile_project_host")]

    def __str__(self):
        return f"{self.host}: {self.criticality}"


class HostMove(models.Model):
    """A host moved out of this project into another ("Move host"). The source project never brings it back: its discovery and
    scans treat the name as excluded (cveFeed.exclusions.excluded_names), while the destination scans it as its own target.
    Exact name only, lowercase. Moving the host back into this project deletes the row."""

    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    host = models.CharField(max_length=500)  # lowercase, no trailing dot
    moved_to = models.ForeignKey("dashboard.Project", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    moved_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    moved_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "host"], name="uniq_hostmove_project_host")]

    def __str__(self):
        return f"{self.host} moved out of project {self.project_id}"


class HostExclusion(models.Model):
    """A host an organization never wants scanned again ("Remove & exclude"). Org-wide: it applies to every project of the org
    and to nothing outside it. The match is the whole host name, lowercase and case-insensitive; never a bare suffix or substring,
    so excluding ``provider.example`` leaves ``notprovider.example`` and ``www.provider.example`` alone, unless the exclusion was
    made with ``include_subdomains``, which also covers every name under the domain (on a dot boundary).

    Not in tenancy.scope.SCOPES (that maps a model to a project id): it is read and written only through cveFeed.exclusions
    and the agentapi services, which always filter by the caller's own org, so it cannot leak across orgs. Scanners read it
    unscoped (Celery has no request scope), always through the project's own org."""

    org = models.ForeignKey("dashboard.Org", on_delete=models.CASCADE, related_name="host_exclusions")
    host = models.CharField(max_length=500)  # lowercase, no trailing dot
    include_subdomains = models.BooleanField(default=False, db_default=False)  # a whole domain: the name and every name under it ("-example.com")
    reason = models.CharField(max_length=300, blank=True, default="")
    created_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["org", "host"], name="uniq_hostexclusion_org_host")]

    def __str__(self):
        return f"{self.host} (org {self.org_id})"


class ExcludedAddress(models.Model):
    """An address or network an organization must never have scanned (the "do not scan these addresses" list). Org-wide, like HostExclusion,
    but matched on the ADDRESS: the entry itself, any host name whose resolved addresses (the inventory's stored ones, or the answer of a lookup
    a task made) fall inside it, and any task that names an address inside it. ``cidr`` is stored normalised (``cveFeed.exclusions.parse_entry``:
    a bare address is a /32 or /128, host bits are cleared, IPv6 is compressed), so the same network is one row however it was typed. Private
    ranges are valid entries. Read and written only through cveFeed.exclusions and agentapi.excluded_addresses, which always filter by the
    organization, so it cannot leak across orgs; scanners read it unscoped (Celery has no request scope) through the project's own org."""

    org = models.ForeignKey("dashboard.Org", on_delete=models.CASCADE, related_name="excluded_addresses")
    cidr = models.CharField(max_length=64, default="", db_default="")
    note = models.CharField(max_length=300, blank=True, default="", db_default="")
    created_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    created_at = models.DateTimeField(default=timezone.now, db_default=Now())

    class Meta:
        constraints = [models.UniqueConstraint(fields=["org", "cidr"], name="uniq_excludedaddress_org_cidr")]
        ordering = ["id"]

    def __str__(self):
        return f"{self.cidr} (org {self.org_id})"


class HostState(models.Model):
    """What CVEngine last knew about one host of a project: the snapshot the next scan is diffed against.
    One row per (project, host); Port/IpAddress rows are shared and rewritten in place, so this is the only
    record of what a host looked like before the latest scan."""

    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    domain = models.ForeignKey("targetApp.Domain", on_delete=models.CASCADE, related_name="+")  # the target it was found under
    host = models.CharField(max_length=500)
    state = models.JSONField(default=dict, blank=True)  # see changes.host_state()
    fingerprint = models.CharField(max_length=40, blank=True, default="")  # sha1 of the canonical state
    scan = models.ForeignKey("startScan.ScanHistory", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(default=timezone.now)
    retired_at = models.DateTimeField(null=True, blank=True)
    score = models.IntegerField(default=0)  # mirror of Subdomain.score, so the project-wide ranking needs no per-scan rows
    zombie_since = models.DateTimeField(null=True, blank=True)  # the name is gone from DNS but its last address still answers
    last_alive_check = models.DateTimeField(null=True, blank=True)
    archived_at = models.DateTimeField(null=True, blank=True)
    archive_reason = models.CharField(max_length=300, blank=True, default='')
    archived_by_user = models.BooleanField(default=False)  # a person archived it: only Restore brings it back, never rediscovery
    pinned = models.BooleanField(default=False)
    archive_checked_at = models.DateTimeField(null=True, blank=True)
    archive_check_status = models.CharField(max_length=24, blank=True, default='')
    archive_check_error = models.CharField(max_length=200, blank=True, default='')
    archive_assessment = models.ForeignKey('cveFeed.HostAssessment', on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    inactive_first_absent_at = models.DateTimeField(null=True, blank=True)
    inactive_last_absent_at = models.DateTimeField(null=True, blank=True)
    inactive_absent_checks = models.PositiveSmallIntegerField(default=0)
    # A different streak from inactive_first_absent_at/retired_at: this host is still enumerated every run (it never
    # vanished), but every attempt since unresolved_first_at failed to resolve to a scannable IP (see
    # cveFeed.unresolved_archive). One successful resolution resets all three fields to their defaults.
    unresolved_first_at = models.DateTimeField(null=True, blank=True)
    unresolved_last_at = models.DateTimeField(null=True, blank=True)
    unresolved_checks = models.PositiveSmallIntegerField(default=0, db_default=0)
    resolution_note = models.CharField(max_length=160, blank=True, default='', db_default='')  # why it has no scannable address: 'private address ...' or 'no DNS answer' (unresolved_archive.recheck)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "host"], name="uniq_hoststate_project_host")]
        indexes = [models.Index(fields=["domain", "retired_at"], name="hoststate_domain_retired_idx"),
                   models.Index(fields=["project", "zombie_since"], name="hoststate_proj_zombie_idx"),
                   models.Index(fields=['archived_at', 'retired_at', 'id'], name='hoststate_inactive_idx'),
                   models.Index(fields=['archived_at', 'unresolved_first_at', 'id'], name='hoststate_unresolved_idx'),
                   # the due-host query asks, per host, whether its name was tried and has no address (unresolved_checks >= 1): almost no row is, and
                   # the planner, thinking so few hosts reach that check, scanned the whole table for each of 3000 hosts (0.4 s of a 0.45 s query)
                   models.Index(fields=['project', 'host'], condition=models.Q(unresolved_checks__gte=1), name='hoststate_unresolved_host_idx')]

    def __str__(self):
        return self.host


class HostArchive(models.Model):
    """What the web archive says a host has run (see cveFeed.archive_urls): technologies read from archived URLs. Historical
    evidence for search only, never a current technology. One row per (project, host)."""

    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    domain = models.ForeignKey("targetApp.Domain", on_delete=models.CASCADE, related_name="+")
    host = models.CharField(max_length=500)
    technologies = models.JSONField(default=dict, blank=True)  # {name: {"count": n, "sample": [paths]}}
    tech_text = models.TextField(blank=True, default="")       # the names as flat lowercase text, which search reads
    url_count = models.PositiveIntegerField(default=0)
    checked_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "host"], name="uniq_hostarchive_project_host")]

    def __str__(self):
        return self.host


class RdpScreenshot(models.Model):
    """One RDP login-screen capture (see cveFeed.rdp_shot), only ever attempted against a server nmap's
    rdp-enum-encryption showed accepts a connection without Network Level Authentication. The AI model reads who, if
    anyone, the pre-authentication screen shows signed in. One row per (project, host, port); a later scan replaces it."""

    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    domain = models.ForeignKey("targetApp.Domain", on_delete=models.CASCADE, related_name="+")
    host = models.CharField(max_length=500)
    address = models.CharField(max_length=64)
    port = models.PositiveIntegerField(default=3389)
    image_path = models.CharField(max_length=1000, blank=True, default="")
    image_hash = models.CharField(max_length=16, blank=True, default="")  # cveFeed.shots.dhash_file
    logged_in_user = models.CharField(max_length=300, blank=True, default="")
    ai_summary = models.TextField(blank=True, default="")
    ai_error = models.CharField(max_length=300, blank=True, default="")
    captured_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "host", "port"], name="uniq_rdpshot_project_host_port")]

    def __str__(self):
        return f"{self.host}:{self.port}"


class HostScreenshot(models.Model):
    """The newest capture of one web page (or RDP login screen) of a host: one row per (project, host, scheme, port).

    Written by ``cveFeed.web_shot`` (a real browser, its own stage and queue), never by discovery, so a host's screenshot no longer lives on
    a per-scan ``Subdomain`` row that a rescan replaces. ``outcome`` and ``reason`` say what the last attempt did, so a host with no image
    can say why. A failed attempt keeps the previous image (``image_path``) and ``captured_at`` (the time of the last success); a row that
    is waiting for the capture worker is ``queued``. ``previous_image_path`` is the capture before the current one (the pair a visual diff
    needs); older files are deleted."""

    OUTCOMES = ("queued", "ok", "blank", "timeout", "unreachable", "tls_error", "blocked", "nla_required", "unavailable", "too_big", "error")

    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    domain = models.ForeignKey("targetApp.Domain", on_delete=models.CASCADE, related_name="+")
    host = models.CharField(max_length=500)
    scheme = models.CharField(max_length=8, default="https")  # http, https or rdp
    port = models.PositiveIntegerField(default=443)
    image_path = models.CharField(max_length=1000, blank=True, default="")  # relative to MEDIA_ROOT
    thumb_path = models.CharField(max_length=1000, blank=True, default="")
    image_hash = models.CharField(max_length=16, blank=True, default="")  # cveFeed.shots.dhash_file
    image_bytes = models.PositiveIntegerField(default=0)
    previous_image_path = models.CharField(max_length=1000, blank=True, default="")
    previous_image_hash = models.CharField(max_length=16, blank=True, default="")
    previous_image_bytes = models.PositiveIntegerField(default=0)
    final_url = models.CharField(max_length=2000, blank=True, default="")  # where the page ended up after redirects
    http_status = models.PositiveIntegerField(null=True, blank=True)
    title = models.CharField(max_length=300, blank=True, default="")
    outcome = models.CharField(max_length=16, default="queued")
    reason = models.CharField(max_length=300, blank=True, default="")
    captured_at = models.DateTimeField(null=True, blank=True)  # the last successful capture
    attempted_at = models.DateTimeField(null=True, blank=True)  # the last attempt, success or not
    queued_at = models.DateTimeField(null=True, blank=True)
    by_person = models.BooleanField(default=False)  # a person asked for it: the bug bounty confirmation does not hold it back

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "host", "scheme", "port"], name="uniq_hostshot_project_host_scheme_port")]
        indexes = [models.Index(fields=["project", "outcome"], name="hostshot_project_outcome_idx"),
                   models.Index(fields=["outcome", "queued_at"], name="hostshot_queue_idx")]

    def __str__(self):
        return f"{self.scheme}://{self.host}:{self.port} ({self.outcome})"

    @property
    def has_image(self):
        return bool(self.image_path)


@receiver(post_delete, sender=HostScreenshot)
def _remove_screenshot_files(sender, instance, **kwargs):
    """A row deleted, by a cascade from its project or target or by a purge, takes its picture files with it (never raises)."""
    try:
        from cveFeed import web_shot
        web_shot.remove_row_files(instance)
    except Exception:  # noqa: BLE001 - the weekly sweep removes whatever is left
        pass


class HostAssessment(models.Model):
    """One requested assessment of an inventoried host. Active requests are unique per project and name."""

    project = models.ForeignKey('dashboard.Project', on_delete=models.CASCADE, related_name='+')
    domain = models.ForeignKey('targetApp.Domain', on_delete=models.CASCADE, related_name='+')
    host = models.CharField(max_length=500)
    source = models.CharField(max_length=20, default='manual')
    requested_by = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    status = models.CharField(max_length=16, default='queued')  # queued | running | completed | inconclusive | failed | stopped
    scan = models.ForeignKey('startScan.ScanHistory', on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    celery_id = models.CharField(max_length=100, blank=True, default='')
    result = models.JSONField(default=dict, blank=True)
    error = models.CharField(max_length=300, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=['project', 'status', 'created_at'], name='hostassess_project_idx')]
        constraints = [models.UniqueConstraint(fields=['project', 'host'], condition=models.Q(status__in=['queued', 'running']),
                                           name='one_active_host_assessment')]


class ArchiveRediscovery(models.Model):
    """Daily checkpoint through every archived host, including later pages and retryable errors."""

    day = models.DateField(unique=True)
    status = models.CharField(max_length=16, default='queued')
    cursor_hoststate_id = models.PositiveBigIntegerField(default=0)
    total = models.PositiveIntegerField(default=0)
    checked = models.PositiveIntegerField(default=0)
    reactivated = models.PositiveIntegerField(default=0)
    deferred = models.PositiveIntegerField(default=0)
    errors = models.PositiveIntegerField(default=0)
    lease_until = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)


class InactiveArchiveReview(models.Model):
    """One daily, checkpointed observation pass over retired but unarchived hosts."""

    day = models.DateField(unique=True)
    status = models.CharField(max_length=16, default='queued')
    cursor_hoststate_id = models.PositiveBigIntegerField(default=0)
    total = models.PositiveIntegerField(default=0)
    checked = models.PositiveIntegerField(default=0)
    archived = models.PositiveIntegerField(default=0)
    reactivated = models.PositiveIntegerField(default=0)
    deferred = models.PositiveIntegerField(default=0)
    errors = models.PositiveIntegerField(default=0)
    lease_until = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)


class UnresolvedArchiveReview(models.Model):
    """One daily, checkpointed pass over hosts stuck without a scannable IP (see cveFeed.unresolved_archive): a
    shorter, separate timeline from InactiveArchiveReview's 30-day vanished-from-enumeration case."""

    day = models.DateField(unique=True)
    status = models.CharField(max_length=16, default='queued')
    cursor_hoststate_id = models.PositiveBigIntegerField(default=0)
    total = models.PositiveIntegerField(default=0)
    checked = models.PositiveIntegerField(default=0)
    archived = models.PositiveIntegerField(default=0)
    deferred = models.PositiveIntegerField(default=0)
    errors = models.PositiveIntegerField(default=0)
    lease_until = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)


class AssetChange(models.Model):
    """One observed difference between two snapshots of a host. Append only; pruned after a retention period."""

    KINDS = ("host_new", "host_returned", "host_retired", "port_opened", "port_closed", "service_changed",
             "tech_added", "tech_removed", "tech_version_changed", "cert_changed", "auth_changed", "sensitive_found",
             "zombie_host", "zombie_cleared", "route_retired", "zombie_route", "screenshot_changed")
    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    domain = models.ForeignKey("targetApp.Domain", on_delete=models.CASCADE, related_name="+")
    scan = models.ForeignKey("startScan.ScanHistory", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    host = models.CharField(max_length=500)
    kind = models.CharField(max_length=24)
    ip = models.CharField(max_length=100, blank=True, default="")
    port = models.IntegerField(null=True, blank=True)
    before = models.JSONField(null=True, blank=True)
    after = models.JSONField(null=True, blank=True)
    detected_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-detected_at", "-id"]
        indexes = [
            models.Index(fields=["project", "detected_at"], name="assetchange_proj_at_idx"),
            models.Index(fields=["project", "kind", "detected_at"], name="assetchange_proj_kind_at_idx"),
            models.Index(fields=["project", "host", "detected_at"], name="assetchange_proj_host_at_idx"),
        ]

    def __str__(self):
        return f"{self.kind} {self.host}"


class RouteAuth(models.Model):
    """How one web route answers an anonymous GET: open, a login page, a session requirement (401/403 or a redirect to a
    login), or single sign-on (a redirect to or a page from a known identity provider). Probes are safe GETs with no
    credentials, no cookies, no redirects followed, and at most ROUTE_SAMPLE_BYTES of each body read. When the owner stored a sign-in
    for the target, the same GET is also made with it and answered under ``evidence["authenticated"]`` (cveFeed.auth_routes); the
    state and every other field stay the anonymous answer."""

    STATES = ("open", "login", "session_required", "sso", "redirect", "not_found", "catch_all", "error")  # catch_all: the answer for a path that cannot exist
    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    domain = models.ForeignKey("targetApp.Domain", on_delete=models.CASCADE, related_name="+")
    host = models.CharField(max_length=500)
    url = models.CharField(max_length=2000)
    path = models.CharField(max_length=500)
    auth_state = models.CharField(max_length=20)
    http_status = models.IntegerField(null=True, blank=True)
    redirect_to = models.CharField(max_length=2000, blank=True, default="")
    provider = models.CharField(max_length=100, blank=True, default="")  # SSO vendor when known (Entra ID, Okta, ...)
    title = models.CharField(max_length=300, blank=True, default="")
    evidence = models.JSONField(default=dict, blank=True)  # markers matched, www_authenticate, cookie names, bytes sampled
    # sensitive data seen in the sampled body: {type: {"count", "sample"}} with the sample already masked; never a raw value
    sensitive = models.JSONField(default=dict, blank=True)
    sensitive_score = models.IntegerField(default=0)
    content_type = models.CharField(max_length=100, blank=True, default="")
    retired_at = models.DateTimeField(null=True, blank=True)  # the route once answered and now says not found
    zombie_since = models.DateTimeField(null=True, blank=True)  # a retired route that answers again
    previous_state = models.CharField(max_length=20, blank=True, default="")  # its state before it was retired
    first_seen = models.DateTimeField(auto_now_add=True)
    checked_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "url"], name="uniq_routeauth_project_url")]
        indexes = [models.Index(fields=["project", "auth_state"], name="routeauth_proj_state_idx"),
                   models.Index(fields=["project", "host"], name="routeauth_proj_host_idx"),
                   models.Index(fields=["project", "sensitive_score"], name="routeauth_proj_sens_idx")]

    def __str__(self):
        return f"{self.url} [{self.auth_state}]"


class TriageVerdict(models.Model):
    """One AI answer for a kind of finding, shared by every host that has it (the MatchVerdict idea for every finding kind).

    ``signature`` is the sha1 of the evidence the answer depends on (see cveFeed.triage.signature_for), never a hostname: fifty hosts
    with the same evidence are one question. ``model_classification`` / ``model_reason`` are what the model said; ``classification`` /
    ``reason`` are what the rules kept (they differ when ``overridden``, i.e. hard evidence outranked the model). The model's words may
    quote what the host it was asked about showed (a page title, a certificate, a banner, a path).

    ``project`` and ``host`` record where the answer was reached (the finding the model was asked about). An answer that raises attention is
    reused by every host with the same signature, and so is a needs-validation one where the finding's own question could not do better
    (``triage.answer_reusable``), but only its classification and severity step up: its words are shown only in that project
    (``triage.verdict_text``). A closing one (likely_false_positive, not_applicable) is reused only
    within that project, and for the kinds whose prompt shows host text the signature does not carry (every kind but a CVE match) only on
    that host; elsewhere the finding asks its own question, stored under ``triage.own_candidates`` (task 256). An answer whose origin could not
    be proven (stored before it was recorded: migration 0140) has none: it closes no other finding and its words are shown nowhere."""

    CLASSIFICATIONS = ("confirmed", "likely", "needs_validation", "likely_false_positive", "not_applicable")
    kind = models.CharField(max_length=16)
    signature = models.CharField(max_length=40)
    classification = models.CharField(max_length=24)
    reason = models.TextField(blank=True, default="")
    model_classification = models.CharField(max_length=24, blank=True, default="")
    model_reason = models.TextField(blank=True, default="")
    overridden = models.BooleanField(default=False)  # hard evidence kept the finding above what the model said
    impact = models.TextField(blank=True, default="")
    severity_adjust = models.IntegerField(default=0)  # -1, 0 or +1 step on the 0-4 scale; shown, never written to the finding
    severity_reason = models.TextField(blank=True, default="")
    remediation = models.TextField(blank=True, default="")
    validation_notes = models.JSONField(default=list, blank=True)  # advisory [{kind, note}] from the model, text only
    model = models.CharField(max_length=128, blank=True, default="")
    invalid_output = models.BooleanField(default=False)  # the reply failed validation: stored as needs_validation
    project = models.ForeignKey("dashboard.Project", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")  # where it was reached
    host = models.CharField(max_length=500, blank=True, default="", db_default="")  # db_default: old code still inserting during an update
    created_at = models.DateTimeField(auto_now_add=True)

    objects = models.Manager()

    class Meta:
        constraints = [models.UniqueConstraint(fields=["kind", "signature"], name="uniq_triageverdict_signature")]
        indexes = [models.Index(fields=["created_at"], name="triageverdict_created_idx")]

    def __str__(self):
        return f"{self.kind} {self.signature[:8]} -> {self.classification}"


class ValidationBudget(models.Model):
    """Durable admitted check attempts, independent of mutable freshness rows."""

    day = models.DateField()
    scope = models.CharField(max_length=64)
    reserved = models.PositiveIntegerField(default=0)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['day', 'scope'], name='uniq_validation_budget_day_scope')]


class TriageCall(models.Model):
    """A reserved provider attempt, including errors and crashed workers.

    Admission is serialized in the database before the provider call. A running
    signature has one owner until its lease expires; daily budgets count attempts,
    including provider failures, rather than only saved verdicts.
    """

    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    kind = models.CharField(max_length=16)
    signature = models.CharField(max_length=40)
    status = models.CharField(max_length=12, default="running")
    started_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["project", "started_at"], name="triagecall_project_day_idx"),
                   # who asked for a signature: the origin of a stored answer (migration 0140, cveFeed.verdict_tenancy)
                   models.Index(fields=["signature", "status"], name="triagecall_signature_idx")]
        constraints = [models.UniqueConstraint(fields=["kind", "signature"],
                                               condition=models.Q(status="running"), name="one_running_triage_signature")]


class AIUsage(models.Model):
    """One provider completion attempt; no prompt, response, URL, or credential content."""

    provider = models.CharField(max_length=32)
    model = models.CharField(max_length=200, blank=True, default='')
    actual_model = models.CharField(max_length=200, blank=True, default='')
    stage = models.CharField(max_length=40, default='unspecified')
    status = models.CharField(max_length=12)  # succeeded | failed
    error_category = models.CharField(max_length=40, blank=True, default='')
    stop_reason = models.CharField(max_length=24, blank=True, default='', db_default='')  # the provider's stop reason (end_turn, max_tokens, refusal, ...), never text
    input_tokens = models.PositiveIntegerField(null=True, blank=True)
    output_tokens = models.PositiveIntegerField(null=True, blank=True)
    cache_read_tokens = models.PositiveIntegerField(null=True, blank=True)
    cache_write_tokens = models.PositiveIntegerField(null=True, blank=True)
    duration_ms = models.PositiveIntegerField(null=True, blank=True)
    started_at = models.DateTimeField(default=timezone.now)

    class Meta:
        indexes = [models.Index(fields=['started_at', 'provider', 'model'], name='aiusage_time_model_idx')]


class AIJob(models.Model):
    """One model call the pipeline needs, made by the AI reviewer container (docs/AI-REVIEWER.md, cveFeed.ai_jobs): the server makes no
    model call itself. The server queues the job; the container takes it (``leased``, for a while, with a fresh ``lease`` token), calls
    the model and posts the answer back (``answered``); a Celery task checks the answer with the stage's own validator and applies it
    (``applied``), or queues the stage's one retry (``attempt`` 2), or gives up (``failed``). ``packet`` is what the container gets: the
    stage's fixed system prompt, its parts (text cvENGINE wrote, and fenced data that came from a scanned host or a feed), the schema and
    request options, and at most one bounded image. ``context`` is what the continuation needs and never leaves the server. The raw answer
    is kept only until it is applied. ``dedupe`` keeps one open job per question."""

    OPEN = ("queued", "leased", "answered", "applying")
    kind = models.CharField(max_length=24)
    stage = models.CharField(max_length=40, default="unspecified")  # the usage stage each call is recorded under (AIUsage.stage)
    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, null=True, blank=True, related_name="+")
    dedupe = models.CharField(max_length=80, blank=True, default="")
    priority = models.PositiveSmallIntegerField(default=5)  # lower first
    packet = models.JSONField(default=dict, blank=True)
    context = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=10, default="queued")  # queued | leased | answered | applying | applied | failed | expired
    attempt = models.PositiveSmallIntegerField(default=1)
    leases = models.PositiveSmallIntegerField(default=0)
    lease = models.CharField(max_length=32, blank=True, default="")
    lease_until = models.DateTimeField(null=True, blank=True)
    result = models.JSONField(default=dict, blank=True)  # the answer {text} or the failure {error}, until it is applied
    error_category = models.CharField(max_length=40, blank=True, default="")
    provider = models.CharField(max_length=32, blank=True, default="")
    model = models.CharField(max_length=200, blank=True, default="")
    input_tokens = models.PositiveIntegerField(default=0)
    output_tokens = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    answered_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["status", "priority", "created_at"], name="aijob_queue_idx"),
                   models.Index(fields=["kind", "dedupe"], name="aijob_dedupe_idx")]
        constraints = [models.UniqueConstraint(fields=["kind", "dedupe"], condition=models.Q(status__in=("queued", "leased", "answered", "applying"))
                                               & ~models.Q(dedupe=""), name="one_open_aijob_per_question")]

    def __str__(self):
        return f"AI job {self.pk} ({self.kind}, {self.status})"


class AIPriceRate(models.Model):
    """Operator supplied USD rates; a rate only applies to the exact provider/model."""

    provider = models.CharField(max_length=32)
    model = models.CharField(max_length=200)
    input_per_million_usd = models.DecimalField(max_digits=12, decimal_places=6)
    output_per_million_usd = models.DecimalField(max_digits=12, decimal_places=6)
    cache_read_per_million_usd = models.DecimalField(max_digits=12, decimal_places=6, null=True, blank=True)
    cache_write_per_million_usd = models.DecimalField(max_digits=12, decimal_places=6, null=True, blank=True)
    source_url = models.URLField(max_length=500)
    as_of = models.DateField()
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['provider', 'model'], name='one_ai_price_per_model')]


class DeferredRetest(models.Model):
    """A durable retest episode; equal evidence shares active work, not all future occurrences."""

    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    domain = models.ForeignKey("targetApp.Domain", on_delete=models.CASCADE, related_name="+")
    scan = models.ForeignKey("startScan.ScanHistory", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    host = models.CharField(max_length=500)
    signature = models.CharField(max_length=40)
    status = models.CharField(max_length=12, default="pending")
    attempts = models.IntegerField(default=0)
    next_attempt_at = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["project", "host", "signature"], name="uniq_retest_active_evidence",
                                    condition=models.Q(status__in=["pending", "dispatching", "queued", "running"])),
            models.UniqueConstraint(fields=["project", "host", "signature", "scan"], name="uniq_retest_scan_evidence"),
        ]
        indexes = [models.Index(fields=["status", "created_at"], name="retest_pending_age_idx")]


class Triage(models.Model):
    """The triage of one finding: an AI classification (shared through a TriageVerdict), what CVEngine's own read-only checks
    found when it tried to reproduce it, and when it was first and last seen.

    Exactly one of ``match`` / ``vulnerability`` / ``route`` / ``hygiene`` is set. Triage never deletes, closes or hides a finding:
    a likely_false_positive is still listed. ``classification`` is empty until a verdict exists; with no AI provider configured it
    stays empty (status ``not_triaged``) and can still become ``confirmed`` through a validation hit, which is evidence, not AI."""

    KINDS = ("cve_match", "nuclei", "db_exposure", "route_auth", "hygiene", "bbot")
    STATUSES = ("pending", "triaged", "not_triaged", "error")
    VALIDATION_STATUSES = ("none", "no_check", "pending", "hit", "clean", "observed", "failed", "skipped_blocked")
    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    domain = models.ForeignKey("targetApp.Domain", on_delete=models.CASCADE, null=True, blank=True, related_name="+")
    host = models.CharField(max_length=500, blank=True, default="")
    kind = models.CharField(max_length=16)
    match = models.OneToOneField(CVEMatch, on_delete=models.CASCADE, null=True, blank=True, related_name="triage")
    vulnerability = models.OneToOneField("startScan.Vulnerability", on_delete=models.CASCADE, null=True, blank=True,
                                         related_name="triage")
    route = models.OneToOneField(RouteAuth, on_delete=models.CASCADE, null=True, blank=True, related_name="triage")
    hygiene = models.OneToOneField(HygieneFinding, on_delete=models.CASCADE, null=True, blank=True, related_name="triage")
    signature = models.CharField(max_length=40, blank=True, default="")
    review_nonce = models.CharField(max_length=40, blank=True, default="")  # explicit user-requested fresh AI review
    evidence_key = models.CharField(max_length=40, blank=True, default="")  # the asset evidence alone (triage.evidence_key_for)
    verdict = models.ForeignKey(TriageVerdict, on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    status = models.CharField(max_length=12, default="pending")
    classification = models.CharField(max_length=24, blank=True, default="")
    reason = models.TextField(blank=True, default="")  # why it has this classification (the verdict's, or what validation found)
    hard_evidence = models.JSONField(default=list, blank=True)  # the facts the classification floor was computed from
    validation_status = models.CharField(max_length=16, default="none")
    validation_steps = models.JSONField(default=list, blank=True)  # [{kind, label, display, target, ran_at, result, output_excerpt, error}]
    validation_evidence = models.JSONField(default=dict, blank=True)  # request / response excerpts of a hit, capped; never in a prompt
    # {commands: [{os, command, look_for}], caveat, model, generated_at}: AI-suggested, read-only commands a host owner
    # can run themselves, only generated when validation_status is "no_check" (cveFeed.triage.suggest_local_checks).
    # Unverified by this tool; shown as a suggestion, never as evidence a classification can rest on.
    local_checks = models.JSONField(default=dict, blank=True)
    validated_at = models.DateTimeField(null=True, blank=True)
    attempts = models.IntegerField(default=0)
    next_attempt_at = models.DateTimeField(null=True, blank=True)
    confidence_adjust = models.FloatField(default=0.0)
    # the CVE match this row took its record from when a rescan made a new match for the same finding (cveFeed.triage._twins); its
    # validation jobs are this finding's job history (cveFeed.hot_validation.enqueue). A plain id: the older match may be pruned.
    carried_from = models.PositiveBigIntegerField(null=True, blank=True)
    # A heat a person set by hand (agentapi.services.set_finding_heat): '' or fire, smoke or ice. It wins over the heat cvENGINE derives
    # (cveFeed.threat: match_heat, finding_heat and their database forms) in every list, count, score, report, alert and API, until
    # cleared. Only a CVE match or a scanner finding has one. Triage, re-triage and validation never write these fields; a rescan's new
    # match takes them from its twin (triage._inherited_fields). db_default: old code still inserting rows during an update.
    heat_override = models.CharField(max_length=8, blank=True, default="", db_default="")
    heat_override_reason = models.TextField(blank=True, default="", db_default="")
    heat_override_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    heat_override_at = models.DateTimeField(null=True, blank=True)
    # The newest result of re-checking this finding after it was marked fixed (cveFeed.retest): '' (never marked fixed, or reset when the status
    # changed by hand), verifying, verified_fixed, still_reproduces, not_verified or no_check. The columns sit on the row the lists already join, so a
    # list shows the state with no query of its own. The full record of each try is FixRetest. db_default: old code still inserting rows during an update.
    retest_state = models.CharField(max_length=16, blank=True, default="", db_default="")
    retest_at = models.DateTimeField(null=True, blank=True)
    retest_reason = models.CharField(max_length=300, blank=True, default="", db_default="")
    retest_sentinel = models.CharField(max_length=120, blank=True, default="", db_default="")
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["project", "status"], name="triage_proj_status_idx"),
            models.Index(fields=["project", "classification"], name="triage_proj_class_idx"),
            models.Index(fields=["project", "validation_status", "next_attempt_at"], name="triage_proj_valid_idx"),
            models.Index(fields=["kind", "signature"], name="triage_kind_sig_idx"),
            models.Index(fields=["project", "host"], name="triage_proj_host_idx"),
        ]
        constraints = [
            models.CheckConstraint(
                condition=(models.Q(match__isnull=False, vulnerability__isnull=True, route__isnull=True, hygiene__isnull=True)
                           | models.Q(match__isnull=True, vulnerability__isnull=False, route__isnull=True, hygiene__isnull=True)
                           | models.Q(match__isnull=True, vulnerability__isnull=True, route__isnull=False, hygiene__isnull=True)
                           | models.Q(match__isnull=True, vulnerability__isnull=True, route__isnull=True, hygiene__isnull=False)),
                name="triage_exactly_one_finding"),
        ]

    @property
    def finding(self):
        return self.match or self.vulnerability or self.route or self.hygiene

    def __str__(self):
        return f"{self.kind} {self.host} [{self.classification or self.status}]"


class FixRetest(models.Model):
    """One re-check of a finding that was marked fixed: the same check that produced its proof, run again on a Sentinel through the validation
    dispatch (cveFeed.retest). ``outcome`` is verified_fixed (the check ran and no longer reproduces it), still_reproduces (it does: the finding was
    reopened and ``evidence`` is the new exchange) or not_verified (it could not be told: no Sentinel, host not reachable, the check failed; the
    finding stays fixed, not verified, and is tried again with back-off). Never a result without the time and the Sentinel that ran it."""

    triage = models.ForeignKey('cveFeed.Triage', on_delete=models.CASCADE, related_name='fix_retests')
    project = models.ForeignKey('dashboard.Project', on_delete=models.CASCADE, related_name='+')
    source = models.CharField(max_length=12, default='automatic', db_default='automatic')  # automatic (marked fixed) | manual (Retest now) | retry
    requested_by = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    status = models.CharField(max_length=12, default='queued', db_default='queued')  # queued | running | done | failed
    outcome = models.CharField(max_length=16, blank=True, default='', db_default='')  # verified_fixed | still_reproduces | not_verified
    reason = models.CharField(max_length=300, blank=True, default='', db_default='')
    check_run = models.JSONField(default=dict, blank=True)  # {kind, label, display, target} of the check that was run again
    sentinel = models.CharField(max_length=120, blank=True, default='', db_default='')
    evidence = models.JSONField(default=dict, blank=True)  # summary and the request / response excerpts of the new exchange
    attempts = models.PositiveSmallIntegerField(default=1, db_default=1)
    next_attempt_at = models.DateTimeField(null=True, blank=True)  # a not_verified retest: when it may be tried again; None once given up
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=['project', 'status', 'created_at'], name='fixretest_proj_status_idx'),
                   models.Index(fields=['outcome', 'next_attempt_at'], name='fixretest_due_idx')]
        constraints = [models.UniqueConstraint(fields=['triage'], condition=models.Q(status__in=['queued', 'running']),
                                               name='one_active_fixretest_per_finding')]


class UpdateSettings(models.Model):
    """Single-row state for the GitHub update check: what to watch, what was found, what an admin decided.
    The token is write-only (never returned by the API). Applying an update is done by a host script that
    only acts on an approval written here (see cveFeed/updater.py and scripts/apply-update.sh)."""

    enabled = models.BooleanField(default=True)
    repo = models.CharField(max_length=200, default="hevnsnt/CVEngine")
    branch = models.CharField(max_length=100, default="master")
    token = EncryptedCharField(max_length=ENCRYPTED_COLUMN_LENGTH, blank=True, default="")  # needed for a private repository
    latest_sha = models.CharField(max_length=40, blank=True, default="")
    latest_message = models.CharField(max_length=300, blank=True, default="")
    latest_url = models.CharField(max_length=300, blank=True, default="")
    latest_date = models.DateTimeField(null=True, blank=True)
    behind_by = models.IntegerField(null=True, blank=True)  # commits between the installed version and latest
    reference_unknown = models.BooleanField(default=False, db_default=False)  # GitHub has never seen the installed commit and the host has not named a shared one
    commits = models.JSONField(default=list, blank=True)  # [{sha, message}] newest first, capped
    last_checked_at = models.DateTimeField(null=True, blank=True)
    last_error = models.CharField(max_length=300, blank=True, default="")
    dismissed_sha = models.CharField(max_length=40, blank=True, default="")
    approved_sha = models.CharField(max_length=40, blank=True, default="")
    approved_by = models.CharField(max_length=150, blank=True, default="")
    approved_at = models.DateTimeField(null=True, blank=True)

    @classmethod
    def current(cls):
        return cls.objects.first() or cls.objects.create()


class ScanControl(models.Model):
    """Durable global operator hold. Queued work is retained for resume."""

    paused = models.BooleanField(default=False)
    # Set when cveFeed.scan_control.request_drain_pause (an approved update waiting to drain, see cveFeed.updater)
    # requested this pause, rather than an operator's own "Pause all scanning": only a pause with this set True may be
    # released automatically, by scripts/apply-update.sh once its deploy finishes; an operator's own pause is theirs
    # to lift. A drain pause never calls abort_running_scans: it stops new dispatch and lets active work finish.
    paused_by_update = models.BooleanField(default=False)
    reason = models.CharField(max_length=200, blank=True, default='')
    actor = models.CharField(max_length=150, blank=True, default='')
    last_error = models.CharField(max_length=160, blank=True, default='')
    changed_at = models.DateTimeField(default=timezone.now)
    # An update does not wait for scans that run on Sentinels (cveFeed.scan_control, docs/UPDATES.md). The window of the last update, written by
    # request_drain_pause (``update_started_at``) and release_update_pause (``update_ended_at``, and ``update_grace_until``: how long after it
    # the broker still keeps what the outage left open, so Sentinels that come back with finished work are heard before any lease is judged).
    update_started_at = models.DateTimeField(null=True, blank=True)
    update_ended_at = models.DateTimeField(null=True, blank=True)
    update_grace_until = models.DateTimeField(null=True, blank=True)

    @classmethod
    def current(cls):
        return cls.objects.get_or_create(pk=1)[0]


# --- Bug bounty ----------------------------------------------------------------------------------
# The program catalogue is public data (see cveFeed.bounty_data) and belongs to no project. Engagements and reports belong to one
# project each and are listed in tenancy.scope.SCOPES.

class BountyProgram(models.Model):
    """One bug bounty or disclosure program of a platform, from the public bounty-targets-data dump."""

    PLATFORMS = (("hackerone", "HackerOne"), ("bugcrowd", "Bugcrowd"), ("intigriti", "Intigriti"), ("yeswehack", "YesWeHack"))

    platform = models.CharField(max_length=16, choices=PLATFORMS)
    handle = models.CharField(max_length=200)  # the platform's own identifier of the program
    name = models.CharField(max_length=300)
    url = models.CharField(max_length=500, blank=True, default="")
    offers_bounties = models.BooleanField(null=True, blank=True)  # False: a disclosure program that pays nothing
    min_bounty = models.IntegerField(null=True, blank=True)
    max_bounty = models.IntegerField(null=True, blank=True)
    currency = models.CharField(max_length=8, blank=True, default="")
    safe_harbor = models.CharField(max_length=16, blank=True, default="")  # full, partial or empty (unknown)
    managed = models.BooleanField(default=False)
    state = models.CharField(max_length=32, blank=True, default="")
    response_efficiency = models.IntegerField(null=True, blank=True)  # percent of reports answered (HackerOne)
    first_response_hours = models.FloatField(null=True, blank=True)
    resolved_hours = models.FloatField(null=True, blank=True)
    in_scope_count = models.IntegerField(default=0)
    bounty_scope_count = models.IntegerField(default=0)
    first_seen_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    last_scope_change_at = models.DateTimeField(null=True, blank=True, db_index=True)
    removed_at = models.DateTimeField(null=True, blank=True)  # the platform no longer lists it
    content_hash = models.CharField(max_length=64, blank=True, default="")

    class Meta:
        constraints = [models.UniqueConstraint(fields=["platform", "handle"], name="uniq_bountyprogram_platform_handle")]
        indexes = [models.Index(fields=["platform", "removed_at"], name="bntyprogram_platform_idx")]

    def __str__(self):
        return f"{self.platform}:{self.handle}"


class BountyAsset(models.Model):
    """One in-scope or out-of-scope entry of a program, normalized (see cveFeed.bounty_data.normalize_asset)."""

    KINDS = ("domain", "wildcard", "url", "ip", "cidr", "mobile", "code", "other")

    program = models.ForeignKey(BountyProgram, on_delete=models.CASCADE, related_name="assets")
    kind = models.CharField(max_length=12)
    identifier = models.CharField(max_length=500)  # lowercase host, wildcard, URL, IP or CIDR for the network kinds
    raw_type = models.CharField(max_length=64, blank=True, default="")
    in_scope = models.BooleanField(default=True)
    eligible_for_bounty = models.BooleanField(null=True, blank=True)
    max_severity = models.CharField(max_length=16, blank=True, default="")
    instruction = models.CharField(max_length=1000, blank=True, default="")
    first_seen_at = models.DateTimeField(default=timezone.now)
    removed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["program", "identifier", "raw_type", "in_scope"], name="uniq_bountyasset")]
        indexes = [models.Index(fields=["program", "in_scope", "removed_at"], name="bntyasset_program_idx"),
                   models.Index(fields=["identifier"], name="bntyasset_ident_idx")]


class BountyScopeChange(models.Model):
    """A program or asset appearing, leaving or changing in the public data: the radar that shows new scope first."""

    KINDS = ("program_added", "program_removed", "asset_added", "asset_removed", "asset_flipped")

    program = models.ForeignKey(BountyProgram, on_delete=models.CASCADE, related_name="changes")
    kind = models.CharField(max_length=16)
    asset_kind = models.CharField(max_length=12, blank=True, default="")
    identifier = models.CharField(max_length=500, blank=True, default="")
    in_scope = models.BooleanField(default=True)
    detected_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ["-detected_at", "-id"]


class BountySource(models.Model):
    """The state of one platform's data file: the ETag that makes polling cheap, and when it last changed or failed."""

    platform = models.CharField(max_length=16, unique=True)
    etag = models.CharField(max_length=200, blank=True, default="")
    last_checked = models.DateTimeField(null=True, blank=True)
    last_changed = models.DateTimeField(null=True, blank=True)
    last_error = models.CharField(max_length=300, blank=True, default="")
    programs = models.IntegerField(default=0)
    assets = models.IntegerField(default=0)


class BountyEngagement(models.Model):
    """A project's decision to work one program: the policy acknowledgement, the imported targets and the notes."""

    STATUSES = ("watching", "active", "paused", "done")

    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    program = models.ForeignKey(BountyProgram, on_delete=models.CASCADE, related_name="engagements")
    status = models.CharField(max_length=12, default="watching")
    policy_url = models.CharField(max_length=500, blank=True, default="")
    policy_ack_at = models.DateTimeField(null=True, blank=True)
    policy_ack_by = models.ForeignKey("auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    ack_content_hash = models.CharField(max_length=64, blank=True, default="")  # the program's scope when it was acknowledged
    automated_ok = models.BooleanField(default=False)  # the user confirmed the policy allows automated scanning
    notes = models.TextField(blank=True, default="")
    created_by = models.ForeignKey("auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "program"], name="uniq_bountyengagement_project_program")]


class BountyEngagementTarget(models.Model):
    """A target an engagement imported from the program's scope."""

    engagement = models.ForeignKey(BountyEngagement, on_delete=models.CASCADE, related_name="targets")
    domain = models.ForeignKey("targetApp.Domain", null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    value = models.CharField(max_length=500)
    asset_identifier = models.CharField(max_length=500, blank=True, default="")
    imported_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["engagement", "value"], name="uniq_bountytarget_engagement_value")]


class BountyReport(models.Model):
    """A vulnerability report in the making or on its way: drafted from a finding, edited, submitted, tracked."""

    STATUSES = ("draft", "ready", "submitted", "triaged", "needs_info", "resolved", "duplicate", "informative",
                "not_applicable", "spam", "closed")
    OPEN_STATUSES = ("submitted", "triaged", "needs_info")

    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    engagement = models.ForeignKey(BountyEngagement, null=True, blank=True, on_delete=models.SET_NULL, related_name="reports")
    program = models.ForeignKey(BountyProgram, null=True, blank=True, on_delete=models.SET_NULL, related_name="reports")
    platform = models.CharField(max_length=16)
    program_handle = models.CharField(max_length=200, blank=True, default="")
    program_name = models.CharField(max_length=300, blank=True, default="")
    title = models.CharField(max_length=300)
    status = models.CharField(max_length=16, default="draft")
    severity = models.CharField(max_length=16, blank=True, default="")
    cvss_score = models.FloatField(null=True, blank=True)
    cvss_vector = models.CharField(max_length=120, blank=True, default="")
    cwe = models.CharField(max_length=200, blank=True, default="")
    vrt = models.CharField(max_length=200, blank=True, default="")
    asset = models.CharField(max_length=500, blank=True, default="")
    location_url = models.CharField(max_length=2000, blank=True, default="")
    summary = models.TextField(blank=True, default="")
    steps = models.TextField(blank=True, default="")
    impact = models.TextField(blank=True, default="")
    remediation = models.TextField(blank=True, default="")
    references = models.TextField(blank=True, default="")
    evidence = models.JSONField(default=dict, blank=True)
    checklist = models.JSONField(default=dict, blank=True)
    warnings = models.JSONField(default=list, blank=True)
    finding_kind = models.CharField(max_length=16, blank=True, default="")
    finding_id = models.IntegerField(null=True, blank=True)
    platform_report_id = models.CharField(max_length=64, blank=True, default="")
    platform_url = models.CharField(max_length=500, blank=True, default="")
    submitted_at = models.DateTimeField(null=True, blank=True)
    submitted_by = models.ForeignKey("auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    bounty_amount = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    bounty_currency = models.CharField(max_length=8, blank=True, default="")
    created_by = models.ForeignKey("auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "program", "finding_kind", "finding_id"],
                                               condition=models.Q(finding_id__isnull=False), name="uniq_bountyreport_finding")]
        indexes = [models.Index(fields=["project", "status"], name="bntyreport_proj_status_idx")]
        ordering = ["-updated_at", "-id"]


class BountyReportEvent(models.Model):
    """The timeline of one report: created, edited, status changes, submission, bounty, platform sync."""

    report = models.ForeignKey(BountyReport, on_delete=models.CASCADE, related_name="events")
    kind = models.CharField(max_length=16)
    note = models.CharField(max_length=2000, blank=True, default="")
    actor = models.ForeignKey("auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["at", "id"]


class BountyCredential(models.Model):
    """One user's own account on a bug bounty platform, used only when that user submits a report. It is per user on purpose: a
    report is attributed to the account that sends it, so a shared key would put every report, and every reputation penalty, on one
    person. The token is encrypted at rest and is never returned by the API."""

    user = models.ForeignKey("auth.User", on_delete=models.CASCADE, related_name="+")
    platform = models.CharField(max_length=16)
    username = models.CharField(max_length=200)
    token = EncryptedCharField(max_length=ENCRYPTED_COLUMN_LENGTH)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["user", "platform"], name="uniq_bountycredential_user_platform")]


class StatsSnapshot(models.Model):
    """One project's point-in-time inventory and findings counts for one day, written once daily by
    cveFeed.stats_history.snapshot_all_projects. Trend charts (exposure over time, time-to-fix) need a past this
    schema otherwise has no record of; everything else here is derived live from current rows."""

    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="stats_snapshots")
    date = models.DateField()
    hosts = models.IntegerField(default=0)
    exposed_hosts = models.IntegerField(default=0)
    open_findings = models.JSONField(default=dict, blank=True)  # {critical, high, medium, low, info: n}, actionable set
    cve_matches = models.JSONField(default=dict, blank=True)  # {fire, smoke, ice: n}, actionable (not ruled-out) matches
    fixed = models.IntegerField(default=0)  # findings of any kind currently marked remediation_status=fixed
    mean_days_to_fix = models.FloatField(null=True, blank=True)  # over currently-fixed findings; null when there are none
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "date"], name="uniq_statssnapshot_project_date")]
        indexes = [models.Index(fields=["project", "-date"], name="statssnap_proj_date_idx")]
        ordering = ["-date"]


FINDING_KINDS = ("match", "vulnerability", "hygiene")  # a finding kind with a remediation workflow; same set as agentapi.services.STATUS_KINDS


class FindingComment(models.Model):
    """A free-text note on one finding (a CVEMatch, Vulnerability or HygieneFinding), named generically by
    ``(finding_kind, finding_id)`` rather than three parallel FKs, the same way cveFeed.models.Triage and the activity
    log already address a finding of any kind."""

    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    finding_kind = models.CharField(max_length=16, choices=[(k, k) for k in FINDING_KINDS])
    finding_id = models.PositiveIntegerField()
    author = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    text = models.TextField(max_length=4000)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["project", "finding_kind", "finding_id", "created_at"], name="findingcomment_target_idx"),
                   # the comment count of a findings page names (kind, id) with no project (agentapi.services._comment_count_annotation)
                   models.Index(fields=["finding_kind", "finding_id"], name="findingcomment_kind_id_idx")]
        ordering = ["created_at", "id"]


class FindingAuditEvent(models.Model):
    """One entry of a finding's audit trail: a status change, an assignee change, or a comment, each with who did it,
    when, and (status/assignee) what changed from and to. Written alongside the action itself (agentapi.services),
    never derived after the fact."""

    EVENTS = ("status", "assignee", "comment", "heat", "retest")
    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    finding_kind = models.CharField(max_length=16, choices=[(k, k) for k in FINDING_KINDS])
    finding_id = models.PositiveIntegerField()
    event = models.CharField(max_length=16, choices=[(e, e) for e in EVENTS])
    actor = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    before = models.JSONField(default=dict, blank=True)
    after = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["project", "finding_kind", "finding_id", "-created_at"], name="findingaudit_target_idx")]
        ordering = ["-created_at", "-id"]


DEFAULT_SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}  # days to fix, by severity; info has no SLA


class ProjectSettings(models.Model):
    """Settings that belong to one project and are the same for everyone who works in it, so "overdue" reads the same on
    every screen. One row per project, created on its first write; a project without one uses the defaults."""

    project = models.OneToOneField("dashboard.Project", on_delete=models.CASCADE, related_name="cve_settings")
    sla_days = models.JSONField(default=dict, blank=True)  # only the severities changed from DEFAULT_SLA_DAYS
    # host inventory reports (cveFeed.host_inventory): whether a report from a host nobody scans yet may add it to the project (off:
    # it waits for an administrator to adopt it), and how old a report may get before it stops creating findings
    inventory_create_hosts = models.BooleanField(default=False, db_default=False)
    inventory_stale_days = models.PositiveSmallIntegerField(default=14, db_default=14)
    # opt-in secret validation (cveFeed.secrets_validation): read-only identity checks of found credentials, by the built-in scanner only, never for a
    # project in a bug bounty engagement. Who switched it on, when, and the attestation they accepted, word for word
    secrets_validation = models.BooleanField(default=False, db_default=False)
    secrets_validation_by = models.ForeignKey("auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    secrets_validation_at = models.DateTimeField(null=True, blank=True)
    secrets_validation_attestation = models.TextField(blank=True, default="", db_default="")
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey("auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="+")

    @classmethod
    def sla_for(cls, project):
        """The effective {severity: days} of ``project``: the defaults with its own overrides on top."""
        row = cls.objects.filter(project=project).first()
        return {**DEFAULT_SLA_DAYS, **{k: v for k, v in ((row.sla_days if row else None) or {}).items() if k in DEFAULT_SLA_DAYS}}


class RunZeroSync(models.Model):
    """The runZero integration of one project (cveFeed.runzero_sync): whether unknown runZero addresses are imported as targets, which
    runZero search limits that, and how the last sync went. One row per project, created when first needed. The token itself is an
    ApiCredential; nothing here is secret."""

    DEFAULT_SEARCH = "alive:true"
    project = models.OneToOneField("dashboard.Project", on_delete=models.CASCADE, related_name="runzero_sync")
    import_enabled = models.BooleanField(default=False)
    search = models.CharField(max_length=300, default=DEFAULT_SEARCH)  # runZero inventory search that limits what is imported
    status = models.CharField(max_length=10, blank=True, default="")
    started_at = models.DateTimeField(null=True, blank=True)  # when the current or last run began (a stale "running" is not honoured)
    last_sync_at = models.DateTimeField(null=True, blank=True)  # when the last run finished, whether it worked or not
    last_ok_at = models.DateTimeField(null=True, blank=True)
    last_error = models.CharField(max_length=300, blank=True, default="")
    counts = models.JSONField(default=dict, blank=True)  # what the last good run did: assets, matched_hosts, imported, skipped ...
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"runZero sync for {self.project_id}"


class CVEDetection(models.Model):
    """How to tell whether a product is affected by one CVE: remote checks and checks on the host itself, as data
    (cveFeed.detection). One row per CVE, shared by every organization: it describes the CVE, never a project's assets."""

    SOURCES = ("rules", "ai", "manual")

    cve_entry = models.OneToOneField(CVEEntry, on_delete=models.CASCADE, related_name="detection")
    schema_version = models.PositiveSmallIntegerField(default=1)
    source = models.CharField(max_length=8, default="rules")  # who wrote the newest checks: rules | ai | manual
    strategy = models.JSONField(default=dict, blank=True)  # {} until the record supports a check
    rules_at = models.DateTimeField(null=True, blank=True)  # when the rules author last read the CVE's affected data
    ai_model = models.CharField(max_length=128, blank=True, default="")
    ai_attempted_at = models.DateTimeField(null=True, blank=True)  # the model is asked once; a failed ask is retried after a week
    ai_problems = models.JSONField(default=list, blank=True)  # what validation dropped from the model's answer, or why the model could not be asked
    ai_failures = models.PositiveSmallIntegerField(default=0, db_default=0)  # failed asks in a row (cveFeed.detection_author.AI_BACKOFF); 0 after an answer
    ai_retry_at = models.DateTimeField(null=True, blank=True)  # the back-off: not asked again before this; None with failures at the limit means given up
    ai_input_hash = models.CharField(max_length=16, blank=True, default="", db_default="")  # what the CVE said when the model last read it: a change re-asks
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "CVE detection"
        verbose_name_plural = "CVE detections"
        indexes = [models.Index(fields=["ai_attempted_at"], name="cvedetect_ai_idx"),
                   # ``detection_author.progress``: the detections that have checks, counted by source, without reading the ``strategy`` JSON of every row
                   models.Index(fields=["source", "id"], name="cvedetection_source_filled_idx", condition=~models.Q(strategy={}))]

    def __str__(self):
        return f"detection for {self.cve_entry_id}"


class SavedSearch(models.Model):
    """A host search (the Hosts page / ``search_hosts`` syntax) a person keeps and, optionally, is alerted about. Private to its
    owner, inside one project. The evaluator (cveFeed.saved_searches) re-runs due searches with the owner's own access and keeps
    ``matched`` (host key hash -> host name, one entry per host, aliases of one machine counted once) to tell new matches from old."""

    FREQUENCIES = {"hourly": 60, "daily": 24 * 60, "weekly": 7 * 24 * 60}  # minutes between evaluations
    CHANNELS = ("slack", "discord", "telegram", "lark")
    MAX_PER_USER, MAX_PER_PROJECT = 25, 100
    MAX_NAME, MAX_QUERY, MAX_MATCHES = 80, 1000, 1000  # a search with more matches than MAX_MATCHES is too broad to watch

    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE, related_name="+")
    name = models.CharField(max_length=MAX_NAME)
    query = models.CharField(max_length=MAX_QUERY)
    enabled = models.BooleanField(default=True)  # evaluated on schedule; off after the owner loses access, until they switch it on again
    alert_new = models.BooleanField(default=True)  # a host starts to match
    alert_gone = models.BooleanField(default=False)  # a host stops matching
    threshold = models.PositiveIntegerField(null=True, blank=True)  # the match count reaches this (once per crossing)
    channels = models.JSONField(default=list, blank=True)  # subset of CHANNELS; empty means every channel Settings has on
    frequency = models.CharField(max_length=8, default="daily")
    next_run_at = models.DateTimeField(default=timezone.now)
    last_run_at = models.DateTimeField(null=True, blank=True)
    last_alert_at = models.DateTimeField(null=True, blank=True)
    last_match_count = models.PositiveIntegerField(default=0)
    last_status = models.CharField(max_length=12, blank=True, default="")  # ok | too_broad | error | disabled
    last_error = models.CharField(max_length=200, blank=True, default="")
    baseline_at = models.DateTimeField(null=True, blank=True)  # null until the first evaluation, which alerts nothing
    matched = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "owner", "name"], name="uniq_savedsearch_project_owner_name")]
        indexes = [models.Index(fields=["enabled", "next_run_at"], name="savedsearch_due_idx"),
                   models.Index(fields=["owner", "project"], name="savedsearch_owner_proj_idx")]
        ordering = ["name", "id"]

    def __str__(self):
        return f"{self.name}: {self.query}"


class TailscaleLink(models.Model):
    """A tailnet an administrator connected to one project (see cveFeed.tailscale_sync): its devices become that project's targets.
    One link per project. The credentials are encrypted like every other stored secret and never leave the server; the settings
    page and the API say only whether they are set. Connecting is what authorises scanning the tailnet's addresses for this
    project's imported devices (cveFeed.tailscale_scope)."""

    project = models.OneToOneField("dashboard.Project", on_delete=models.CASCADE, related_name="tailscale_link")
    enabled = models.BooleanField(default=True)
    credentials = EncryptedJSONField(default=dict, blank=True)  # {"access_token"} or {"client_id", "client_secret"}
    use_local = models.BooleanField(default=True)  # also read this server's own tailscaled (the sidecar) for status and peers
    ROUTING_CHOICES = (("auto", "this server's tailscale sidecar"), ("host", "already routed (the Docker host is on the tailnet)"))
    routing = models.CharField(max_length=8, choices=ROUTING_CHOICES, default="auto")  # how scans reach the tailnet; "host" is the operator's word
    scan_reachable = models.BooleanField(default=False)  # the scanner can reach this tailnet (checked at each sync); only then may its devices be scanned
    auto_scan = models.BooleanField(default=False)  # queue the normal pipeline for new and changed devices
    max_devices = models.PositiveIntegerField(default=100)  # most devices one sync imports or queues; the rest follow on the next run
    only_tags = models.JSONField(default=list, blank=True)  # import only devices carrying one of these tags (empty: any)
    skip_tags = models.JSONField(default=list, blank=True)  # never import devices carrying one of these tags
    only_os = models.JSONField(default=list, blank=True)  # import only these operating systems (empty: any)
    check_policy = models.BooleanField(default=True)  # read the tailnet policy file for the tailnet-wide findings
    tailnet_name = models.CharField(max_length=200, blank=True, default="")
    device_count = models.PositiveIntegerField(default=0)
    last_sync_at = models.DateTimeField(null=True, blank=True)
    last_status = models.CharField(max_length=12, default="never")  # never | ok | partial | error
    last_error = models.CharField(max_length=300, blank=True, default="")
    local_state = models.JSONField(default=dict, blank=True)  # what this server's own tailscaled reported at the last sync
    anchor_domain = models.ForeignKey("targetApp.Domain", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")  # carries the tailnet-wide findings
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")

    def __str__(self):
        return f"tailnet of project {self.project_id}"


class TailscaleDevice(models.Model):
    """One device of a linked tailnet and what Tailscale said about it at the last sync. ``domain`` is the target the device became
    (named by its tailnet IPv4 address, which every scanner already handles); ``facts`` is the clipped, typed record. A device that
    left the tailnet keeps its row with ``departed_at`` set, so its findings and history stay and its address stops being scannable."""

    link = models.ForeignKey(TailscaleLink, on_delete=models.CASCADE, related_name="devices")
    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    node_id = models.CharField(max_length=80)  # Tailscale's stable node id (the API's nodeId or id; the public key from a local status)
    domain = models.ForeignKey("targetApp.Domain", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    name = models.CharField(max_length=300, blank=True, default="")  # MagicDNS name without the trailing dot, else the hostname
    addresses = models.JSONField(default=list, blank=True)  # tailnet IPs only (100.64.0.0/10, fd7a:115c:a1e0::/48)
    online = models.BooleanField(default=False)
    facts = models.JSONField(default=dict, blank=True)
    fingerprint = models.CharField(max_length=40, blank=True, default="")  # of the facts that matter for scanning, to spot a changed device
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)  # the last sync that listed it
    departed_at = models.DateTimeField(null=True, blank=True)
    scan_queued_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["link", "node_id"], name="uniq_tailscaledevice_link_node")]
        indexes = [models.Index(fields=["project", "departed_at"], name="tsdevice_proj_departed_idx")]

    def __str__(self):
        return self.name or self.node_id


class HostInventory(models.Model):
    """The latest report one machine sent about itself (cveFeed.host_inventory): what the on-host reporter script found, which an
    external scan cannot see. One row per (project, machine); ``host`` is the name of the project's host it was matched to (lowercase,
    like HostProfile), empty while the report is unmatched and waiting for an administrator. The package list is kept compact
    (``[{n, v, e, a, s}]``); older reports are summarised in HostInventoryReport."""

    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    key = models.CharField(max_length=300)  # the machine's app-specific id hash, else "h:" plus its lowercase host name
    host = models.CharField(max_length=500, blank=True, default="")
    match_basis = models.CharField(max_length=12, blank=True, default="")  # ip | name | adopted | "" (unmatched)
    hostname = models.CharField(max_length=255, blank=True, default="")
    fqdn = models.CharField(max_length=255, blank=True, default="")
    ips = models.JSONField(default=list, blank=True)
    os_family = models.CharField(max_length=16, blank=True, default="")  # linux | windows | macos
    os_name = models.CharField(max_length=120, blank=True, default="")
    os_version = models.CharField(max_length=60, blank=True, default="")
    os_build = models.CharField(max_length=60, blank=True, default="")
    os_kernel = models.CharField(max_length=80, blank=True, default="")
    os_arch = models.CharField(max_length=20, blank=True, default="")
    os_info = models.JSONField(default=dict, blank=True)  # the whole validated os block (id, pretty name, last boot and update, ...)
    packages = models.JSONField(default=list, blank=True)
    package_count = models.PositiveIntegerField(default=0)
    patches = models.JSONField(default=list, blank=True)
    services = models.JSONField(default=list, blank=True)  # listening sockets
    details = models.JSONField(default=dict, blank=True)  # runtime (reboot, containers, units) and security posture
    script_name = models.CharField(max_length=40, blank=True, default="")
    script_version = models.CharField(max_length=20, blank=True, default="")
    collected_at = models.DateTimeField(null=True, blank=True)  # the host's own clock
    reported_at = models.DateTimeField(default=timezone.now)  # ours: staleness is judged on this one
    token_id = models.PositiveBigIntegerField(null=True, blank=True)  # which token sent it (kept after the token is deleted)
    source_ip = models.CharField(max_length=64, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "key"], name="uniq_hostinventory_project_key")]
        indexes = [models.Index(fields=["project", "host"], name="hostinv_project_host_idx")]

    def __str__(self):
        return f"{self.hostname or self.key}: {self.os_name} {self.os_version}".strip()


class HostInventoryReport(models.Model):
    """One report of a HostInventory, summarised (never the whole package list): when, what changed since the one before and how big.
    Trimmed to the newest ``host_inventory.HISTORY_KEEP`` per machine."""

    inventory = models.ForeignKey(HostInventory, on_delete=models.CASCADE, related_name="history")
    reported_at = models.DateTimeField()
    script_version = models.CharField(max_length=20, blank=True, default="")
    os_summary = models.CharField(max_length=200, blank=True, default="")
    package_count = models.PositiveIntegerField(default=0)
    changes = models.JSONField(default=dict, blank=True)  # {added, removed, changed: counts, names: [first few], os_changed: bool}

    class Meta:
        ordering = ["-reported_at", "-id"]


class AuthCredential(models.Model):
    """Request headers and a cookie the owner supplied for a target they may test, so Nuclei and the web route check see the signed-in
    application and not only its login page (see cveFeed.auth_checks). One row per target and host: ``host`` names the one host it is
    for, or is blank for every host of the target (the target's own name and its subdomains). ``origins`` lists the ``scheme:port`` pairs it
    may be sent to; nothing else is covered. The header and cookie values are encrypted at rest and never returned by any read: only
    the header names are shown. Past ``expires_at`` it is not sent."""

    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    domain = models.ForeignKey("targetApp.Domain", on_delete=models.CASCADE, related_name="auth_credentials")
    host = models.CharField(max_length=300, blank=True, default="")
    label = models.CharField(max_length=80)
    origins = models.JSONField(default=list)  # ["https:443"]: the only scheme and port pairs the values may be sent to
    secret = EncryptedJSONField(default=dict)  # {"headers": [[name, value], ...], "cookie": "a=b; c=d"}
    expires_at = models.DateTimeField(null=True, blank=True)
    # The owner's choice, per target: send the values over a TLS connection whose certificate does not verify (self-signed, expired, wrong name).
    # Off by default: then a sign-in goes only to a server that proves its name, and anyone in the network path could read it otherwise.
    allow_untrusted_certificate = models.BooleanField(default=False, db_default=False)
    updated_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    last_used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["domain", "host"], name="uniq_authcredential_domain_host")]
        indexes = [models.Index(fields=["project"], name="authcred_project_idx")]

    def __str__(self):
        return f"{self.label} for {self.host or self.domain_id}"


class ReportExport(models.Model):
    """One requested PDF report (cveFeed.report_export): who asked for what, how it went, and the random file name it was written to.

    The file lives under the report directory and is served only by an authenticated view to the user who asked, until ``expires_at``.
    ``token`` is the id a client sees; ``filename`` is a second random value that never leaves the server."""

    STATUSES = ("queued", "running", "done", "failed")
    token = models.CharField(max_length=64, unique=True)
    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    requested_by = models.ForeignKey("auth.User", on_delete=models.CASCADE, related_name="+")
    host = models.CharField(max_length=500, blank=True, default="")  # empty: the whole project
    include_closed = models.BooleanField(default=False)  # also list fixed and accepted-risk findings
    status = models.CharField(max_length=10, default="queued")
    filename = models.CharField(max_length=80, blank=True, default="")
    size_bytes = models.PositiveBigIntegerField(default=0)
    summary = models.JSONField(default=dict, blank=True)  # what the report holds and what the caps left out
    error = models.CharField(max_length=200, blank=True, default="")
    celery_id = models.CharField(max_length=64, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()

    class Meta:
        indexes = [models.Index(fields=["status", "expires_at"], name="reportexport_status_exp_idx"),
                   models.Index(fields=["requested_by", "created_at"], name="reportexport_user_created_idx")]
        ordering = ["-id"]

    def __str__(self):
        return f"report {self.pk} {self.project_id} {self.host or 'project'} [{self.status}]"


class OpenvasSettings(models.Model):
    """Single-row state of the optional OpenVAS (Greenbone) add-on (see cveFeed.openvas_scan): the App Admin's switch, the GMP login of the
    sidecar and what the worker last saw of it. Off by default; while it is off nothing contacts the sidecar and the beat task is disabled.
    The password is encrypted like every other stored secret and never leaves the server: the settings page says only whether it is set."""

    enabled = models.BooleanField(default=False)
    sentinel_only = models.BooleanField(default=False)  # no longer read: OpenVAS only ever runs on a Sentinel (a due batch with no eligible Sentinel stays due)
    gmp_username = models.CharField(max_length=64, blank=True, default="")
    gmp_password = EncryptedCharField(max_length=ENCRYPTED_COLUMN_LENGTH, blank=True, default="")
    state = models.JSONField(default=dict, blank=True)  # the worker's last check: {checked_at, connected, gmp_version, error, feed: {...}}
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")

    @classmethod
    def current(cls):
        return cls.objects.first() or cls.objects.create()

    def __str__(self):
        return f"OpenVAS add-on ({'on' if self.enabled else 'off'})"


class ScanConcurrency(models.Model):
    """Single-row scan concurrency chosen on Settings, configMaxxing (see cveFeed.scan_concurrency): ``values`` maps a setting key (``heavy.nmap``,
    ``discovery_concurrency``, ``work_depth``) to the whole number an App Admin chose, and ``meta`` to who chose it and when. A key that is
    absent was never set (or was reset), so the environment variable, then the built-in default, applies. The row is the durable truth; the
    workers read a copy published to Redis (a few seconds old at most) so that admission never waits on the database."""

    values = models.JSONField(default=dict, blank=True)
    meta = models.JSONField(default=dict, blank=True)  # {key: {"by": username, "at": iso time}}
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")

    @classmethod
    def current(cls):
        return cls.objects.order_by("pk").first() or cls.objects.create()

    def __str__(self):
        return f"scan concurrency ({len(self.values)} set)"


class TunableSettings(models.Model):
    """Single-row store of the advanced tunables chosen on Settings, configMaxxing (see cveFeed.tunables): ``values`` maps a tunable's key
    (``triage_max_per_day``, ``stage_parallel`` ...) to the whole number an App Admin chose, and ``meta`` to who chose it and when. A key that
    is absent was never set (or was reset), so the environment variable, then the built-in default, applies. One row for every tunable, so
    another tunable is one registry entry and no migration. The row is the durable truth; the processes that read a tunable use a copy that is
    published to Redis (a few seconds old at most). It belongs to the instance, not to a project or an organization."""

    values = models.JSONField(default=dict, blank=True)
    meta = models.JSONField(default=dict, blank=True)  # {key: {"by": username, "at": iso time}}
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")

    @classmethod
    def current(cls):
        return cls.objects.order_by("pk").first() or cls.objects.create()

    def __str__(self):
        return f"tunables ({len(self.values)} set)"


class AutoTuneSettings(models.Model):
    """Single-row auto-tuning state of Settings, configMaxxing (see cveFeed.autotune): the mode (``off``, ``suggest`` or ``auto``, the default),
    whether the AI advisor may be asked, and ``values``: the numbers the tuner chose for the settings it manages, ``{key: whole number}``. A
    number here is used only while the mode is ``auto`` (and ``CVENGINE_AUTOTUNE`` is not ``0``), and only for a setting no person saved a value
    for: a saved value pins its setting and always wins. Instance-wide, like the settings it tunes."""

    MODES = ("off", "suggest", "auto")
    mode = models.CharField(max_length=10, default="auto")
    advisor = models.BooleanField(default=True)  # ask the AI advisor when a provider is configured
    values = models.JSONField(default=dict, blank=True)
    meta = models.JSONField(default=dict, blank=True)  # {key: {"hold_until": iso time}}
    changed_at = models.DateTimeField(null=True, blank=True)  # the last change of the mode or the advisor switch, by a person
    changed_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    updated_at = models.DateTimeField(auto_now=True)

    @classmethod
    def current(cls):
        return cls.objects.order_by("pk").first() or cls.objects.create()

    def __str__(self):
        return f"auto-tuning ({self.mode}, {len(self.values)} tuned)"


class TuningDecision(models.Model):
    """One change, or one recommendation, of a setting the auto-tuner manages (cveFeed.autotune): who proposed it (the controller, the AI
    advisor, or a person applying or reverting one), the number before and after, the reason in one sentence and the measurements it read
    (numbers only). ``applied`` is False for a recommendation that changed nothing (Suggest mode). ``layer`` says where an applied number went:
    ``auto`` (the tuner's own numbers) or ``saved`` (a person applied it, which pins the setting). Kept ``RETENTION_DAYS`` (cveFeed.autotune)."""

    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    setting = models.CharField(max_length=64)
    old_value = models.IntegerField(null=True, blank=True)
    new_value = models.IntegerField(null=True, blank=True)
    mode = models.CharField(max_length=10)
    source = models.CharField(max_length=12)  # controller | ai | person
    action = models.CharField(max_length=12)  # raise | lower | apply | revert | release
    layer = models.CharField(max_length=8, blank=True, default="")  # auto | saved | "" for a recommendation
    old_layer_value = models.IntegerField(null=True, blank=True)  # what that layer held before (None: nothing), so a revert restores it exactly
    applied = models.BooleanField(default=False)
    pressure = models.BooleanField(default=False)  # a back-off forced by trouble (memory, database, worker, Sentinel time-outs)
    phase = models.CharField(max_length=12, blank=True, default="")  # aim_high | back_off | cap | probe | emergency | recover | "" (a person, or a calm change)
    reason = models.CharField(max_length=300, blank=True, default="")
    signals = models.JSONField(default=dict, blank=True)
    actor = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    resolved_at = models.DateTimeField(null=True, blank=True)  # a recommendation applied or replaced, or a change reverted
    resolved_by = models.CharField(max_length=150, blank=True, default="")
    resolution = models.CharField(max_length=12, blank=True, default="")  # applied | superseded | reverted

    class Meta:
        indexes = [models.Index(fields=["setting", "created_at"], name="tuning_setting_time_idx")]

    def __str__(self):
        return f"{self.setting} {self.old_value}->{self.new_value} ({self.source})"


class SmtpSettings(models.Model):
    """Single-row outgoing mail server (Settings, Email; see cveFeed.mailer). Off by default: with it off, or with no address on the
    account, adding a person shows a temporary password as it always did. The password is encrypted like every other stored secret and
    never leaves the server: the settings page says only whether it is set."""

    SECURITY_CHOICES = (("starttls", "STARTTLS"), ("ssl", "SSL/TLS"), ("none", "None"))

    enabled = models.BooleanField(default=False)
    host = models.CharField(max_length=255, blank=True, default="")
    port = models.PositiveIntegerField(default=587)
    security = models.CharField(max_length=8, choices=SECURITY_CHOICES, default="starttls")
    username = models.CharField(max_length=255, blank=True, default="")
    password = EncryptedCharField(max_length=ENCRYPTED_COLUMN_LENGTH, blank=True, default="")
    from_address = models.CharField(max_length=254, blank=True, default="")
    from_name = models.CharField(max_length=100, blank=True, default="")
    verify_certificate = models.BooleanField(default=True)  # off only for a relay with a private or self-signed certificate
    link_base = models.CharField(max_length=200, blank=True, default="")  # the address links in a message start with; empty: https://DOMAIN_NAME
    state = models.JSONField(default=dict, blank=True)  # the last test send: {at, ok, to, error}
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")

    @classmethod
    def current(cls):
        return cls.objects.first() or cls()

    def __str__(self):
        return f"Outgoing mail ({'on' if self.enabled else 'off'})"


class OpenvasProject(models.Model):
    """A project's opt-in to OpenVAS scanning. Off by default. The project's hosts that are Fire or Smoke are scanned by themselves; ``hosts`` (each
    one already a host of the project) adds hosts someone named, still gated by heat unless the host is also in ``forced_hosts``. ``target_id`` is the GVM target last made for this host set, kept
    so an unchanged set reuses it."""

    project = models.OneToOneField("dashboard.Project", on_delete=models.CASCADE, related_name="openvas_link")
    enabled = models.BooleanField(default=False)
    hosts = models.JSONField(default=list, blank=True)
    forced_hosts = models.JSONField(default=list, blank=True)  # the listed hosts an administrator chose to scan whatever their heat (OpenVAS otherwise only scans Fire or Smoke)
    # An explicit "not this project" that wins over the organization's opt-in (``OpenvasOrg``); ``enabled`` (the project's own opt-in) wins over this.
    excluded = models.BooleanField(default=False, db_default=False)
    target_id = models.CharField(max_length=40, blank=True, default="")
    target_key = models.CharField(max_length=64, blank=True, default="")  # hash of the address set the target was made for
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")

    def __str__(self):
        return f"OpenVAS opt-in of project {self.project_id}"


class OpenvasOrg(models.Model):
    """An organization's opt-in to OpenVAS scanning: every project of the organization (the ones it has now and the ones it gets later) is
    scanned, through the same gate as a single opted-in project. An Org Admin or an App Admin sets it; nothing outside the chosen organizations
    is scanned."""

    org = models.OneToOneField("dashboard.Org", on_delete=models.CASCADE, related_name="openvas_link")
    enabled = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")

    def __str__(self):
        return f"OpenVAS opt-in of organization {self.org_id}"


class OpenvasRun(models.Model):
    """One GVM task cvENGINE started: the batch of hosts it covers, where it stands and what its import found. At most one is ``running``
    at a time (the constraint), which is how the sweep stays one task at a time even across workers and restarts."""

    STATUSES = ("running", "done", "failed", "stopped")
    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    status = models.CharField(max_length=10, default="running")
    sentinel_task = models.ForeignKey("agentapi.SentinelTask", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    # Null: cvENGINE ran this against its own sidecar. Set: a Sentinel ran it against its own, and this row only tracks the
    # hand-off and the imported result - see cveFeed.openvas_scan.dispatch_to_sentinel / poll_sentinel.
    task_id = models.CharField(max_length=40, blank=True, default="")
    target_id = models.CharField(max_length=40, blank=True, default="")
    gvm_status = models.CharField(max_length=30, blank=True, default="")  # the task's own status: New, Requested, Queued, Running, Done ...
    progress = models.IntegerField(default=0)
    hosts = models.JSONField(default=dict, blank=True)  # {address: host name the results are stored under}
    summary = models.JSONField(default=dict, blank=True)  # what the import did: results, findings, evidence, resolved, skipped
    error = models.CharField(max_length=300, blank=True, default="")
    started_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["status"], condition=models.Q(status="running"), name="uniq_openvasrun_one_running")]
        ordering = ["-id"]

    def __str__(self):
        return f"OpenVAS run {self.pk} ({self.status})"


class Supplier(models.Model):
    """A third party a project depends on and cannot fix for itself (cveFeed.supplier_scan). It is NOT an owned host: it never becomes a
    target, host or scan input, and nothing the owned-asset flows do (discovery, port scans, assessments, remediation, SLA clocks, stats)
    reads this table. ``domains`` are the exact names that are checked, never expanded. The checks are passive and polite, run weekly at
    most per supplier, and store their results as ``SupplierFinding`` rows."""

    TIERS = ("critical", "high", "normal")
    TIER_CHOICES = [(t, t) for t in TIERS]
    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="suppliers")
    name = models.CharField(max_length=120)
    tier = models.CharField(max_length=10, choices=TIER_CHOICES, default="normal")
    domains = models.JSONField(default=list, blank=True)  # the exact names to check: lowercase, validated, never wildcards
    contact = models.CharField(max_length=300, blank=True, default="")  # who to write to (free text)
    notes = models.TextField(blank=True, default="")
    added_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_checked_at = models.DateTimeField(null=True, blank=True)  # when a sweep last got an answer for this supplier

    class Meta:
        ordering = ["name"]
        constraints = [models.UniqueConstraint(Lower("name"), "project", name="uniq_supplier_project_name")]

    def __str__(self):
        return f"{self.name} ({self.tier})"


class SupplierHostCard(models.Model):
    """The Shodan-style card of one supplier domain: what its public services say about themselves, as of the last check. One row per
    (supplier, domain), refreshed by each sweep. A section the last check could not read (the certificate, the web page) keeps what the
    check before it saw, and ``checked_at`` says when the card was last attempted. Everything here is what a browser or a TLS client is
    given anyway: response headers (never cookies' values), the certificate, the technologies the page and its headers state (the same
    fingerprinting owned hosts use, ``cvengine_scanner.fingerprint``), and the address and mail facts. ``tech_text`` is the lowercase text the
    technology search reads."""

    STATES = ("ok", "no_address", "blocked", "unreachable", "challenged", "excluded")
    supplier = models.ForeignKey(Supplier, on_delete=models.CASCADE, related_name="cards")
    domain = models.CharField(max_length=255)
    state = models.CharField(max_length=12, default="ok")
    addresses = models.JSONField(default=list, blank=True)  # the public addresses the name resolved to
    http = models.JSONField(default=dict, blank=True)  # status of the front page over https and http, title, server, powered_by, raw response headers
    tls = models.JSONField(default=dict, blank=True)  # subject, issuer, SANs, validity, key, signature, protocol, cipher, chain error
    technologies = models.JSONField(default=list, blank=True)  # [{name, version, category, source}]
    tech_text = models.TextField(blank=True, default="")
    mail = models.JSONField(default=dict, blank=True)  # whether the name handles mail, and its MX records
    evidence = models.JSONField(default=dict, blank=True)  # edge in front, challenge, DNS state, notes: whatever else explains the card
    checked_at = models.DateTimeField(null=True, blank=True)
    last_ok_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["supplier__name", "domain"]
        constraints = [models.UniqueConstraint(fields=["supplier", "domain"], name="uniq_supplierhostcard_domain")]

    def __str__(self):
        return f"{self.domain} ({self.state})"


class SupplierFinding(models.Model):
    """One thing a supplier's public face got wrong, as seen from outside: a "supplier posture" item. One row per (supplier, domain,
    check). ``status`` is ``open`` while the check still finds it, ``resolved`` (by the sweep) when a later check no longer does, and
    ``accepted`` when an admin decided to live with it (the sweep then only refreshes its evidence), or ``false_positive`` when an admin found
    the check got it wrong (the sweep leaves it as it is: never resolved, so never reopened). ``status_note`` says why, ``status_by`` and
    ``status_at`` who and when. ``ask`` says what to ask the supplier. Never validated by exploitation: nothing here is ever tested beyond
    what the supplier's service announces."""

    STATUSES = ("open", "accepted", "false_positive", "resolved")  # cveFeed.closure.SUPPLIER_STATUSES
    supplier = models.ForeignKey(Supplier, on_delete=models.CASCADE, related_name="findings")
    domain = models.CharField(max_length=255)
    check_name = models.CharField(max_length=60)
    category = models.CharField(max_length=12, default="")  # tls | email | web | cve
    severity = models.IntegerField(default=0)  # 0 info .. 4 critical, the same scale as hygiene findings
    title = models.CharField(max_length=300)
    detail = models.TextField(blank=True, default="")
    ask = models.TextField(blank=True, default="")  # plain text: what to ask the supplier to do or confirm
    evidence = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=16, default="open")
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    resolved_at = models.DateTimeField(null=True, blank=True)
    status_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    status_note = models.CharField(max_length=2000, blank=True, default="")
    status_at = models.DateTimeField(null=True, blank=True)  # when a person last set the status (None before 1.3.3, or never set)

    class Meta:
        ordering = ["-severity", "domain", "check_name"]
        constraints = [models.UniqueConstraint(fields=["supplier", "domain", "check_name"], name="uniq_supplierfinding_check")]
        indexes = [models.Index(fields=["supplier", "status"], name="supplierfinding_status_idx")]

    def __str__(self):
        return f"{self.domain}: {self.title}"


class InternalRange(models.Model):
    """A private network a project declares as its own internal scope (office LAN, a VPC, a VPN), reachable only from a Sentinel
    deployed inside it. The row is the opt-in: nothing is internal unless a project administrator declared it. Declaring a range
    lets the project add targets inside it (``agentapi.services._expand_target``) and nothing more: ``targetApp.target_types.
    is_scannable_ip`` keeps refusing those addresses for every local scanner, so this server never connects to them itself."""

    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="internal_ranges")
    cidr = models.CharField(max_length=64)  # canonical, network address form (10.20.0.0/24)
    description = models.CharField(max_length=200, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    # The sweep that finds the live hosts of this range (``cveFeed.internal_discovery``): when one last finished, how many hosts it found,
    # what stopped the last attempt, and where a range too large for one run resumes.
    last_discovery_at = models.DateTimeField(null=True, blank=True)
    last_discovery_hosts = models.PositiveIntegerField(null=True, blank=True)
    last_discovery_error = models.CharField(max_length=200, blank=True, default="")
    discovery_cursor = models.PositiveIntegerField(default=0)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "cidr"], name="internalrange_project_cidr_uniq")]
        ordering = ["cidr", "id"]

    def __str__(self):
        return f"{self.cidr} (project {self.project_id})"


class ReviewerSettings(models.Model):
    """Single-row settings of the AI reviewer (docs/AI-REVIEWER.md), the separate container that reviews every open finding once and checks
    the server's operations a few times a day. The provider and its key are the ones in Settings > AI model (``AIProviderSettings``); this row
    chooses a model per job ('' = ``claude-sonnet-5-5`` / ``claude-haiku-5-5`` on Anthropic, else the provider's own model), whether a false
    positive is closed or only recorded, the daily review cap and the UTC hours of the operations check. Instance-wide.

    Both switches ship OFF: the review and the operations check are billed by the AI provider and ``auto_close`` lets the model close findings, so an
    update never starts them. An administrator answers "Do you want AI validation?" (``cveFeed.setup_questions``) or changes them in Settings."""

    enabled = models.BooleanField(default=False)
    review_model = models.CharField(max_length=100, blank=True, default="")
    ops_model = models.CharField(max_length=100, blank=True, default="")
    auto_close = models.BooleanField(default=False)
    review_daily_max = models.PositiveIntegerField(default=300)
    ops_hours = models.JSONField(default=list, blank=True)  # UTC hours; [] = the default (3, 9, 15, 21)
    last_ops_at = models.DateTimeField(null=True, blank=True)  # when the operations job last reported
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")

    @classmethod
    def current(cls):
        return cls.objects.order_by("pk").first() or cls.objects.create()

    def __str__(self):
        return "AI reviewer settings"


class SetupAnswer(models.Model):
    """What an administrator answered to one question about an update (``cveFeed.setup_questions``). One row per question ``key``, instance-wide (it
    holds no project, so there is nothing to scope). ``answer`` is one of the question's choices, or ``later`` for "decide later": the feature stays
    off and the question stays listed. No migration ever writes a row: only a person answers."""

    key = models.CharField(max_length=60, unique=True)
    answer = models.CharField(max_length=60)
    answered_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    answered_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.key}: {self.answer}"


class FindingReview(models.Model):
    """One review of one finding by the AI reviewer (cveFeed.reviewer). ``review_key`` is the finding's evidence key and its host's state
    fingerprint together: a finding is reviewed once per key, and a new port, version or piece of evidence is a new key. ``outcome`` is what
    the server did with the verdict: ``closed`` (closed as a false positive), ``recorded`` (kept as the reviewer's opinion), ``disputed`` (a
    false positive the server would not close because the finding has hard evidence) or ``held`` (a false positive it would not close for
    another reason, in ``held_reason``). Kept as history: the newest row of a finding is its current review."""

    VERDICTS = ("false_positive", "true_open", "true_in_progress", "true_fixed", "true_accepted_risk", "uncertain")
    OUTCOMES = ("closed", "recorded", "disputed", "held")
    triage = models.ForeignKey(Triage, on_delete=models.CASCADE, related_name="reviews")
    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    review_key = models.CharField(max_length=40)
    verdict = models.CharField(max_length=20)
    confidence = models.CharField(max_length=8, default="low")
    reason_code = models.CharField(max_length=32, blank=True, default="")
    note = models.TextField(blank=True, default="")
    model = models.CharField(max_length=100, blank=True, default="")
    outcome = models.CharField(max_length=10, default="recorded")
    held_reason = models.CharField(max_length=200, blank=True, default="")
    injection = models.JSONField(default=list, blank=True)  # the families of AI-directed text found in the evidence (cveFeed.injection_guard)
    input_tokens = models.PositiveIntegerField(default=0)
    output_tokens = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["triage", "-created_at"], name="findingreview_triage_idx"),
                   models.Index(fields=["review_key"], name="findingreview_key_idx"),
                   models.Index(fields=["created_at"], name="findingreview_created_idx")]

    def __str__(self):
        return f"review of triage {self.triage_id}: {self.verdict} ({self.outcome})"


class AdminAlert(models.Model):
    """A problem with the server itself that an App Admin should read: a banner on every page for App Admins until it is resolved or
    dismissed (cveFeed.reviewer: the operations checks raise and resolve them, and the AI reviewer's operations job adds its diagnosis).
    One row per ``code`` while it is open; a resolved problem that comes back opens a new row. ``detail`` is the deterministic description,
    ``ai_detail`` the reviewer's diagnosis and next steps; both are plain text and are only ever rendered as text."""

    SEVERITIES = ("info", "warning", "critical")
    code = models.CharField(max_length=40)
    severity = models.CharField(max_length=8, default="warning")
    title = models.CharField(max_length=200)
    detail = models.TextField(blank=True, default="")
    ai_detail = models.TextField(blank=True, default="")
    ai_model = models.CharField(max_length=100, blank=True, default="")
    facts = models.JSONField(default=dict, blank=True)
    digest = models.CharField(max_length=40, blank=True, default="")  # the facts that make it this problem: a dismissed alert returns when they change
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    resolved_at = models.DateTimeField(null=True, blank=True)
    dismissed_at = models.DateTimeField(null=True, blank=True)
    dismissed_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    dismissed_digest = models.CharField(max_length=40, blank=True, default="")

    class Meta:
        indexes = [models.Index(fields=["code", "resolved_at"], name="adminalert_code_open_idx")]
        ordering = ["-last_seen", "-id"]

    def __str__(self):
        return f"{self.code}: {self.title}"


class SecretFingerprintKey(models.Model):
    """The install's key for fingerprinting exposed secrets (cveFeed.secrets_inventory): 32 random bytes, made once, stored encrypted with the field key.
    It is not derived from SECRET_KEY or the field key, so rotating those (``rotate_field_key``) never splits an inventory row in two, and a database
    dump without the field key cannot confirm a guessed secret by fingerprinting it. One row."""

    key = EncryptedCharField(max_length=ENCRYPTED_COLUMN_LENGTH)
    created_at = models.DateTimeField(auto_now_add=True)


class SecretFinding(models.Model):
    """One exposed secret of a project, however many hosts, URLs, scans and detectors saw it (docs/SECRETS-PLAN.md section 7). The value itself is
    never stored: ``fingerprint`` is a keyed HMAC of it and ``masked`` its prefix and last four characters. Opt-in validation happens in the scanner
    while it holds the value (cveFeed.secrets_validation), so nothing here needs it."""

    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    domain = models.ForeignKey("targetApp.Domain", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")  # where it was first seen
    fingerprint = models.CharField(max_length=64)
    fp_version = models.PositiveSmallIntegerField(default=1, db_default=1)
    provider = models.CharField(max_length=40, blank=True, default="", db_default="")
    kind = models.CharField(max_length=60)
    klass = models.CharField(max_length=1)  # P publishable (browser key), S server secret, I identifier (cveFeed.secrets_catalog)
    catalogued = models.BooleanField(default=True, db_default=True)
    rule_ids = ArrayField(models.CharField(max_length=120), default=list, blank=True)
    masked = models.CharField(max_length=80)
    length = models.PositiveIntegerField(default=0, db_default=0)
    confidence = models.CharField(max_length=10, blank=True, default="", db_default="")
    severity = models.SmallIntegerField(default=0, db_default=0)
    severity_basis = models.CharField(max_length=300, blank=True, default="", db_default="")
    facts = models.JSONField(default=dict, db_default=Value({}, output_field=models.JSONField()), blank=True)  # what the value says that is not the value (a JWT's expiry)
    status = models.CharField(max_length=20, default="unverified", db_default="unverified")
    status_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    status_at = models.DateTimeField(null=True, blank=True)
    status_note = models.TextField(blank=True, default="", db_default="")
    validation_outcome = models.CharField(max_length=20, blank=True, default="", db_default="")
    validated_at = models.DateTimeField(null=True, blank=True)
    validation_meta = models.JSONField(default=dict, db_default=Value({}, output_field=models.JSONField()), blank=True)  # allow-listed keys only, short strings (cveFeed.secrets_inventory.clean_meta)
    first_seen = models.DateTimeField(default=timezone.now, db_default=Now())
    last_seen = models.DateTimeField(default=timezone.now, db_default=Now())
    occurrence_count = models.PositiveIntegerField(default=0, db_default=0)
    host_count = models.PositiveIntegerField(default=0, db_default=0)
    REMEDIATION_STATUSES = CVEMatch.REMEDIATION_STATUSES
    remediation_status = models.CharField(max_length=16, default="open", db_default="open")
    assignee = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "fingerprint"], name="uniq_secretfinding_project_fp")]
        indexes = [models.Index(fields=["project", "status"], name="secretfinding_proj_status_idx"),
                   models.Index(fields=["project", "-severity"], name="secretfinding_proj_sev_idx")]
        ordering = ["-severity", "-last_seen", "id"]

    def __str__(self):
        return f"{self.provider or self.kind} {self.masked}"


class SecretOccurrence(models.Model):
    """Where an inventory secret was seen: one row per URL, detector and rule. ``url`` carries no query string."""

    SOURCES = ("kingfisher", "nuclei", "route", "bbot")
    finding = models.ForeignKey(SecretFinding, on_delete=models.CASCADE, related_name="occurrences")
    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    domain = models.ForeignKey("targetApp.Domain", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    scan = models.ForeignKey("startScan.ScanHistory", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    host = models.CharField(max_length=255)
    url = models.CharField(max_length=2000)
    source = models.CharField(max_length=20)
    rule_id = models.CharField(max_length=120)
    line = models.PositiveIntegerField(null=True, blank=True)
    # the text around the value, with the value masked before it was stored (cveFeed.secrets_catalog.mask_context); empty when it was not captured
    context = models.TextField(blank=True, default="", db_default="")
    vulnerability = models.ForeignKey("startScan.Vulnerability", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    first_seen = models.DateTimeField(default=timezone.now, db_default=Now())
    last_seen = models.DateTimeField(default=timezone.now, db_default=Now())
    retired_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["finding", "url", "source", "rule_id"], name="uniq_secretocc_where")]
        indexes = [models.Index(fields=["project", "host"], name="secretocc_proj_host_idx")]

    def __str__(self):
        return f"{self.source} {self.rule_id} at {self.url}"


class ResourceRef(models.Model):
    """A resource a served page or script points at: a storage bucket, a Firebase database, a container registry, or a URL on some other host.
    Recorded for a person to look at, and (storage and Firebase) handed to the bucket sweep (cveFeed.bucket_scan); never fetched for itself."""

    KINDS = ("s3", "gcs", "azure", "firebase_rtdb", "firebase_storage", "gcr", "ecr", "ghcr", "dockerhub", "url")
    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    domain = models.ForeignKey("targetApp.Domain", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    host = models.CharField(max_length=255)
    found_url = models.CharField(max_length=2000)
    kind = models.CharField(max_length=20)
    identifier = models.CharField(max_length=255)
    secret = models.ForeignKey(SecretFinding, on_delete=models.SET_NULL, null=True, blank=True, related_name="resources")
    first_seen = models.DateTimeField(default=timezone.now, db_default=Now())
    last_seen = models.DateTimeField(default=timezone.now, db_default=Now())

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "kind", "identifier"], name="uniq_resourceref_project_kind_id")]

    def __str__(self):
        return f"{self.kind}:{self.identifier}"


class SecretScanRules(models.Model):
    """The instance's own Kingfisher rules and placeholder lists for the secrets scan (cveFeed.secret_rules): custom detection rules (never a
    validator), the skip words and skip patterns passed as --skip-word and --skip-regex. One row; an App Admin changes it."""

    rules_yaml = models.TextField(blank=True, default="")
    skip_words = models.JSONField(default=list, blank=True)
    skip_regex = models.JSONField(default=list, blank=True)
    updated_by = models.ForeignKey("auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "secrets scan rules"


class PlannerBatch(models.Model):
    """One batch of due checks the work planner (``cveFeed.work_planner``) handed to a Sentinel: up to one task's worth of units of one kind of one
    project's target. The row is the planner's own bookkeeping: what is in flight (so a minute later it does not queue the same units again), what
    failed (so it backs off), and the audit trail of what it did. ``units`` are the assets (``address:port`` for SSH, a host name for secrets); no
    credential, secret or finding is ever stored here."""

    STATUSES = ("queued", "running", "done", "failed", "skipped")
    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    domain = models.ForeignKey("targetApp.Domain", on_delete=models.CASCADE, null=True, blank=True, related_name="+")
    kind = models.CharField(max_length=32)  # the Sentinel task kind (ssh_probe, secrets_scan)
    units = models.JSONField(default=list)
    status = models.CharField(max_length=10, default="queued")
    detail = models.CharField(max_length=300, blank=True, default="")
    created_at = models.DateTimeField(default=timezone.now, db_default=Now())
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["status", "kind"], name="plannerbatch_status_kind_idx"),
                   models.Index(fields=["kind", "finished_at"], name="plannerbatch_kind_fin_idx")]

    def __str__(self):
        return f"planner batch {self.pk}: {self.kind} x{len(self.units or [])} ({self.status})"


class WatchdogEvent(models.Model):
    """One line of what the outer watchdog saw, decided or did (cveFeed.watchdog, docs/WATCHDOG.md): when, which rule, what it observed, what
    it did and what came of it. Append only: a row is never changed once written (old rows are pruned by age, nothing else removes one).
    Plain text, no secrets: it is shown in the Watchdog panel of the Scanners page."""

    LEVELS = ("info", "action", "fixed", "problem")
    at = models.DateTimeField(default=timezone.now, db_index=True)
    rule = models.CharField(max_length=24)
    level = models.CharField(max_length=8, default="info")
    observation = models.CharField(max_length=500, blank=True, default="")
    action = models.CharField(max_length=80, blank=True, default="")
    result = models.CharField(max_length=500, blank=True, default="")
    detail = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-id"]
        indexes = [models.Index(fields=["rule", "id"], name="wdevent_rule_id_idx")]

    def save(self, *args, **kwargs):
        if self.pk is not None and not self._state.adding:
            raise RuntimeError("watchdog events are append only")
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.at:%Y-%m-%d %H:%M:%S} {self.rule} {self.action or self.observation}"


class WatchdogState(models.Model):
    """The watchdog's memory, one row per rule (and one, rule ``_all``, for the watchdog itself: the global switch, the last tick and the last snapshot),
    in the database so a decision survives a restart of the web container: how long a symptom has been seen (hysteresis), when the rule last acted
    (rate limits), the check that follows an action, and the hold that stops it acting again for an hour when it could not fix the problem."""

    rule = models.CharField(max_length=24, unique=True)
    enabled = models.BooleanField(default=True)
    status = models.CharField(max_length=16, default="unknown")  # ok | watching | acting | held | problem | unknown | standing_down | off
    status_text = models.CharField(max_length=400, blank=True, default="")
    fire_since = models.DateTimeField(null=True, blank=True)  # the symptom has been seen continuously since this moment
    last_action_at = models.DateTimeField(null=True, blank=True)
    actions = models.JSONField(default=list, blank=True)  # epoch seconds of the actions of the last day, for the hourly and daily caps
    verify_due = models.DateTimeField(null=True, blank=True)  # when to check that the last action worked
    verify = models.JSONField(default=dict, blank=True)  # {action, symptom_at, acted_at}
    hold_until = models.DateTimeField(null=True, blank=True)  # after an action that did not work: nothing more is done for this rule until then
    escalated_at = models.DateTimeField(null=True, blank=True)
    data = models.JSONField(default=dict, blank=True)  # per rule memory (windows, the discovery override); the last snapshot on ``_all``
    last_tick_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"watchdog {self.rule}: {self.status}"
