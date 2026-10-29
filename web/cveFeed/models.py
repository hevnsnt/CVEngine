"""Models for the cve.now feed.

One row per cve.now entry, carrying the merged severity, exploitation
(CISA KEV / EPSS / Exploit-DB) and affected-product data that the AI
correlation engine matches against the discovered asset inventory.
"""
from django.db import models
from django.db.models.functions import Lower

from reNgine.crypto_fields import ENCRYPTED_COLUMN_LENGTH, EncryptedCharField, EncryptedJSONField
from django.utils import timezone
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
    def threat_tier(self):
        """CVEngine fire / smoke / ice tier (see cveFeed.threat)."""
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
        # a branch-by-branch fix list the feed gave with no lower bounds takes the CNA's own bounds from the CVE List record (issue 205)
        from cveFeed.intel import overlay_branch_ranges
        defaults["affected"], overlaid = overlay_branch_ranges(str(entry["id"])[:64], defaults["affected"])
        if overlaid and "CVE List V5" not in defaults["sources"]:
            defaults["sources"] = [*defaults["sources"], "CVE List V5"]
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

    # What a nuclei template test said about this host for this CVE: vulnerable | no_match | error, or "" when untested.
    TEMPLATE_RESULTS = ("vulnerable", "no_match", "error")
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

    # Remediation workflow, driven by people or agents through the API / MCP.
    REMEDIATION_STATUSES = ("open", "in_progress", "fixed", "accepted_risk")
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

    Lifecycle: draft -> (static check) -> (nuclei -validate) -> valid | invalid,
    then tested against hosts: test_results holds the per-host outcome.
    """

    STATUS_DRAFT = "draft"
    STATUS_VALID = "valid"
    STATUS_INVALID = "invalid"

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
    status = models.CharField(max_length=10, default="done")  # running | done | failed
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
    """A configuration-hygiene finding for a domain or host: TLS, certificates, SPF, DKIM, DMARC, CAA."""

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
    source = models.CharField(max_length=48, blank=True, default="")  # header:server, body:regex, nmap:-sV, wpscan ...
    evidence = models.JSONField(default=dict, blank=True)
    first_seen = models.DateTimeField(default=timezone.now)
    observed_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "host", "probe", "port", "kind", "product"], name="uniq_probeobs_host_probe_port_kind_product")]
        indexes = [models.Index(fields=["project", "host"], name="probeobs_proj_host_idx")]

    def __str__(self):
        return f"{self.host}: {self.probe} {self.product} {self.version}".strip()


class HostProfile(models.Model):
    """Editable asset information for one host of a project: who owns it, what it is for and how much it matters.
    One row per (project, host); the host name is stored lowercase. Never read by a scanner."""

    CRITICALITY = ("unknown", "low", "medium", "high", "critical")
    CRITICALITY_CHOICES = [(c, c) for c in CRITICALITY]

    project = models.ForeignKey("dashboard.Project", on_delete=models.CASCADE, related_name="+")
    host = models.CharField(max_length=500)  # lowercase
    owner = models.CharField(max_length=200, blank=True, default="")
    purpose = models.CharField(max_length=500, blank=True, default="")
    criticality = models.CharField(max_length=16, choices=CRITICALITY_CHOICES, default="unknown")
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
                   models.Index(fields=['archived_at', 'unresolved_first_at', 'id'], name='hoststate_unresolved_idx')]

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
    ``reason`` are what the rules kept (they differ when ``overridden``, i.e. hard evidence outranked the model). Holds only text
    derived from cleaned fingerprints and feed data, so it is not tenant data and has no project (like ServiceRun)."""

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
        indexes = [models.Index(fields=["project", "started_at"], name="triagecall_project_day_idx")]
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
    input_tokens = models.PositiveIntegerField(null=True, blank=True)
    output_tokens = models.PositiveIntegerField(null=True, blank=True)
    cache_read_tokens = models.PositiveIntegerField(null=True, blank=True)
    cache_write_tokens = models.PositiveIntegerField(null=True, blank=True)
    duration_ms = models.PositiveIntegerField(null=True, blank=True)
    started_at = models.DateTimeField(default=timezone.now)

    class Meta:
        indexes = [models.Index(fields=['started_at', 'provider', 'model'], name='aiusage_time_model_idx')]


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
    """One durable pending retest per project/host/evidence revision."""

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
        constraints = [models.UniqueConstraint(fields=["project", "host", "signature"], name="uniq_retest_evidence")]
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

    @classmethod
    def current(cls):
        return cls.objects.get_or_create(pk=1)[0]


class AssessmentReview(models.Model):
    """Checkpointed three-hour assessment review; decisions live in AssessmentReviewDecision."""

    status = models.CharField(max_length=16, default='queued')
    period_start = models.DateTimeField()
    period_end = models.DateTimeField()
    cursor_project_id = models.PositiveIntegerField(default=0)
    total_projects = models.PositiveIntegerField(default=0)
    reviewed_projects = models.PositiveIntegerField(default=0)
    model_calls = models.PositiveIntegerField(default=0)
    queued_actions = models.PositiveIntegerField(default=0)
    error_count = models.PositiveIntegerField(default=0)
    performance = models.JSONField(default=dict, blank=True)
    error = models.CharField(max_length=200, blank=True, default='')
    lease_until = models.DateTimeField(null=True, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)


class AssessmentReviewDecision(models.Model):
    review = models.ForeignKey(AssessmentReview, on_delete=models.CASCADE, related_name='decisions')
    project = models.ForeignKey('dashboard.Project', on_delete=models.CASCADE)
    action = models.CharField(max_length=32, default='none')
    status = models.CharField(max_length=16, default='no_action')
    reason = models.CharField(max_length=300, blank=True, default='')
    evidence = models.JSONField(default=dict, blank=True)
    job_id = models.PositiveIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=('review', 'project'), name='one_assessment_decision_per_project')]


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

    EVENTS = ("status", "assignee", "comment")
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
    ai_problems = models.JSONField(default=list, blank=True)  # what validation dropped from the model's answer
    ai_input_hash = models.CharField(max_length=16, blank=True, default="", db_default="")  # what the CVE said when the model last read it: a change re-asks
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "CVE detection"
        verbose_name_plural = "CVE detections"
        indexes = [models.Index(fields=["ai_attempted_at"], name="cvedetect_ai_idx")]

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
    sentinel_only = models.BooleanField(default=False)  # refuse the local gvmd fallback: a due batch with no eligible Sentinel stays due
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
    fingerprinting owned hosts use, ``cveFeed.fingerprint``), and the address and mail facts. ``tech_text`` is the lowercase text the
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
    ``accepted`` when an admin decided to live with it (the sweep then only refreshes its evidence). ``ask`` says what to ask the supplier.
    Never validated by exploitation: nothing here is ever tested beyond what the supplier's service announces."""

    STATUSES = ("open", "accepted", "resolved")
    supplier = models.ForeignKey(Supplier, on_delete=models.CASCADE, related_name="findings")
    domain = models.CharField(max_length=255)
    check_name = models.CharField(max_length=60)
    category = models.CharField(max_length=12, default="")  # tls | email | web | cve
    severity = models.IntegerField(default=0)  # 0 info .. 4 critical, the same scale as hygiene findings
    title = models.CharField(max_length=300)
    detail = models.TextField(blank=True, default="")
    ask = models.TextField(blank=True, default="")  # plain text: what to ask the supplier to do or confirm
    evidence = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=10, default="open")
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    resolved_at = models.DateTimeField(null=True, blank=True)
    status_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    status_note = models.CharField(max_length=500, blank=True, default="")

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
