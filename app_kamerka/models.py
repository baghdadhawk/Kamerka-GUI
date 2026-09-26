from django.conf import settings
from django.db import models
from django.db.models import JSONField
import uuid


# Create your models here.

class Search(models.Model):
    coordinates = models.CharField(max_length=100)
    country = models.CharField(max_length=100)
    ics = JSONField(default=list)
    coordinates_search = JSONField(default=list)
    nmap = models.BooleanField(default=False)

class Device(models.Model):
    # Triage status: manually set by an operator via the set_device_status
    # AJAX endpoint (app_kamerka.views.set_device_status). Defaults to "new"
    # for every freshly-saved device.
    STATUS_CHOICES = [
        ('new', 'New'),
        ('reviewed', 'Reviewed'),
        ('confirmed', 'Confirmed'),
        ('false_positive', 'False positive'),
    ]

    search = models.ForeignKey(Search, on_delete=models.CASCADE)
    ip = models.CharField(max_length=100, default="")
    product = models.CharField(max_length=500, default="")
    org = models.CharField(max_length=100, default="", null=True)
    data = models.CharField(max_length=1000, default="")
    port = models.CharField(max_length=10, default="")
    type = models.CharField(max_length=100, default="")
    city = models.CharField(max_length=100, default="", null=True)
    lon = models.CharField(max_length=100, default="")
    lat = models.CharField(max_length=100, default="")
    country_code = models.CharField(max_length=100, default="")
    query = models.CharField(max_length=100, default="")
    category = models.CharField(max_length=100, default="")
    vulns = JSONField(default=list)
    indicator = JSONField(default=list)
    hostnames = JSONField(default=list)
    screenshot = models.CharField(max_length=100000, default="")
    located = models.BooleanField(default=False, null=True)
    notes = models.CharField(max_length=1000, default="")
    scan = JSONField(default=dict)
    exploit = JSONField(default=dict)
    exploited_scanned = models.BooleanField(default=False)
    # Local heuristic honeypot detection (app_kamerka.honeypot.score_device),
    # computed automatically at save time, no network required.
    honeypot_score = models.IntegerField(default=0)
    honeypot_reasons = models.TextField(default="")  # JSON-encoded list[str]
    # On-demand Shodan HoneyScore (0.0-1.0), null until a user explicitly
    # requests it via the "Check HoneyScore" button (get_honeyscore view).
    honeyscore = models.FloatField(null=True, blank=True, default=None)
    # Persistent, non-destructive "this match is probably a generic web
    # server / HTTP-error page misclassified as a device family" flag,
    # computed at save time in kamerka.tasks._save_device_from_result. Never
    # deletes/hides data by itself -- see the `devices` view's
    # false_positive/hide_fp filter for that.
    suspected_false_positive = models.BooleanField(default=False)
    # Manual operator triage status (see STATUS_CHOICES above).
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')

    class Meta:
        # Capability-based roles (see app_kamerka.authz.require_capability and
        # the Viewer/Analyst/Active Scanner/Exploit Operator/Administrator
        # groups created by the 000x_capability_groups data migration).
        # These are plain custom Django permissions -- not tied to any
        # particular Device instance -- hung off this model only because
        # every custom permission needs *some* model to live on and Device
        # is the app's central one. A superuser holds all of them implicitly
        # (django.contrib.auth's ModelBackend.has_perm short-circuits to True
        # for is_superuser).
        permissions = [
            ('view_capability', 'Can view read-only pages and passive lookups'),
            ('run_search', 'Can run passive Shodan searches and enrichment/triage/export'),
            ('active_scan', 'Can run active Nmap scans'),
            ('exploit', 'Can run exploitation modules'),
            ('view_exploit_results', 'Can view exploitation results and credentials'),
            ('administer', 'Can administer scan scopes and users'),
        ]

class DeviceNearby(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    lat = models.CharField(max_length=100)
    lon = models.CharField(max_length=100)
    ip = models.CharField(max_length=100)
    product = models.CharField(max_length=100)
    port = models.CharField(max_length=100)
    org = models.CharField(max_length=100)


class ShodanScan(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    ports = models.CharField(max_length=100)
    tags = models.CharField(max_length=100)
    products = models.CharField(max_length=100)
    module = models.CharField(max_length=100)
    # Was CharField(max_length=100) but callers (kamerka.tasks.shodan_scan_task)
    # assign the raw Shodan `vulns` list here -- silently truncated (and
    # str()-mangled) past 100 chars. See Device.vulns/indicator/hostnames
    # for the same class of bug.
    vulns = JSONField(default=list)


class BinaryEdgeScore(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    grades = JSONField()
    cve = JSONField()
    score = models.CharField(max_length=3)


class Whois(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    org = models.CharField(max_length=100)
    street = models.CharField(max_length=100)
    city = models.CharField(max_length=100)
    netrange = models.CharField(max_length=100)
    admin_org = models.CharField(max_length=100)
    admin_email = models.CharField(max_length=100)
    admin_phone = models.CharField(max_length=100)
    email = models.CharField(max_length=100)

class Bosch(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=100)

class Dnp3(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    source = models.CharField(max_length=100)
    destination = models.CharField(max_length=100)
    control = models.CharField(max_length=100)


class ScanAuthorization(models.Model):
    """An explicit engagement/authorization scope for ACTIVE operations
    (Nmap scanning, exploitation). A device discovered via passive Shodan
    search can only be scanned/exploited if its IP falls within some
    non-expired row here with the matching allow_* flag set -- see
    app_kamerka.authz.is_target_authorized(). Administrators create these
    via the Django admin (see app_kamerka/admin.py)."""

    name = models.CharField(max_length=200, help_text="Short label, e.g. the engagement name.")
    reference = models.CharField(
        max_length=200, blank=True, default="",
        help_text="Optional reference, e.g. an incident/engagement ticket id.",
    )
    cidr = models.CharField(
        max_length=100,
        help_text="An IPv4/IPv6 network (e.g. 203.0.113.0/24) or a single host (e.g. 203.0.113.5).",
    )
    allow_port_scan = models.BooleanField(default=False, help_text="Authorizes active Nmap scanning.")
    allow_exploit = models.BooleanField(default=False, help_text="Authorizes exploitation attempts.")
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(
        null=True, blank=True,
        help_text="Leave blank for a scope that never expires.",
    )

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return "%s (%s)" % (self.name, self.cidr)


class AuditLog(models.Model):
    """Audit trail for sensitive/side-effecting operations (active scanning,
    exploitation, third-party enrichment lookups, and triage-affecting
    writes). Written via app_kamerka.views.record_audit() from the POST-only
    views that perform these operations -- never mutated afterwards, and
    read-only in the admin (see app_kamerka/admin.py)."""

    ACTION_CHOICES = [
        ('scan', 'Active scan'),
        ('exploit', 'Exploit attempt'),
        ('honeyscore', 'Shodan HoneyScore check'),
        ('set_status', 'Set device status'),
        ('update_coordinates', 'Update coordinates'),
        ('whois', 'Whois lookup'),
        ('shodan_scan', 'Shodan scan'),
        ('binaryedge', 'BinaryEdge score lookup'),
        ('nearby', 'Nearby devices search'),
        ('notes', 'Notes update'),
        ('capability_denied', 'Capability denied'),
        ('scope_denied', 'Target scope denied'),
        ('operation_queued', 'Active operation queued'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
    )
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True)
    target = models.CharField(max_length=255, blank=True, default="")
    detail = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        who = self.user_id or "anonymous"
        return "%s by %s on %s @ %s" % (self.action, who, self.target or self.device_id, self.created_at)


class ExploitTaskAccess(models.Model):
    """Marks Celery task IDs whose results may contain retrieved secrets.

    The generic progress endpoint uses this record to withhold sensitive
    result payloads; the dedicated result endpoint checks a separate
    capability before releasing them.
    """
    task_id = models.CharField(max_length=255, primary_key=True)
    created_at = models.DateTimeField(auto_now_add=True)


class GeneralTaskResultAccess(models.Model):
    """Allow ordinary task result visibility for known passive tasks only.

    Unknown and legacy task IDs fail closed in generic status endpoints.
    """
    task_id = models.CharField(max_length=255, primary_key=True)
    created_at = models.DateTimeField(auto_now_add=True)


class Operation(models.Model):
    """Durable lifecycle and authorization snapshot for active work.

    ``succeeded`` means the worker completed without an execution error;
    scan/exploit findings remain in Celery/device results and do not redefine
    whether the operation worker itself completed.
    """
    STATUS_CHOICES = [(value, value.title()) for value in
                      ('queued', 'running', 'succeeded', 'failed', 'blocked')]
    KIND_CHOICES = [('scan', 'Scan'), ('exploit', 'Exploit')]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    kind = models.CharField(max_length=16, choices=KIND_CHOICES)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default='queued')
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                               null=True, blank=True, related_name='active_operations')
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True,
                               related_name='operations')
    authorization_id = models.PositiveBigIntegerField(null=True, blank=True)
    target_ip = models.CharField(max_length=100)
    target_port = models.CharField(max_length=10)
    target_type = models.CharField(max_length=100)
    celery_task_id = models.CharField(max_length=255, blank=True, default='', db_index=True)
    error = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
