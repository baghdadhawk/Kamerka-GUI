from django.conf import settings
from django.db import models
from django.db.models import JSONField


# Create your models here.

class Search(models.Model):
    coordinates = models.CharField(max_length=100)
    country = models.CharField(max_length=100)
    ics = models.CharField(max_length=100)
    coordinates_search = models.CharField(max_length=1000)
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
    vulns = models.CharField(max_length=100, default="")
    indicator = models.CharField(max_length=100, default="")
    hostnames = models.CharField(max_length=100, default="")
    screenshot = models.CharField(max_length=100000, default="")
    located = models.BooleanField(default=False, null=True)
    notes = models.CharField(max_length=1000, default="")
    scan = models.CharField(max_length=100000, default="")
    exploit = models.CharField(max_length=10000, default="")
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
    vulns = models.CharField(max_length=100)


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

