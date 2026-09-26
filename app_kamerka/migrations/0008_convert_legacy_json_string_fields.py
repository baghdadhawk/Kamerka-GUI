"""Data migration: rewrite the stringified-Python values currently stored in
Device.vulns/indicator/hostnames/scan/exploit, Search.ics/coordinates_search
and ShodanScan.vulns into real JSON text, WHILE those columns are still plain
CharField/TextField (this migration runs before the AlterField migration
that actually switches them to JSONField).

This matters most on backends (e.g. PostgreSQL) where changing a text column
to jsonb requires the existing text to already be valid JSON -- the old
values here are Python repr strings (e.g. "['CVE-2020-1111']", single
quotes), which is NOT valid JSON. Rewriting them to JSON text first (this
migration) then altering the column type (the next migration) means the
type change can never fail or silently corrupt data, on any backend.

Every conversion is wrapped so a malformed/legacy value can never abort the
migration -- it just falls back to [] or {} for that one row.
"""
import ast
import json

from django.db import migrations


def _parse_list_like(raw):
    """Best-effort: an ast.literal_eval-able string representing a
    list/tuple -> a plain list. Anything else (empty, unparsable, not a
    list/tuple) -> []."""
    if not raw:
        return []
    try:
        parsed = ast.literal_eval(raw)
    except Exception:
        return []
    if isinstance(parsed, (list, tuple)):
        return list(parsed)
    return []


def _parse_hostnames(raw):
    """The old Device.hostnames value was a single hostname string (or
    ""). -> [raw] if non-empty, else []."""
    if not raw:
        return []
    return [raw]


def _parse_dict_like(raw):
    """Best-effort: an ast.literal_eval-able or JSON-decodable string
    representing a dict -> that dict. Anything else -> {}."""
    if not raw:
        return {}
    try:
        parsed = ast.literal_eval(raw)
    except Exception:
        try:
            parsed = json.loads(raw)
        except Exception:
            return {}
    if isinstance(parsed, dict):
        return parsed
    return {}


def convert_forward(apps, schema_editor):
    Device = apps.get_model('app_kamerka', 'Device')
    Search = apps.get_model('app_kamerka', 'Search')
    ShodanScan = apps.get_model('app_kamerka', 'ShodanScan')

    for device in Device.objects.all().iterator():
        try:
            new_vulns = _parse_list_like(device.vulns)
        except Exception:
            new_vulns = []
        try:
            new_indicator = _parse_list_like(device.indicator)
        except Exception:
            new_indicator = []
        try:
            new_hostnames = _parse_hostnames(device.hostnames)
        except Exception:
            new_hostnames = []
        try:
            new_scan = _parse_dict_like(device.scan)
        except Exception:
            new_scan = {}
        try:
            new_exploit = _parse_dict_like(device.exploit)
        except Exception:
            new_exploit = {}

        device.vulns = json.dumps(new_vulns)
        device.indicator = json.dumps(new_indicator)
        device.hostnames = json.dumps(new_hostnames)
        device.scan = json.dumps(new_scan)
        device.exploit = json.dumps(new_exploit)
        device.save(update_fields=['vulns', 'indicator', 'hostnames', 'scan', 'exploit'])

    for search in Search.objects.all().iterator():
        try:
            new_ics = _parse_list_like(search.ics)
        except Exception:
            new_ics = []
        try:
            new_coords = _parse_list_like(search.coordinates_search)
        except Exception:
            new_coords = []

        search.ics = json.dumps(new_ics)
        search.coordinates_search = json.dumps(new_coords)
        search.save(update_fields=['ics', 'coordinates_search'])

    for shodan_scan in ShodanScan.objects.all().iterator():
        try:
            new_vulns = _parse_list_like(shodan_scan.vulns)
        except Exception:
            new_vulns = []

        shodan_scan.vulns = json.dumps(new_vulns)
        shodan_scan.save(update_fields=['vulns'])


class Migration(migrations.Migration):

    dependencies = [
        ('app_kamerka', '0007_capability_groups'),
    ]

    operations = [
        migrations.RunPython(convert_forward, reverse_code=migrations.RunPython.noop),
    ]
