"""Cross-search de-dupe / prior sightings.

A given IP can show up in more than one Search (different runs, different
families/categories, over time). `other_sightings()` finds those other
Device rows so the device page can surface "this host was seen before"
instead of treating every Search as an isolated island.

Pure DB query -- no I/O beyond the ORM -- so it is trivially unit testable
and cheap enough to call from a view on every device page load.
"""
from app_kamerka.models import Device


def other_sightings(device):
    """Return a queryset of other Device rows sharing `device.ip`, across
    all searches, excluding `device` itself, most-recent first (highest id
    / most recently saved first).

    Returns an empty queryset for a falsy `device` or a device with no ip,
    rather than raising.
    """
    if not device or not getattr(device, 'ip', None):
        return Device.objects.none()

    return Device.objects.filter(ip=device.ip).exclude(id=device.id).order_by('-id')
