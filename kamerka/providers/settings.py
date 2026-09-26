"""Provider API-key loading and a small validated settings layer.

Historically every task in kamerka/tasks.py reached into a module-level
``keys`` dict (``keys['keys']['shodan']``) loaded once at import time from
keys.json. That still works exactly as before via :func:`get_keys` (kept as
a thin backward-compat shim -- nothing that already calls it needs to
change), but new/refactored code should prefer :class:`ProviderSettings`,
which:

* loads the same keys.json (respecting the ``KAMERKA_KEYS_FILE`` override),
* is a frozen (immutable) dataclass instead of a loosely-shaped dict, and
* exposes whether each provider is actually configured (``is_configured``)
  instead of forcing every caller to catch a deep ``KeyError``/``TypeError``
  from a missing/empty keys.json.
"""
import json
import logging
import os
from dataclasses import dataclass, fields
from typing import Optional

logger = logging.getLogger(__name__)

# API keys are read from a JSON file resolved relative to the project root
# (or from the path in the KAMERKA_KEYS_FILE environment variable), so the
# location no longer depends on the current working directory.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KEYS_FILE = os.environ.get('KAMERKA_KEYS_FILE', os.path.join(_PROJECT_ROOT, 'keys.json'))

# Maps a ProviderSettings field name -> the key name inside keys.json's
# "keys" object, exactly as every existing `keys['keys'][...]` access does.
_KEY_FIELD_MAP = {
    'shodan_key': 'shodan',
    'binaryedge_key': 'binaryedge',
    'whoisxmlapi_key': 'whoisxmlapi',
    'google_maps_key': 'google_maps',
}


def get_keys():
    """Backward-compat shim: load and return the raw keys.json dict exactly
    as the original kamerka.tasks.get_keys() did (same file resolution,
    same "log a warning and return None on failure" behavior). Existing
    callers of ``keys['keys']['shodan']``-style access keep working
    unchanged.
    """
    try:
        with open(KEYS_FILE) as keys:
            keys_json = json.load(keys)

        return keys_json
    except Exception as e:
        logger.warning("Failed to load keys file %s: %s", KEYS_FILE, e)


@dataclass(frozen=True)
class ProviderSettings:
    """Validated, immutable view of the provider API keys in keys.json.

    Any field left unset (missing key, missing/unreadable keys.json, or an
    empty/placeholder value) is None rather than raising -- callers ask
    :meth:`is_configured` before using a provider instead of hitting a
    KeyError deep inside a task.
    """
    shodan_key: Optional[str] = None
    binaryedge_key: Optional[str] = None
    whoisxmlapi_key: Optional[str] = None
    google_maps_key: Optional[str] = None

    def is_configured(self, provider):
        """True if the named provider (e.g. 'shodan_key', or just 'shodan')
        has a non-empty key loaded."""
        field_name = provider if provider.endswith('_key') else provider + '_key'
        return bool(getattr(self, field_name, None))

    def require(self, provider):
        """Return the named provider's key, or raise ProviderKeyMissing with
        a clear message instead of a bare KeyError."""
        field_name = provider if provider.endswith('_key') else provider + '_key'
        value = getattr(self, field_name, None)
        if not value:
            raise ProviderKeyMissing(
                "Provider key '%s' is not configured (checked %s)" % (provider, KEYS_FILE)
            )
        return value

    def unavailable_providers(self):
        """List the field names (without the trailing '_key') that have no
        key configured -- handy for a one-line startup/health-check log."""
        return [f.name[:-4] for f in fields(self) if not getattr(self, f.name)]


class ProviderKeyMissing(RuntimeError):
    """Raised by ProviderSettings.require() when a provider's key is not
    configured. A typed, clearly-named alternative to a bare KeyError/
    TypeError bubbling up from deep inside a keys.json dict access."""


def load_provider_settings(raw_keys=None):
    """Build a ProviderSettings from keys.json (or from `raw_keys`, the same
    shape get_keys() returns, mainly for tests). Never raises: any problem
    reading/parsing the file, or a missing "keys" section, results in a
    ProviderSettings with every field None (and is logged).
    """
    if raw_keys is None:
        raw_keys = get_keys()

    values = {}
    try:
        provider_keys = (raw_keys or {}).get('keys', {}) or {}
    except AttributeError:
        logger.warning("keys.json did not contain a dict; ignoring")
        provider_keys = {}

    for field_name, json_key in _KEY_FIELD_MAP.items():
        value = provider_keys.get(json_key)
        values[field_name] = value if value else None

    return ProviderSettings(**values)
