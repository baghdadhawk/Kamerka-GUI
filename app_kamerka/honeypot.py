"""Local (offline, zero-API-cost) honeypot heuristics.

This is a pure module: `score_device()` takes plain values (strings/ints)
already extracted from a Shodan match (or from a stored `Device` row) and
returns a score + reasons. It does no I/O, no DB access and no network
calls, so it is safe to call synchronously for every device as it is saved
(see kamerka.tasks._save_device_from_result), and is trivially unit
testable.

This is one of TWO honeypot signals in the app:
  1. THIS module - local heuristics, runs automatically on every device.
  2. Shodan's HoneyScore (api.honeyscore) - flaky, paid-ish, on demand only,
     via kamerka.tasks.honeyscore() / the get_honeyscore view.

The two are complementary and intentionally not merged into one field:
honeypot_score/honeypot_reasons are always populated (best-effort, may be
wrong), while honeyscore stays null until a human explicitly asks Shodan.
"""
import re

from app_kamerka.banner_utils import looks_like_generic_http_response

# --- Tunable weights -------------------------------------------------------
# Keep the ruleset small and high-confidence. Every rule below contributes at
# most its own weight; the final score is capped at 100. Raise/lower these to
# tune how aggressively devices get flagged.

# Conpot (the most widely deployed open-source ICS honeypot) ships with a set
# of well-known default/template values that operators very often forget (or
# don't bother) to change. Seeing any of them in the raw banner is a strong
# signal.
CONPOT_FINGERPRINT_WEIGHT = 60

# Real ICS/SCADA equipment is physical hardware sitting on an OT network; it
# essentially never lives on a generic cloud/hosting VM. A device classified
# as "ics" whose org/hostnames point at a well-known cloud/hosting provider
# is a solid (if not 100%) signal of a honeypot running on a cheap VPS.
CLOUD_HOSTED_ICS_WEIGHT = 55

# A banner that is just a generic/echoed HTTP response (see banner_utils)
# but was still classified as a specific ICS/healthcare product suggests a
# low-interaction honeypot (or emulator) that doesn't actually implement the
# protocol it claims to speak.
GENERIC_BANNER_WEIGHT = 20

# Score at/above this value means "likely honeypot" throughout the app
# (views, templates, tests). Kept as a single named constant so it can be
# tuned in one place.
HONEYPOT_THRESHOLD = 50

# --- Conpot fingerprints -----------------------------------------------
# Conpot (https://github.com/mushorg/conpot) ships a default "default"
# template (and the closely related Siemens S7-300 template) whose
# identifying strings are hardcoded in the project and show up verbatim in
# the banner unless an operator customizes them. These are lower-cased
# before matching.
CONPOT_FINGERPRINTS = (
    "technodrome",       # default S7comm plant identification ("Technodrome" - TMNT reference)
    "mouser factory",    # default S7comm module name
    "88111222",          # default S7comm serial number / module type default
    "conpot",             # the honeypot literally advertises its own name in some templates/banners
)

# Cloud / hosting providers real industrial hardware essentially never runs
# on. Matched as a case-insensitive substring against org and hostnames.
CLOUD_PROVIDER_MARKERS = (
    "digitalocean",
    "amazon",
    "aws",
    "google",
    "microsoft",
    "azure",
    "hetzner",
    "ovh",
    "linode",
    "vultr",
    "oracle cloud",
    "oraclecloud",
    "cloudflare",
    "dreamhost",
    "contabo",
    "scaleway",
)


def _contains_any(text, markers):
    if not text:
        return None
    lowered = text.lower()
    for marker in markers:
        if marker in lowered:
            return marker
    return None


def score_device(*, data="", product="", org="", hostnames="", port=None,
                 category="", ip=None, type=None):
    """Score a single Shodan match / Device for how likely it is a honeypot.

    All arguments are plain values (strings, may be None/""); nothing here
    touches the DB or network. Returns (score:int 0-100, reasons:list[str]).
    An all-empty/benign input scores 0 with no reasons.
    """
    data = data or ""
    product = product or ""
    org = org or ""
    hostnames = hostnames or ""
    category = (category or "").lower()

    score = 0
    reasons = []

    # 1. Conpot fingerprints in the raw banner.
    hit = _contains_any(data, CONPOT_FINGERPRINTS)
    if hit:
        score += CONPOT_FINGERPRINT_WEIGHT
        reasons.append(
            "Banner contains a known Conpot default/template artifact (%r)" % hit
        )

    # 2. "ICS" device hosted on a cloud/hosting provider.
    if category == "ics":
        provider = _contains_any(org, CLOUD_PROVIDER_MARKERS) or _contains_any(hostnames, CLOUD_PROVIDER_MARKERS)
        if provider:
            score += CLOUD_HOSTED_ICS_WEIGHT
            reasons.append(
                "Classified as ICS but hosted on a cloud/hosting provider (%r) - "
                "real ICS/SCADA hardware rarely runs on cloud VMs" % provider
            )

    # 3. Generic/HTTP-error banner presented as a specific ICS/healthcare
    #    product (reuses the same heuristic the device page already warns
    #    with, so the two stay consistent with each other).
    if category in ("ics", "healthcare") and looks_like_generic_http_response(data):
        score += GENERIC_BANNER_WEIGHT
        reasons.append(
            "Banner looks like a generic/HTTP-error response rather than "
            "device-specific data, despite being classified as %s" % (category or "a device")
        )

    score = min(score, 100)
    return score, reasons
