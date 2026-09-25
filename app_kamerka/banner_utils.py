"""Small, unit-testable helpers for making sense of the raw Shodan banner
(`Device.data`) shown on the device page.

Shodan occasionally captures a generic web-server response (e.g. an nginx
"400 Bad Request" error page) instead of anything specific to the device
type it classified the host as. That banner is technically real data, but
showing it as "device intelligence" without comment is misleading, so the
device view/template flags it instead.
"""
import re

# Substrings (already lower-cased) that show up in a generic HTTP error
# response body/status line.
_ERROR_MARKERS = (
    "400 bad request",
    "401 unauthorized",
    "403 forbidden",
    "404 not found",
    "405 not allowed",
    "500 internal server error",
    "502 bad gateway",
    "503 service unavailable",
    "504 gateway timeout",
)

# An HTTP status line like "HTTP/1.1 400 Bad Request" on its own is a
# strong enough signal by itself (no need for an HTML wrapper too).
_STATUS_LINE_RE = re.compile(r'http/\d(?:\.\d)?\s+[45]\d\d\b')


def looks_like_generic_http_response(banner):
    """Return True when `banner` looks like a generic/HTTP-error web
    response rather than device-specific banner data.

    Heuristic: either an HTTP status line with a 4xx/5xx code, or an
    HTML/DOCTYPE-wrapped body that also mentions an HTTP error status
    (e.g. a default nginx/Apache error page).
    """
    if not banner or not isinstance(banner, str):
        return False

    text = banner.lower()

    if _STATUS_LINE_RE.search(text):
        return True

    has_html_wrapper = ('<html' in text) or ('<!doctype' in text)
    has_error_marker = any(marker in text for marker in _ERROR_MARKERS)

    return has_html_wrapper and has_error_marker
