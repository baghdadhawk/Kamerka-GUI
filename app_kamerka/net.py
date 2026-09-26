"""Shared HTTP safety layer for outbound requests made by Kamerka.

This module exists because Kamerka makes two very different *kinds* of
outbound HTTP calls, and treating them the same way is a security bug in
itself:

* **Passive calls** talk to our own trusted, well-behaved third-party
  provider APIs (BinaryEdge, WhoisXML, ...). These endpoints are on the
  public internet, have valid TLS certificates, and are expected to respond
  quickly and predictably. It is safe (and desirable) to verify TLS, retry
  on transient network hiccups, and enforce a response-size cap so a
  misbehaving/huge response can't blow up worker memory.

* **Active calls** talk *directly to attacker-adjacent, untrusted target
  devices* as part of exploit/PoC probing (cameras, PLCs, and other legacy
  ICS/IoT gear discovered during scanning). These devices are often on
  hostile or unknown networks, may have broken/self-signed TLS, may hang
  forever instead of responding, and must never be retried automatically
  (retrying an exploit attempt can trip lockouts, alarms, or simply hammer
  a fragile embedded device). TLS verification must be an explicit,
  per-call decision here -- never a silent, scattered ``verify=False``.

Both client policies share one hard rule: **every request always has an
explicit timeout**. A raw ``requests.get(...)`` with no timeout can block a
Celery worker indefinitely if the remote end never responds, stalling the
whole task queue behind it.
"""

import logging
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Centralized constants
# --------------------------------------------------------------------------

USER_AGENT = "Kamerka/1.0 (+https://github.com/woj-ciech/Kamerka; passive-http-client)"
ACTIVE_USER_AGENT = "Kamerka/1.0 (+https://github.com/woj-ciech/Kamerka; active-probe)"

# (connect_timeout, read_timeout) tuples, in seconds.
PASSIVE_TIMEOUT = (5, 15)
ACTIVE_TIMEOUT = (3, 8)
ACTIVE_MAX_DURATION = 20

PASSIVE_MAX_RETRIES = 2
PASSIVE_BACKOFF_FACTOR = 0.5
PASSIVE_RETRY_STATUS_FORCELIST = (500, 502, 503, 504)

# Refuse to buffer a response body larger than this many bytes, to avoid
# unbounded memory usage from a huge/hostile response.
MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB

DOWNLOAD_CHUNK_SIZE = 64 * 1024


class ResponseTooLarge(Exception):
    """Raised when a response body exceeds MAX_RESPONSE_BYTES."""


def _enforce_size_guard(response, max_bytes=MAX_RESPONSE_BYTES):
    """Stream-consume `response` while enforcing a byte cap.

    Reads the response through in chunks (rather than trusting
    Content-Length, which a malicious/misbehaving server can lie about or
    omit) and raises ResponseTooLarge if the cap is exceeded. After this
    call, response.content/.text/.json() work normally against the buffered
    (size-checked) body.
    """
    total = 0
    chunks = []
    for chunk in response.iter_content(chunk_size=DOWNLOAD_CHUNK_SIZE):
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            response.close()
            raise ResponseTooLarge(
                "Response body exceeded %d bytes limit" % max_bytes
            )
        chunks.append(chunk)

    body = b"".join(chunks)
    # Rewrite requests' internal buffer so .content/.text/.json() reflect
    # exactly what we already validated, without re-reading from the socket.
    response._content = body
    response._content_consumed = True
    return response


class PassiveClient:
    """HTTP client for calling our own trusted provider APIs.

    - TLS verification is always on.
    - A sane connect+read timeout is always applied.
    - Transient errors (connection errors and 5xx) are retried a couple of
      times with backoff.
    - A descriptive User-Agent identifies Kamerka to the provider.
    - Response bodies are size-capped to avoid unbounded memory use.
    """

    def __init__(
        self,
        timeout=PASSIVE_TIMEOUT,
        max_retries=PASSIVE_MAX_RETRIES,
        backoff_factor=PASSIVE_BACKOFF_FACTOR,
        user_agent=USER_AGENT,
        max_response_bytes=MAX_RESPONSE_BYTES,
    ):
        self.timeout = timeout
        self.user_agent = user_agent
        self.max_response_bytes = max_response_bytes
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor

        self.session = requests.Session()
        # Belt-and-braces: urllib3's Retry handles retries for connections
        # that got far enough to reach the transport (including retrying on
        # 5xx responses). It runs *below* Session.request, transparently to
        # our own code.
        retry = Retry(
            total=max_retries,
            connect=max_retries,
            read=max_retries,
            status=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=PASSIVE_RETRY_STATUS_FORCELIST,
            allowed_methods=frozenset(["GET", "POST", "PUT", "HEAD", "OPTIONS"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _request(self, method, url, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", True)
        kwargs["stream"] = True  # required so we can enforce the size guard

        headers = dict(kwargs.pop("headers", None) or {})
        headers.setdefault("User-Agent", self.user_agent)
        kwargs["headers"] = headers

        max_response_bytes = kwargs.pop("max_response_bytes", self.max_response_bytes)

        # Outer retry loop: covers transient errors that surface as Python
        # exceptions raised out of Session.request (e.g. a connection reset
        # before urllib3's own retry machinery could kick in). Kept
        # separate from, and on top of, the transport-level Retry adapter
        # above.
        attempts = self.max_retries + 1
        last_exc = None
        for attempt in range(attempts):
            try:
                response = self.session.request(method, url, **kwargs)
                _enforce_size_guard(response, max_bytes=max_response_bytes)
                return response
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
                last_exc = exc
                if attempt >= attempts - 1:
                    raise
                sleep_for = self.backoff_factor * (2 ** attempt)
                logger.warning(
                    "PassiveClient transient error on %s %s (attempt %d/%d): %s",
                    method, url, attempt + 1, attempts, exc,
                )
                time.sleep(sleep_for)
        raise last_exc

    def get(self, url, **kwargs):
        return self._request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self._request("POST", url, **kwargs)

    def get_json(self, url, **kwargs):
        return self.get(url, **kwargs).json()


class ActiveClient:
    """HTTP client for direct interaction with untrusted/legacy target devices.

    - A SHORT timeout is always applied (these are live exploit/PoC probes;
      we don't want a single unresponsive device to stall a worker).
    - No automatic retries: retrying against a fragile/hostile device can
      trigger lockouts or simply be abusive.
    - TLS verification defaults to True but is an EXPLICIT, per-call
      parameter, so disabling it for a legacy device with broken TLS is a
      deliberate, visible choice rather than a scattered `verify=False`.
    - A descriptive User-Agent is sent.
    """

    def __init__(self, timeout=ACTIVE_TIMEOUT, user_agent=ACTIVE_USER_AGENT,
                 max_response_bytes=MAX_RESPONSE_BYTES, max_duration=ACTIVE_MAX_DURATION):
        self.timeout = timeout
        self.user_agent = user_agent
        self.max_response_bytes = max_response_bytes
        self.max_duration = max_duration

    def _request(self, method, url, verify=True, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        if kwargs.get('allow_redirects', False):
            raise ValueError('ActiveClient does not follow redirects')
        kwargs['allow_redirects'] = False
        kwargs["stream"] = True

        headers = dict(kwargs.pop("headers", None) or {})
        headers.setdefault("User-Agent", self.user_agent)
        kwargs["headers"] = headers

        max_bytes = kwargs.pop('max_response_bytes', self.max_response_bytes)
        response = requests.request(method, url, verify=verify, **kwargs)
        deadline = time.monotonic() + self.max_duration
        total = 0
        chunks = []
        try:
            for chunk in response.iter_content(chunk_size=DOWNLOAD_CHUNK_SIZE):
                if time.monotonic() > deadline:
                    raise requests.exceptions.Timeout('Active response exceeded time limit')
                if not chunk:
                    continue
                total += len(chunk)
                if total > max_bytes:
                    raise ResponseTooLarge('Response body exceeded %d bytes limit' % max_bytes)
                chunks.append(chunk)
            response._content = b''.join(chunks)
            response._content_consumed = True
            return response
        finally:
            response.close()

    def get(self, url, verify=True, **kwargs):
        return self._request("GET", url, verify=verify, **kwargs)

    def post(self, url, verify=True, **kwargs):
        return self._request("POST", url, verify=verify, **kwargs)

    def put(self, url, verify=True, **kwargs):
        return self._request("PUT", url, verify=verify, **kwargs)


def passive_get(url, **kwargs):
    """Convenience one-shot helper: GET `url` via a fresh PassiveClient."""
    return PassiveClient().get(url, **kwargs)


def passive_post(url, **kwargs):
    """Convenience one-shot helper: POST `url` via a fresh PassiveClient."""
    return PassiveClient().post(url, **kwargs)
