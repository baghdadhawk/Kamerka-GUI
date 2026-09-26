"""Capability-based role enforcement and target-scope authorization for
active operations (S4 architecture-review stage).

Two independent gates are provided:

- require_capability(): a view decorator checking
  request.user.has_perm('app_kamerka.<capability>'). Backed by the custom
  permissions declared on Device.Meta.permissions and the Viewer/Analyst/
  Active Scanner/Exploit Operator/Administrator groups created by the
  0xxx_capability_groups data migration. A superuser holds every permission
  implicitly (django.contrib.auth.backends.ModelBackend.has_perm
  short-circuits to True for is_superuser), so superuser behavior is
  unchanged.

- is_target_authorized(): a plain function checking a target IP against the
  ScanAuthorization table, for the active (target-facing) operations --
  passive Shodan search itself needs no scope, only the run_search
  capability, since it queries Shodan rather than the target.
"""
import ipaddress
import json
from functools import wraps

from django.http import HttpResponse
from django.utils import timezone


def _forbidden(message):
    return HttpResponse(
        json.dumps({'Error': message}), content_type='application/json', status=403,
    )


def require_capability(capability, methods=None):
    """Decorator factory gating a view behind the given capability.

    `methods`, if given, is an iterable of HTTP methods (e.g. {'POST'}); the
    capability is only enforced for requests using one of those methods, and
    any other method is passed through to the view unchecked -- so a POST-
    only view's own method-not-allowed (405) handling for GET/etc keeps
    working exactly as before, instead of being pre-empted by a 403 here.
    Omit `methods` to enforce on every request method.
    """
    perm = 'app_kamerka.%s' % capability

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            if methods is None or request.method in methods:
                user = getattr(request, 'user', None)
                if not user or not user.is_authenticated or not user.has_perm(perm):
                    # Imported lazily -- app_kamerka.views imports this
                    # module, so importing it back at module load time would
                    # be a circular import.
                    from app_kamerka.views import record_audit
                    record_audit(
                        request, 'capability_denied',
                        target=getattr(view_func, '__name__', ''),
                        detail='missing capability: %s' % capability,
                        success=False,
                    )
                    return _forbidden('Forbidden: missing capability %s' % capability)
            return view_func(request, *args, **kwargs)
        return _wrapped
    return decorator


_OPERATION_FIELDS = {
    'port_scan': 'allow_port_scan',
    'exploit': 'allow_exploit',
}


def is_target_authorized(ip, operation):
    """True iff some non-expired ScanAuthorization row's `cidr` contains
    `ip` and its allow_<operation> flag is set. `operation` is 'port_scan'
    or 'exploit'. Never raises: an unparsable ip/cidr, or an unknown
    operation, is simply treated as "not authorized" rather than erroring
    out (fail closed).
    """
    from app_kamerka.models import ScanAuthorization  # avoid import-time cycle

    field = _OPERATION_FIELDS.get(operation)
    if not field or not ip:
        return False

    try:
        target = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False

    now = timezone.now()
    candidates = ScanAuthorization.objects.filter(**{field: True})

    for auth in candidates:
        if auth.expires_at is not None and auth.expires_at <= now:
            continue
        try:
            network = ipaddress.ip_network(str(auth.cidr).strip(), strict=False)
        except ValueError:
            continue
        if target in network:
            return True
    return False


def matching_authorizations(ip, operation):
    """Return matching authorization rows in deterministic preference order."""
    from app_kamerka.models import ScanAuthorization

    field = _OPERATION_FIELDS.get(operation)
    if not field or not ip:
        return []
    try:
        target = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return []
    now = timezone.now()
    matches = []
    for authorization in ScanAuthorization.objects.filter(**{field: True}).order_by('-created_at', 'pk'):
        if authorization.expires_at and authorization.expires_at <= now:
            continue
        try:
            if target in ipaddress.ip_network(str(authorization.cidr).strip(), strict=False):
                matches.append(authorization)
        except ValueError:
            continue
    return matches
