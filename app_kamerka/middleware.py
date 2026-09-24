from django.conf import settings
from django.contrib.auth.views import redirect_to_login


class LoginRequiredMiddleware:
    """Require authentication for every view except an explicit allowlist.

    The application exposes endpoints that launch scans and query paid
    third-party APIs, so it must never be reachable anonymously. Rather than
    decorating each of the ~35 views individually (and risking one being
    missed), authentication is enforced globally here. The admin login page and
    static/media assets are exempt so users can actually log in and the UI can
    load its assets.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        # Paths that must stay reachable without authentication.
        self.exempt_prefixes = (
            '/admin/login',
            '/admin/logout',
            settings.STATIC_URL,
            getattr(settings, 'MEDIA_URL', None),
        )

    def __call__(self, request):
        path = request.path_info

        exempt = any(
            prefix and path.startswith(prefix) for prefix in self.exempt_prefixes
        )

        if not exempt and not request.user.is_authenticated:
            return redirect_to_login(request.get_full_path(), settings.LOGIN_URL)

        return self.get_response(request)
