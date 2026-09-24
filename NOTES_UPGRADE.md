# Upgrade notes

## What was upgraded

- Django 2.2.7 -> Django 4.2.13 (latest 4.2 LTS patch at time of writing).
- `django_jsonfield` (third-party `JSONField`) replaced with Django's native
  `django.db.models.JSONField` in `app_kamerka/models.py`
  (`BinaryEdgeScore.grades`, `BinaryEdgeScore.cve`). `django_jsonfield` was
  removed from `requirements.txt`.
- `celery_progress` bumped from unpinned (would have resolved to whatever
  was latest) to `0.5`, the first release that declares Django 4.2/5.x
  support.
- All previously-unpinned dependencies are now pinned to specific,
  mutually-compatible versions (see `requirements.txt`): `celery==5.3.6`,
  `redis==5.0.4`, `bs4==0.0.2`, `pynmea2==1.19.0`, `maxminddb==2.6.1`,
  `xmltodict==0.13.0`, `python-libnmap==0.7.3`, `lxml==5.2.1`,
  `celery_progress==0.5`, `python-twitter==3.5`.
- `app_kamerka/urls.py`: the celery-progress include used
  `path(r'^celery-progress/', include(...))`, a regex string passed to
  `path()` (which expects a plain route, not a regex). Fixed to
  `path('celery-progress/', include('celery_progress.urls'))`.
- `request.is_ajax()` (removed in Django 3.1+) replaced everywhere in
  `app_kamerka/views.py` with a local `is_ajax(request)` helper that checks
  the `X-Requested-With: XMLHttpRequest` header.
- `kamerka/settings.py`: dropped `USE_L10N` (removed in Django 5.0, a no-op
  since Django 4.0) and added an explicit `DEFAULT_AUTO_FIELD =
  'django.db.models.AutoField'` so `makemigrations` doesn't warn/prompt
  about the Django 3.2+ implicit-primary-key-type change (kept as
  `AutoField`, not `BigAutoField`, to match the original 2.2 behavior and
  avoid retroactively changing existing primary key columns).
- Generated the initial migration: `app_kamerka/migrations/0001_initial.py`
  (see below).

## Unmaintained / stale libraries (kept, pinned to newest working release)

- **python-twitter** (`python-twitter==3.5`): last released in 2018,
  effectively unmaintained, and the Twitter/X API it targets (v1.1) has
  since been heavily restricted/paywalled. It was left in place per scope
  (don't rip out functionality that needs external API keys to test), but
  if this project keeps using X/Twitter data going forward, consider
  migrating to `tweepy` (actively maintained, supports X API v2) instead.
- **flickrapi** (`flickrapi==2.4.0`, unchanged): last released in 2018.
  Still imports and runs under Python 3.11 in this environment, so it was
  left pinned as-is; no drop-in actively-maintained replacement was
  substituted since that would require re-testing the Flickr integration
  against a real API key.
- **pybinaryedge** (`pybinaryedge==0.5`, unchanged) and **shodan**
  (`shodan==1.19.0`, unchanged): both small, low-churn API client wrappers;
  left pinned to the versions already in use.

## Verified in this sandbox

- `python -m py_compile` on every changed `.py` file succeeded.
- `pip install -r requirements.txt` into a clean Python 3.11 venv succeeded
  with no build failures for any dependency (including `maxminddb`,
  `shodan`, `pybinaryedge`, `python-libnmap`, which the task brief flagged
  as possibly unbuildable here — they installed fine as prebuilt wheels /
  pure-Python packages in this sandbox).
- `DJANGO_SETTINGS_MODULE=kamerka.settings python -c "import django;
  django.setup()"` plus resolving the full URLconf (which imports
  `app_kamerka.views` and `kamerka.tasks`, and therefore every third-party
  dependency) succeeded with no errors.
- `python manage.py check` reported no issues.
- `python manage.py makemigrations app_kamerka` produced a clean
  `0001_initial.py` with no manual edits needed.
- `python manage.py migrate` applied that migration (and all built-in
  Django migrations) to a throwaway sqlite database with no errors.
- Smoke-tested several of the fixed AJAX views with Django's test client
  (logged-in session, `LoginRequiredMiddleware` satisfied): non-AJAX
  requests to `get_whois`, `get_shodan_scan_results`, etc. now return a
  proper `400`/`404` JSON response instead of Django's "did not return an
  HttpResponse" 500; AJAX requests continue to behave as before. An empty
  `ShodanScan` queryset for `get_shodan_scan_results` now returns a `404`
  JSON error instead of raising `IndexError`.

## Still needs manual/real-environment verification

- Nothing in this sandbox has real Shodan/BinaryEdge/Flickr/Twitter/WHOIS
  API credentials or a running Celery worker + Redis broker, so the actual
  task bodies in `kamerka/tasks.py` (network calls, Celery task execution)
  were not exercised end-to-end — only that the module imports cleanly and
  the views that dispatch tasks return sane HTTP responses when Celery/
  Redis are unavailable.
- `python-libnmap`'s Nmap-XML parsing and the `nmap_scan` upload flow in
  `search_main` were not exercised with a real Nmap XML file.
- No `nginx`/gunicorn/production deployment check was done; only Django's
  dev-server-equivalent checks (`manage.py check`, test client requests)
  were run.
- The `CSRF`, `LoginRequiredMiddleware`, and `SECURE_*` settings introduced
  before this task were not modified, but were not re-verified against
  Django 4.2's current defaults beyond `manage.py check` passing.
