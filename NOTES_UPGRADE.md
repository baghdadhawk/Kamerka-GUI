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

## Multi-category search + Shodan call reduction (kamerka/tasks.py, app_kamerka/views.py, app_kamerka/forms.py, app_kamerka/templates/search_main.html)

- Added `resolve_family()`, `expand_families()` and `build_family_selection()`
  to `kamerka/tasks.py` (pure functions, no I/O). Together they:
  - resolve a family key (e.g. `"modbus"`) to its `(query, category)` across
    `healthcare_queries` / `ics_queries` / `attackers_infra_queries`,
  - expand a new `"__all__"` sentinel into every key of a given category,
  - de-duplicate the final `(key, query, category)` list so the same
    `(category, query)` is never searched twice in one run.
- `shodan_search()` now takes `ics`, `healthcare` and `infra` as three
  independent optional lists of family keys (each may contain `"__all__"`)
  instead of the old `ics` list + `healthcare` boolean flag, and searches all
  of them in the same run against the same `Search` row, with each `Device`
  tagged with its real category. Coordinates search is untouched and stays a
  separate flow/branch.
- The ICS tab in `search_main.html` gained two checkboxes, "Also include all
  Healthcare families" / "Also include all Attacker Infrastructure families",
  so one submit can span ICS + healthcare + infra in a single `Search` row.
  Each of the three family `<select multiple>`s (`ics_country`, `healthcare`,
  `infra`) also gained a `"__all__"` ("-- All ... families --") first option
  to select every family in that category without hand-picking each one.
- `app_kamerka/views.py::search_main` was updated to read these new
  controls, expand them into `ics=`/`healthcare=`/`infra=` lists passed to
  `shodan_search.delay(...)`, and to fix a pre-existing bug in the infra tab
  branch: it was calling `request.POST.getlist('country_infra')` to read the
  selected family list, but `country_infra` is the single-value country
  field — the family `<select multiple>` is named `infra`. That meant the
  infra tab's family selection was silently ignored before this change; it
  now reads `infra`.
- Shodan call reduction implemented:
  1. De-duplication (`build_family_selection`) plus an in-run `query_cache`
     dict, shared across every family searched in one `shodan_search` call
     and keyed on `(query, country, coordinates)`. If two selections resolve
     to the exact same query in the same run, Shodan is only queried once;
     the cached raw matches are replayed through `_save_device_from_result`
     to create correctly-tagged `Device` rows for the second (and any
     further) selection, with no extra API call.
  2. `shodan_search_worker`'s inner `while not fail:` retry loop (which
     retried forever on any exception — a malformed query could hang the
     worker and burn Shodan query credits indefinitely) was replaced with a
     bounded retry: up to `SHODAN_MAX_ATTEMPTS = 5` attempts with capped
     exponential backoff (`min(2 ** attempt, 30)` seconds); on exhaustion it
     logs and breaks out of that page's fetch instead of looping forever.
  3. Added an optional `max_pages` parameter (threaded through
     `shodan_search` → `shodan_search_worker`) to cap how many pages of
     results are fetched for an "approximate" run. Default behavior is
     unchanged: `all_results=False` still fetches exactly 1 page, and
     `all_results=True` still fetches every page when `max_pages` is not
     given.
- **Curly/smart quotes**: `attackers_infra_queries["covenant"]` is
  `'ssl:”Covenant” http.component:”Blazor”'` — it uses `”`(right double
  quotation mark) instead of a straight `"`. Shodan's query syntax expects
  straight quotes for exact-phrase matching, so this is not a valid
  exact-phrase query as currently written. Left unfixed (added a code
  comment instead) since swapping the quote characters would change what
  this query actually matches on live Shodan and could not be verified
  in this sandbox (no live Shodan access) — flagging it here for someone
  with API access to fix and re-verify results.
- **Deferred optimization (not implemented)**: the largest further cut in
  Shodan API calls would come from grouping the many `port:`-based ICS
  families (e.g. `niagara` on `port:1911,4911`, `dnp3` on `port:20000`,
  `hart` on `port:5094`, `gestrip` on `port:18245,18246`, `mitsubishi` on
  `port:5006,5007`, `omron` on `port:9600`, `redlion` on `port:789`, `iec`
  on `port:2404`, `proconos` on `port:20547`, `tank` on `port:10001`,
  `total_access` on `port:2000`, `doors` on `port:4070`, etc.) into a small
  number of `country:XX port:a,b,c,...` searches covering many ports at
  once, then classifying each match locally (by port, banner/`data`
  content, or the same string checks `_save_device_from_result` already
  does) instead of issuing one Shodan query per family. This could cut the
  number of Shodan queries for an "all ICS families" run substantially.
  It was **not** implemented here because: (a) several families share a
  port (e.g. `niagara` alone already uses two ports, `gestrip` and
  `mitsubishi` each use two), so classification would need to be
  content-based, not just port-based, for those; (b) some queries are not
  port-based at all (`bacnet`, `modbus`, `siemens`, etc. key off strings in
  the banner, not a fixed port) and would need their own grouping strategy
  or would have to stay as individual queries; (c) getting the
  classification wrong silently mislabels or drops real devices, which is
  a correctness risk that needs to be validated against live Shodan data,
  which this sandbox does not have access to. Left as a future option for
  someone who can verify it against real query results.

## Opt-in port-grouping optimization (implemented)

The port-grouping idea flagged above as a deferred optimization is now
implemented, as an **opt-in, curated** version of it, addressing the
correctness risk that previously blocked it: rather than grouping every
`port:`-based ICS family, only a small hand-picked allowlist is grouped,
chosen specifically so port -> family classification is unambiguous.

- **Default is unchanged.** `shodan_search(..., group_ports=False)` (the
  default, both as a Python default and as the checkbox's unchecked state
  in the UI) runs exactly the same one-`api.search`-call-per-family loop as
  before this change — byte-for-byte identical behavior, locked in by
  `ShodanSearchGroupPortsDefaultBehaviorTests` in `kamerka/tests.py`.
- **What `group_ports=True` does.** `kamerka/tasks.py` now has a hardcoded
  `GROUPABLE_PORT_FAMILIES` map (family key -> list of ports) and its
  reverse, `_PORT_TO_FAMILY` (port -> family key). `partition_groupable()`
  splits a `build_family_selection()` result into the selected ICS families
  that are in that map ("groupable") and everything else ("rest":
  healthcare, infra, and any ICS family not in the allowlist). When
  `group_ports=True` and `country` is set, `shodan_search` runs the
  groupable families as **one** combined
  `country:XX port:<all their ports, sorted, deduped>` search
  (`shodan_search_worker_grouped`), classifies each returned match back to
  its family purely by its `port` field via `_PORT_TO_FAMILY`, and saves it
  with that family's own `(search_type, category)` — then runs `rest`
  individually exactly as before. For a run selecting all 11 curated
  families, this turns 11 `api.search` calls into 1.
- **The curated allowlist and why these ports specifically:**
  `niagara` (1911, 4911), `dnp3` (20000), `hart` (5094), `pcworx` (1962),
  `iec` (2404), `proconos` (20547), `omron` (9600), `redlion` (789),
  `mitsubishi` (5006, 5007), `gestrip` (18245, 18246), `doors` (4070).
  Every port in this map belongs to **exactly one** family (even
  `niagara`'s two ports and `mitsubishi`'s/`gestrip`'s two ports each only
  ever map back to their own family), so a match's port unambiguously
  identifies its family — no content-based disambiguation is needed, unlike
  the general case the earlier deferred-optimization note worried about.
  Two categories of `ics_queries` ports were deliberately **excluded**
  from the map even though they are `port:`-based: (1) noisy shared ports
  like `tank` (`port:10001`) and `total_access` (`port:2000`), which are
  common/generic enough on those ports that folding them into the combined
  query would risk pulling in unrelated devices under the wrong family; and
  (2) families whose query isn't fundamentally a port filter (`bacnet`,
  `modbus`, `siemens`, `ethernetip`, `codesys`, etc. — these key off
  banner/string content, not a dedicated port), which stay in `rest` and
  are still searched individually regardless of `group_ports`.
- **Accepted trade-off.** The combined query for a grouped family only
  keeps `port:<n>`, dropping that family's own `product:`/string
  sub-filter (e.g. `niagara`'s `product:Niagara`, `pcworx`'s `PLC`). This
  can very slightly over-include devices that happen to listen on the same
  port without actually being that product. This was accepted deliberately
  for the families on the allowlist, since their ports are protocol-
  specific enough (assigned to that one ICS protocol) that the extra noise
  from dropping the sub-filter is expected to be small; it is exactly why
  the noisier shared ports (`tank`, `total_access`) were excluded instead
  of included with the same trade-off.
- **Free result-count preview (`api.count`, zero query credits).**
  `count_devices(country, query)` wraps Shodan's `api.count()` (unlike
  `api.search()`, `api.count()` never spends a query credit), and the new
  AJAX view `search_estimate` (`GET /search_estimate?country=..&ics=..&ics=..`,
  wired in `app_kamerka/urls.py`) uses it to return a per-family and total
  estimated device count for the currently-selected country + ICS families
  **without** running an actual paid search. The ICS tab in
  `search_main.html` has a "group protocol ports (fewer API calls)"
  checkbox (`name="group_ports"`, read in `views.search_main`'s ICS branch
  and passed through to `shodan_search.delay(...)`) and an
  "Estimate results (free)" button next to it that calls this endpoint and
  shows the total inline, so a user can sanity-check roughly how many
  results a search/credit spend will return before committing to it.
- **Needs live-Shodan verification.** All of the above (the grouped query
  shape, `_PORT_TO_FAMILY` classification, and `api.count()`'s query
  syntax/response shape) is covered by tests against a mocked Shodan client
  only, since this sandbox has no live Shodan access. Before relying on
  `group_ports=True` for a real run, spot-check it against live Shodan: run
  a small `group_ports=True` search and confirm (a) the combined
  `port:a,b,c,...` query is accepted, (b) matches land under the expected
  family, and (c) `api.count()` numbers are in the right ballpark versus an
  equivalent `api.search()` run's `total`.
