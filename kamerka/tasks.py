import json
import logging
import math
import re

import maxminddb
from libnmap.parser import NmapParser
import os
from time import sleep
import requests
from celery import shared_task, current_task
from celery_progress.backend import ProgressRecorder
from pybinaryedge import BinaryEdge
from shodan import Shodan
import time
from bs4 import BeautifulSoup
import pynmea2
import base64
import xmltodict

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
import xmltodict

from app_kamerka import exploits

from app_kamerka.models import Device, DeviceNearby, Search, ShodanScan, BinaryEdgeScore, \
    Whois, Bosch
from app_kamerka.honeypot import score_device
from app_kamerka.banner_utils import looks_like_generic_http_response
from app_kamerka.net import PassiveClient

from kamerka.discovery.queries import (
    attackers_infra_queries,
    coordinates_queries,
    healthcare_queries,
    ics_queries,
)
from kamerka.discovery.selection import (
    ALL_FAMILIES,
    GROUPABLE_PORT_FAMILIES,
    PORT_TO_FAMILY as _PORT_TO_FAMILY,
    build_family_selection,
    expand_families,
    partition_groupable,
    resolve_family,
)
from kamerka.providers.settings import (
    KEYS_FILE,
    ProviderSettings,
    get_keys,
    load_provider_settings,
)

logger = logging.getLogger(__name__)

# Categories where a generic/HTTP-error banner classified under a specific
# device family is suspicious enough to flag as a likely false positive (see
# _save_device_from_result). "coordinates" and "NMAP" are left out: those
# aren't family classifications in the same sense.
_FALSE_POSITIVE_SUSPECT_CATEGORIES = ("ics", "healthcare", "infra")

# The four query dicts, family-selection helpers, and provider key
# loading now live in kamerka/discovery and kamerka/providers -- imported
# above and re-exported here for backward compatibility (see module
# docstring / top-of-file imports).
#
# `keys` is kept exactly as before (the raw keys.json dict, loaded once at
# import time) since every task function below still reads it directly --
# changing that access pattern is out of scope for this refactor (see
# ProviderSettings for the new, validated alternative new code should
# prefer). `provider_settings` is the same data, additionally validated.
keys = get_keys()
provider_settings = load_provider_settings(keys)


@shared_task(bind=False)
def devices_nearby(lat, lon, id, query):
    SHODAN_API_KEY = keys['keys']['shodan']

    device = Device.objects.get(id=id)

    api = Shodan(SHODAN_API_KEY)
    fail = 0
    # Shodan sometimes fails with no reason, sleeping when it happens and it prevents rate limitation
    try:
        # Search Shodan
        results = api.search("geo:" + lat + "," + lon + ",15 " + query)
    except Exception:
        fail = 1
        logger.info("Shodan search failed once (retrying): geo:%s,%s,15 %s", lat, lon, query)

    if fail == 1:
        try:
            results = api.search("geo:" + lat + "," + lon + ",15 " + query)
        except Exception as e:
            logger.warning("Shodan search retry failed for geo:%s,%s,15 %s: %s", lat, lon, query, e)

    try:  # Show the results
        total = len(results['matches'])
        for counter, result in enumerate(results['matches']):
            if 'product' in result:
                product = result['product']
            else:
                product = ""
            current_task.update_state(state='PROGRESS',
                                      meta={'current': counter, 'total': total,
                                            'percent': int((float(counter) / total) * 100)})
            device1 = DeviceNearby(device=device, ip=result['ip_str'], product=product, org=result['org'],
                                   port=str(result['port']), lat=str(result['location']['latitude']),
                                   lon=str(result['location']['longitude']))
            device1.save()

        return {'current': total, 'total': total, 'percent': 100}
    except Exception as e:
        logger.warning("devices_nearby failed to process results: %s", e)


@shared_task(bind=True)
def shodan_search(self, fk, country=None, coordinates=None, ics=None, healthcare=None, coordinates_search=None,
                  all_results=False, infra=None, max_pages=None, group_ports=False):
    """Run a Shodan search for one Search row.

    `ics`, `healthcare` and `infra` are each an optional list of family keys
    for their respective category (see the *_queries dicts above); any of
    them may contain the ALL_FAMILIES ("__all__") sentinel to mean every
    family in that category. When more than one of them is provided they are
    all searched in this same run/Search row, with each resulting Device
    tagged with its own correct category.

    `healthcare` used to be a boolean flag (kept `ics` as the only list of
    selected keys); it is now itself a list of healthcare family keys, same
    shape as `ics`/`infra`. `coordinates`/`coordinates_search` are a separate
    flow, unrelated to country-based category search, and are unaffected by
    this change.

    An in-run cache (keyed by the exact Shodan query string + search scope)
    is shared across every family searched in this call, so if two different
    selections end up resolving to the exact same query, Shodan is only
    queried once and the cached matches are reused to create Device rows for
    both.

    `group_ports` is an OPT-IN optimization, default off. When True (and
    `country` is set), any selected ICS families that are in the curated
    GROUPABLE_PORT_FAMILIES allowlist are pulled out of the per-family loop
    and searched together in a single combined `port:...` query instead of
    one `api.search` call each (see partition_groupable/
    shodan_search_worker_grouped). Every other selected family (healthcare,
    infra, and any ICS family not in the allowlist) is still searched
    individually exactly as before. When group_ports is False (the default),
    behavior is byte-for-byte identical to before this option existed.
    """
    progress_recorder = ProgressRecorder(self)
    result = 0
    query_cache = {}

    if country:
        selection = build_family_selection(ics=ics, healthcare=healthcare, infra=infra)

        if group_ports:
            groupable, rest = partition_groupable(selection)
        else:
            groupable, rest = [], selection

        # The grouped search (if any) counts as a single progress step,
        # alongside one step per individually-searched family in `rest`.
        total = (1 if groupable else 0) + len(rest)
        c = 0

        if groupable:
            try:
                result += c
                shodan_search_worker_grouped(fk=fk, groupable=groupable, country=country,
                                             all_results=all_results, max_pages=max_pages,
                                             query_cache=query_cache)
                progress_recorder.set_progress(c + 1, total=total)
            except Exception as e:
                logger.exception("Grouped Shodan search failed for fk=%s: %s", fk, e)
            c += 1

        for key, query, category in rest:
            try:
                result += c
                shodan_search_worker(country=country, fk=fk, query=query, search_type=key,
                                     category=category, all_results=all_results,
                                     max_pages=max_pages, query_cache=query_cache)
                progress_recorder.set_progress(c + 1, total=total)
            except Exception as e:
                logger.exception("Shodan search failed for fk=%s query=%r: %s", fk, query, e)
            c += 1

    if coordinates:
        total = len(coordinates_search)
        for c, i in enumerate(coordinates_search):
            # print(coordinates_search[i])
            if i in coordinates_queries:
                try:
                    result += c
                    shodan_search_worker(fk=fk, query=coordinates_queries[i], search_type=i, category="coordinates",
                                         coordinates=coordinates, all_results=all_results,
                                         max_pages=max_pages, query_cache=query_cache)
                    progress_recorder.set_progress(c + 1, total=total)
                except Exception as e:
                    logger.exception("Coordinates Shodan search failed for fk=%s query=%r: %s", fk, i, e)
    return result


def check_credits():
    keys_list = []
    try:
        SHODAN_API_KEY = keys['keys']['shodan']

        api = Shodan(SHODAN_API_KEY)
        a = api.info()
        keys_list.append(a['query_credits'])
    except Exception as e:
        logger.warning("Failed to fetch Shodan credits: %s", e)

    try:
        be_key = keys['keys']['binaryedge']
        headers = {"X-Key": be_key}
        req = PassiveClient().get("https://api.binaryedge.io/v2/user/subscription", headers=headers)
        req_json = json.loads(req.content)
        keys_list.append(req_json['requests_left'])
    except Exception as e:
        logger.warning("Failed to fetch BinaryEdge credits: %s", e)

    return keys_list


def count_devices(country, query):
    """Return Shodan's total match count for `query` scoped to `country`,
    using api.count instead of api.search.

    api.count() costs ZERO Shodan query credits (unlike api.search(), which
    costs one credit per page), so this is safe to call freely to preview how
    many devices a search would return before actually running it.
    """
    SHODAN_API_KEY = keys['keys']['shodan']
    api = Shodan(SHODAN_API_KEY)

    if country == "XX":
        full_query = query
    else:
        full_query = "country:" + country + " " + query

    result = api.count(full_query)
    return result.get('total', 0)


def honeyscore(ip):
    """Best-effort wrapper around Shodan's api.honeyscore(ip): a 0.0-1.0
    probability that `ip` is a honeypot. Shodan's honeyscore endpoint is
    known to be flaky (rate limits, occasional 5xx/timeouts), so any
    failure is swallowed and reported as None rather than raising -- this
    is an on-demand, best-effort signal, not a hard dependency.
    """
    SHODAN_API_KEY = keys['keys']['shodan']
    try:
        api = Shodan(SHODAN_API_KEY)
        # In shodan-python the honeyscore endpoint lives on the `labs`
        # sub-client (api.labs.honeyscore), NOT directly on the client.
        result = api.labs.honeyscore(ip)
        return float(result)
    except Exception as e:
        logger.warning("honeyscore(%s) failed: %s", ip, e)
        return None


def _save_device_from_result(search, result, search_type, category, query):
    """Build and save one Device row from a single raw Shodan match `result`.

    Factored out of shodan_search_worker so it can run both against a fresh
    API response and against a cached list of matches reused for a
    duplicate-query search (see the query_cache handling below).
    """
    lat = str(result['location']['latitude'])
    lon = str(result['location']['longitude'])
    city = ""
    indicator = []
    screenshot = ""

    try:
        product = result['product']
    except Exception:
        product = ""

    if 'vulns' in result:
        vulns = [*result['vulns']]
    else:
        vulns = []

    if result['location']['city'] is not None:
        city = result['location']['city']

    hostnames = []
    try:
        hostnames = list(result.get('hostnames', []))
    except Exception:
        hostnames = []
    # score_device's cloud-provider heuristic does a case-insensitive
    # substring match against hostnames, so it still wants a single string
    # -- join every hostname rather than only ever seeing the first one.
    hostnames_text = " ".join(hostnames)

    try:
        if 'SAILOR' in result['http']['title']:
            html = result['http']['html']
            soup = BeautifulSoup(html)
            for gps in soup.find_all("span", {"id": "gnss_position"}):
                gps_coordinates = gps.contents[0]
                space = gps_coordinates.split(' ')
                if "W" in space:
                    lon = "-" + space[2][:-1]
                else:
                    lon = space[2][:-1]
                lat = space[0][:-1]
    except Exception:
        pass

    if 'opts' in result:
        try:
            screenshot = result['opts']['screenshot']['data']

            with open("app_kamerka/static/images/screens/" + result['ip_str'] + ".jpg", "wb") as fh:
                fh.write(base64.b64decode(screenshot))
                fh.close()
                for i in result['opts']['screenshot']['labels']:
                    indicator.append(i)
        except Exception:
            pass

    if query == "Niagara Web Server":
        try:
            soup = BeautifulSoup(result['http']['html'], features="html.parser")
            nws = soup.find("div", {"class": "top"})
            indicator.append(nws.contents[0])
        except Exception:
            pass

    if "SOURCETABLE" in query:
        data = result['data'].split(";")
        try:
            if re.match("^((\-?|\+?)?\d+(\.\d+)?)$", data[9]):
                indicator.append(data[9] + "," + data[10])
                lat = data[9]
                lon = data[10]
        except Exception:
            pass

    # get indicator from niagara fox
    if result['port'] == 1911 or result['port'] == 4911:
        try:
            fox_data_splitted = result['data'].split("\n")
            for i in fox_data_splitted:
                if "station.name" in i:
                    splitted = i.split(":")
                    indicator.append(splitted[1])
        except Exception:
            pass

    # get indicator from tank
    if result['port'] == 10001 and "Siemens" not in query:
        try:
            tank_info = result['data'].split("\r\n\r\n")
            indicator.append(tank_info[1])
        except Exception:
            pass

    if result['port'] == 2000:
        try:
            ta_data = result['data'].split("\\n")
            indicator.append(ta_data[1][:-3])
        except Exception:
            pass

    if result['port'] == 502:
        try:
            sch_el = result['data'].split('\n')
            if sch_el[4].startswith("-- Project"):
                indicator.append(sch_el[4].split(": ")[1])
        except Exception:
            pass

    if "GPGGA" in result['data']:
        try:
            splitted_data = result['data'].split('\n')
            for i in splitted_data:
                if "GPGGA" in i:
                    msg = pynmea2.parse(i)
                    lat = msg.latitude
                    lon = msg.longitude
                    break
        except Exception:
            pass

    if result['port'] == 102:
        try:
            s7_data = result['data'].split("\n")
            for i in s7_data:
                if i.startswith("Plant"):
                    indicator.append(i.split(":")[1])
                if i.startswith("PLC"):
                    indicator.append(i.split(":")[1])
                if i.startswith("Module name"):
                    indicator.append(i.split(":")[1])
        except Exception:
            pass
    # get indicator from bacnet
    if result['port'] == 47808:
        try:
            bacnet_data_splitted = result['data'].split("\n")
            for i in bacnet_data_splitted:
                if "Description" in i:
                    splitted1 = i.split(":")
                    indicator.append(splitted1[1])
                if "Object Name" in i:
                    splitted2 = i.split(":")
                    indicator.append(splitted2[1])

                if "Location" in i:
                    splitted3 = i.split(":")
                    indicator.append(splitted3[1])
        except Exception:
            pass

    device = Device(search=search, ip=result['ip_str'], product=product, org=result['org'],
                    data=result['data'], port=str(result['port']), type=search_type, city=city,
                    lat=lat, lon=lon,
                    country_code=result['location']['country_code'], query=search_type, category=category,
                    vulns=vulns, indicator=indicator, hostnames=hostnames, screenshot=screenshot)

    # Local (offline, no extra API calls) honeypot heuristic. Best-effort:
    # a scoring error must never prevent the device from being saved.
    try:
        honeypot_score, honeypot_reasons = score_device(
            data=result.get('data', ''), product=product, org=result.get('org', ''),
            hostnames=hostnames_text, port=result.get('port'), category=category,
            ip=result.get('ip_str'), type=search_type,
        )
        device.honeypot_score = honeypot_score
        device.honeypot_reasons = json.dumps(honeypot_reasons)
    except Exception as e:
        logger.warning("honeypot scoring failed for %s: %s", result.get('ip_str'), e)

    # Suspected-false-positive flag: a generic/HTTP-error banner (see
    # banner_utils.looks_like_generic_http_response) classified under an
    # ICS/healthcare/infra family, with no sign of that family anywhere in
    # the banner itself. Conservative on purpose (favors false negatives):
    # only fires when the banner is already flagged as generic AND the
    # family name is nowhere in it. Persistent, non-destructive -- never
    # blocks saving on error.
    try:
        if category in _FALSE_POSITIVE_SUSPECT_CATEGORIES and looks_like_generic_http_response(result.get('data', '')):
            family_token = (search_type or "").strip().lower()
            banner_lower = (result.get('data') or "").lower()
            has_family_token = bool(family_token) and family_token in banner_lower
            if not has_family_token:
                device.suspected_false_positive = True
    except Exception as e:
        logger.warning("suspected_false_positive computation failed for %s: %s", result.get('ip_str'), e)

    device.save()


# Bounded retry settings for a single Shodan API call. The old code retried
# forever on any exception (a malformed query, or Shodan being briefly down,
# would hang the worker indefinitely and could keep burning query credits).
SHODAN_MAX_ATTEMPTS = 5
SHODAN_BACKOFF_CAP_SECONDS = 30


def _run_shodan_query(fk, query, on_result, country=None, coordinates=None, all_results=False,
                      max_pages=None, query_cache=None):
    """Run one Shodan query, paginating/retrying/caching exactly as before,
    and call `on_result(search, result)` for every raw match (fresh or
    replayed from the cache).

    Factored out of shodan_search_worker so shodan_search_worker (one query ->
    one family) and shodan_search_worker_grouped (one combined query -> many
    families, classified per-match by port) can share the same pagination,
    bounded-retry, max_pages and query_cache machinery instead of duplicating
    it. `_save_device_from_result` itself is called from `on_result`, by the
    caller, so each caller decides what search_type/category a given match is
    saved under.

    `max_pages`, if given, caps how many pages are fetched even when
    all_results=True (an "approximate run" knob). Default behavior is
    unchanged: all_results=False still fetches exactly 1 page, and
    all_results=True still fetches every page unless max_pages is passed.

    `query_cache`, if given, is a dict shared across every family searched in
    the same shodan_search run, keyed on the exact query string + search
    scope (country/coordinates). If this exact query was already searched
    earlier in the run, the cached matches are replayed through `on_result`
    without hitting the Shodan API again.
    """
    SHODAN_API_KEY = keys['keys']['shodan']
    logger.info("Running Shodan query: %s", query)

    cache_key = (query, country, coordinates)
    if query_cache is not None and cache_key in query_cache:
        logger.info("Reusing cached results for duplicate query: %s", query)
        search = Search.objects.get(id=fk)
        for result in query_cache[cache_key]:
            on_result(search, result)
        return

    collected_matches = []
    api = Shodan(SHODAN_API_KEY)
    page = 1
    pages = None

    while True:
        # `pages` carries a +1 sentinel (see below), so stop once we've reached
        # it: `>=`, not `>`, otherwise one extra (empty) page is fetched, which
        # wastes a Shodan query credit per family in all_results mode.
        if pages is not None and page >= pages:
            break
        if max_pages and page > max_pages:
            break

        search = Search.objects.get(id=fk)

        # Shodan sometimes fails with no reason; retry with backoff instead of
        # sleeping/retrying forever, which could hang the worker and bleed
        # query credits on a persistently-failing (e.g. malformed) query.
        results = None
        for attempt in range(1, SHODAN_MAX_ATTEMPTS + 1):
            try:
                time.sleep(3)
                if coordinates:
                    results = api.search("geo:" + coordinates + ",20 " + query, page)
                elif country == "XX":
                    results = api.search(query, page)
                else:
                    results = api.search("country:" + country + " " + query, page)
                break
            except Exception as e:
                logger.warning('Shodan search failed (attempt %d/%d) for query %r: %s',
                              attempt, SHODAN_MAX_ATTEMPTS, query, e)
                results = None
                if attempt < SHODAN_MAX_ATTEMPTS:
                    time.sleep(min(2 ** attempt, SHODAN_BACKOFF_CAP_SECONDS))

        if results is None:
            logger.warning("Giving up on query after %d attempts: %s", SHODAN_MAX_ATTEMPTS, query)
            break

        try:
            total = results['total']

            if total == 0:
                logger.info("No results for query: %s", query)
                break
        except Exception as e:
            logger.warning("Failed to read result total for query %r: %s", query, e)
            break

        pages = math.ceil(total / 100) + 1
        # Note: don't fold max_pages into `pages` here — the `page > max_pages`
        # guard at the top of the loop already caps the number of pages fetched,
        # and min()'ing it in interacts badly with the +1 sentinel above.
        logger.info("Pages: %s", pages)

        for result in results['matches']:
            collected_matches.append(result)
            on_result(search, result)

        page = page + 1
        if not all_results:
            break

    if query_cache is not None:
        query_cache[cache_key] = collected_matches


def shodan_search_worker(fk, query, search_type, category, country=None, coordinates=None, all_results=False,
                         max_pages=None, query_cache=None):
    """Run one Shodan query and save a Device row per match, tagged with the
    single given search_type/category. See _run_shodan_query for the shared
    pagination/retry/cache behavior."""

    def on_result(search, result):
        _save_device_from_result(search, result, search_type, category, query)

    _run_shodan_query(fk, query, on_result, country=country, coordinates=coordinates,
                      all_results=all_results, max_pages=max_pages, query_cache=query_cache)


def shodan_search_worker_grouped(fk, groupable, country, all_results=False, max_pages=None, query_cache=None):
    """Run ONE combined `port:...` Shodan query covering every family in
    `groupable` (as returned by partition_groupable — all category "ics" and
    all keys in GROUPABLE_PORT_FAMILIES), and classify each returned match
    back to its family locally by port via _PORT_TO_FAMILY, saving it with
    that family's own (search_type, category).

    This is the opt-in query-credit optimization: N groupable families would
    normally cost N `api.search` calls (one per family, via
    shodan_search_worker); here they cost exactly one combined `api.search`
    call per page instead, since every port in the curated allowlist
    unambiguously identifies one family. A match whose port isn't in the map
    (shouldn't happen, since the query itself is `port:<only those ports>`)
    is silently skipped.

    Reuses _run_shodan_query for pagination/bounded-retry/max_pages/
    query_cache, exactly like shodan_search_worker.
    """
    if not groupable:
        return

    ports = sorted({port for key, _query, _category in groupable
                    for port in GROUPABLE_PORT_FAMILIES.get(key, [])})
    if not ports:
        return

    combined_query = "port:" + ",".join(str(p) for p in ports)
    # key -> (search_type, category) for every family in this grouped search.
    # search_type is just the family key, same as the individual-search path.
    families_by_key = {key: (key, category) for key, _query, category in groupable}

    def on_result(search, result):
        family_key = _PORT_TO_FAMILY.get(result.get('port'))
        if family_key is None or family_key not in families_by_key:
            return
        search_type, category = families_by_key[family_key]
        _save_device_from_result(search, result, search_type, category, combined_query)

    _run_shodan_query(fk, combined_query, on_result, country=country, all_results=all_results,
                      max_pages=max_pages, query_cache=query_cache)


def nmap_host_worker(host_arg, max_reader, search):
    ports_list = []
    hostname = host_arg.hostnames[0]

    a = max_reader.get(host_arg.address)
    logger.info("nmap host %s location: %s, %s", host_arg.address, a['location']['latitude'], a['location']['longitude'])
    for ports in host_arg.services:
        if ports.state == 'open':
            ports_list.append(ports.port)
        else:
            ports_list.append("None")

    ports_string = ', '.join(str(e) for e in ports_list)
    logger.info("nmap host %s ports: %s", host_arg.address, ports_string)
    device = Device(search=search, ip=host_arg.address, product="", org="",
                    data="", port=ports_string, type="NMAP", city="NMAP",
                    lat=a['location']['latitude'], lon=a['location']['longitude'],
                    country_code=a['country']['iso_code'], query="NMAP SCAN", category="NMAP",
                    vulns=[], indicator=[], hostnames=[hostname] if hostname else [], screenshot="")
    device.save()


def validate_nmap(file):
    NmapParser.parse_fromfile(os.getcwd() + file)


def validate_maxmind():
    maxminddb.open_database('GeoLite2-City.mmdb')


@shared_task(bind=True)
def nmap_scan(self, file, fk):
    progress_recorder = ProgressRecorder(self)
    result = 0
    logger.info("nmap_scan reading file: %s", os.getcwd() + file)
    search = Search.objects.get(id=fk)
    max_reader = maxminddb.open_database('GeoLite2-City.mmdb')
    nmap_report = NmapParser.parse_fromfile(os.getcwd() + file)
    total = len(nmap_report.hosts)
    for c, i in enumerate(nmap_report.hosts):
        result += c
        nmap_host_worker(host_arg=i, max_reader=max_reader, search=search)
        progress_recorder.set_progress(c + 1, total=total)
    return result


@shared_task(bind=False)
def shodan_scan_task(id):
    SHODAN_API_KEY = keys['keys']['shodan']
    device = Device.objects.get(id=id)
    api = Shodan(SHODAN_API_KEY)
    product = []
    tags = []
    vulns = []
    try:
        # Search Shodan
        results = api.host(device.ip)
        # Show the results
        total = len(results['ports'])
        logger.info("shodan_scan_task total ports: %s", total)
        for counter, i in enumerate(results['data']):

            if 'product' in i:
                product.append(i['product'])

            if 'tags' in i:
                for j in i['tags']:
                    tags.append(j)

            current_task.update_state(state='PROGRESS',
                                      meta={'current': counter, 'total': total,

                                            'percent': int((float(counter) / total) * 100)})
        if 'vulns' in results:
            vulns = results['vulns']

        ports = results['ports']
        device1 = ShodanScan(device=device, products=product,
                             ports=ports, tags=tags, vulns=vulns)
        device1.save()
        logger.info("shodan_scan_task ports: %s", results['ports'])

        return {'current': total, 'total': total, 'percent': 100}

    except Exception as e:
        logger.warning("shodan_scan_task failed: %s", e.args)


@shared_task(bind=False)
def binary_edge_scan(id):
    key = keys['keys']['binaryedge']
    device1 = Device.objects.get(id=id)
    be = BinaryEdge(key)
    results = be.host_score(device1.ip)
    normalized_ip_score = results['normalized_ip_score']

    cve = {}

    if 'cve' in results['results_detailed']:
        for cc in results['results_detailed']['cve']['result']:
            if isinstance(cc['cve'], list):
                for i in cc['cve']:
                    cve[i['cpe']] = i['cve_list']
            if isinstance(cc['cve'], dict):
                if 'cpe' in cc['cve']:
                    cve[cc['cve']['cpe'][0]] = cc['cve']['cve_list']

    device2 = BinaryEdgeScore(device=device1, grades=results['ip_score_detailed'], cve=cve, score=normalized_ip_score)
    device2.save()


ics_scan = {"dnp3": "--script=nmap_scripts/dnp3-info.nse", "niagara": "--script=nmap_scripts/fox-info.nse",
            "siemens": "--script=nmap_scripts/s7-info.nse", "proconos": "--script=nmap_scripts/proconos-info.nse",
            "pcworx": "--script=nmap_scripts/pcworx-info.nse", "omron": "--script=nmap_scripts/omron-info.nse",
            "modbus": "--script=nmap_scripts/modbus-discover.nse", "ethernetip": "--script=nmap_scripts/enip-info.nse",
            "codesys": "--script=nmap_scripts/codesys.nse", "ab_ethernet": "--script=nmap_scripts/cspv4-info.nse",
            "tank": "--script=nmap_scripts/atg-info.nse", "modicon": "--script=nmap_scripts/modicon-info.nse"}


@shared_task(bind=False, queue='active')
def scan_task(id):
    """Active Nmap scan of a single device.

    Routed to the dedicated 'active' Celery queue (see kamerka/settings.py
    CELERY_TASK_ROUTES) so deployments can run a worker consuming that queue
    on separate, network-isolated infrastructure from the default worker.
    Runs on a worker, not the request thread -- see scan_dev() in
    app_kamerka/views.py, which enqueues this via .delay(id) and returns the
    task id for polling instead of blocking on Nmap.
    """
    return_dict = {}
    device1 = Device.objects.get(id=id)
    ip = device1.ip
    port = device1.port
    type = device1.type

    if type in ics_scan.keys():
        nm = NmapProcess(ip, options="-p " + str(port) + " " + ics_scan[type])
        nm.run_background()

        while nm.is_running():
            logger.info("Nmap Scan running: ETC: %s DONE: %s%%", nm.etc, nm.progress)
            sleep(2)

        u = xmltodict.parse(nm.stdout)
        logger.info("%s", u['nmaprun'])

        try:
            for i in u['nmaprun']['host']['ports']['port']['script']:
                logger.info("%s", i)

                if i == "@output":
                    return_dict["ID"] = u['nmaprun']['host']['ports']['port']['script']["@id"]
                    return_dict["Output"] = u['nmaprun']['host']['ports']['port']['script']["@output"]

            device1.scan = return_dict
            device1.exploited_scanned = True
            device1.save()
            return return_dict


        except Exception as e:
            logger.warning("Nmap script scan failed to parse output: %s", e)
            return_dict["State"] = u['nmaprun']['host']['ports']['port']['state']["@state"]
            return_dict["Reason"] = u['nmaprun']['host']['ports']['port']['state']["@reason"]
            device1.scan = return_dict
            device1.exploited_scanned = True

            device1.save()
            return return_dict


    else:
        nm = NmapProcess(ip, options="-p " + str(port))
        nm.run_background()

        while nm.is_running():
            logger.info("Nmap Scan running: ETC: %s DONE: %s%%", nm.etc, nm.progress)
            sleep(2)

        u = xmltodict.parse(nm.stdout)

        try:
            return_dict["State"] = u['nmaprun']['host']['ports']['port']['state']['@state']
            return_dict["Reason"] = u['nmaprun']['host']['ports']['port']['state']['@reason']
            device1.scan = return_dict
            device1.exploited_scanned = True
            device1.save()
            return return_dict
        except Exception as e:
            logger.warning("Nmap plain scan failed to parse output: %s", e)


@shared_task(bind=False, queue='active')
def exploit_task(id):
    """Active exploitation/credential-check probe of a single device.

    Routed to the dedicated 'active' Celery queue -- see scan_task() above.
    Runs on a worker, not the request thread -- see exploit_dev() in
    app_kamerka/views.py, which enqueues this via .delay(id) and returns the
    task id for polling instead of blocking on the exploit probe.
    """
    device1 = Device.objects.get(id=id)
    logger.info("exploit() for device type: %s", device1.type)
    if device1.type == "bosch_security":
        usernames = exploits.bosch_usernames(device1)
        return usernames
    if device1.type == "hikvision":
        creds = exploits.hikvision(device1)
        return creds
    if device1.type == "videoiq":
        users = exploits.videoiq(device1)
        return users
    if device1.type == "contec":
        usernames = exploits.contec(device1)
        return usernames
    if device1.type == "grandstream":
        check = exploits.grandstream(device1)
        return check
    if device1.type == "netwave":
        status = exploits.netwave(device1)
        return status
    if device1.type == "CirCarLife":
        plc_status = exploits.circarlife(device1)
        return plc_status
    if device1.type == "amcrest":
        videotalk = exploits.amcrest(device1)
        return videotalk
    if device1.type == "lutron":
        config = exploits.lutron(device1)
        return config

    else:
        return {"Reason": "No exploit assigned"}


@shared_task(bind=False)
def whoisxml(id):
    api_key = keys['keys']['whoisxmlapi']
    device1 = Device.objects.get(id=id)

    end = "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=" + api_key + "&domainName=" + device1.ip + "&outputFormat=json"

    req = PassiveClient().get(end)

    req_json = json.loads(req.content)

    netrange = ""
    admin_org = ""
    admin_email = ""
    admin_phone = ""
    city = ""
    email = ""
    street = ""
    name = ""
    org = ""

    if 'administrativeContact' in req_json['WhoisRecord']['registryData']:
        admin_email = req_json['WhoisRecord']['registryData']['administrativeContact']['email'],
        admin_phone = req_json['WhoisRecord']['registryData']['administrativeContact']['telephone'],
        admin_org = req_json['WhoisRecord']['registryData']['administrativeContact']['organization']

    if 'registrant' in req_json['WhoisRecord']['registryData']:
        if "name" in req_json['WhoisRecord']['registryData']['registrant']:
            name = req_json['WhoisRecord']['registryData']['registrant']['name']
        if "organization" in req_json['WhoisRecord']['registryData']['registrant']:
            org = req_json['WhoisRecord']['registryData']['registrant']['organization']
        if "street1" in req_json['WhoisRecord']['registryData']['registrant']:
            street = req_json['WhoisRecord']['registryData']['registrant']['street1']

        if req_json['WhoisRecord']['registryData']['customField1Name'] == "netRange":
            netrange = req_json['WhoisRecord']['registryData']['customField1Value']
        if req_json['WhoisRecord']['registryData']['customField2Name'] == "netRange":
            netrange = req_json['WhoisRecord']['registryData']['customField2Value']

        if 'city' in req_json['WhoisRecord']['registryData']['registrant']:
            city = req_json['WhoisRecord']['registryData']['registrant']['city']

        if 'email' in req_json['WhoisRecord']['registryData']['registrant']:
            email = req_json['WhoisRecord']['registryData']['registrant']['email']

        wh = Whois(device=device1, org=org,
                   street=street,
                   city=city,
                   admin_org=admin_org,
                   admin_email=admin_email,
                   admin_phone=admin_phone, netrange=netrange, name=name, email=email)

        wh.save()


    elif 'subRecords' in req_json['WhoisRecord']:
        try:
            if "name" in req_json['WhoisRecord']['subRecords'][0]['registrant']:
                name = req_json['WhoisRecord']['subRecords'][0]['registrant']['name']
                if "street1" in req_json['WhoisRecord']['subRecords'][0]['registrant']:
                    street = req_json['WhoisRecord']['subRecords'][0]['registrant']['street1']
        except Exception as e:
            logger.info("whoisxml: no subRecords registrant name/street: %s", e)

        try:
            if req_json['WhoisRecord']['subRecords'][0]['customField1Name'] == "netRange":
                netrange = req_json['WhoisRecord']['subRecords'][0]['customField1Value']
            if req_json['WhoisRecord']['subRecords'][0]['customField2Name'] == "netRange":
                netrange = req_json['WhoisRecord']['subRecords'][0]['customField2Value']
        except Exception as e:
            logger.info("whoisxml: no subRecords netRange: %s", e)

        try:
            org = req_json['WhoisRecord']['subRecords'][0]['registrant']['organization']
            if 'city' in req_json['WhoisRecord']['subRecords'][0]['registrant']:
                city = req_json['WhoisRecord']['subRecords'][0]['registrant']['city']

            if 'email' in req_json['WhoisRecord']['subRecords'][0]['registrant']:
                email = req_json['WhoisRecord']['subRecords'][0]['registrant']['email']
        except Exception as e:
            logger.info("whoisxml: no subRecords org/city/email: %s", e)

        wh = Whois(device=device1, org=org,
                   street=street,
                   city=city,
                   admin_org=admin_org,
                   admin_email=admin_email,
                   admin_phone=admin_phone, netrange=netrange, name=name, email=email)

        wh.save()
