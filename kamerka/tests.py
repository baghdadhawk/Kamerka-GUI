"""Starter test suite for the pure search-selection logic and the Shodan
worker's control flow in kamerka/tasks.py.

None of these tests hit the network, Shodan, Redis or Celery: the Shodan
client and the per-result save routine are monkeypatched out, and
`time.sleep` is neutralized so retry/backoff tests run instantly.
"""
from unittest import mock

from django.test import TestCase

from app_kamerka.models import Search
from kamerka import tasks
from kamerka.tasks import (
    ALL_FAMILIES,
    GROUPABLE_PORT_FAMILIES,
    SHODAN_MAX_ATTEMPTS,
    attackers_infra_queries,
    build_family_selection,
    count_devices,
    expand_families,
    healthcare_queries,
    ics_queries,
    partition_groupable,
    resolve_family,
    shodan_search_worker,
    shodan_search_worker_grouped,
)
from kamerka.providers.settings import ProviderSettings, load_provider_settings


class ExpandFamiliesTests(TestCase):
    def test_all_sentinel_expands_to_every_family_in_category(self):
        self.assertEqual(
            expand_families([ALL_FAMILIES], 'ics'),
            list(ics_queries.keys()),
        )
        self.assertEqual(
            expand_families([ALL_FAMILIES], 'healthcare'),
            list(healthcare_queries.keys()),
        )
        self.assertEqual(
            expand_families([ALL_FAMILIES], 'infra'),
            list(attackers_infra_queries.keys()),
        )

    def test_non_sentinel_keys_pass_through_unchanged(self):
        self.assertEqual(expand_families(['modbus', 'siemens'], 'ics'), ['modbus', 'siemens'])

    def test_empty_or_none_keys(self):
        self.assertEqual(expand_families([], 'ics'), [])
        self.assertEqual(expand_families(None, 'ics'), [])


class ResolveFamilyTests(TestCase):
    def test_resolves_known_key_without_hint(self):
        self.assertEqual(resolve_family('modbus'), (ics_queries['modbus'], 'ics'))
        self.assertEqual(resolve_family('zoll'), (healthcare_queries['zoll'], 'healthcare'))
        self.assertEqual(resolve_family('msf'), (attackers_infra_queries['msf'], 'infra'))

    def test_resolves_with_correct_hint(self):
        self.assertEqual(
            resolve_family('modbus', category_hint='ics'),
            (ics_queries['modbus'], 'ics'),
        )

    def test_hint_disambiguates_and_rejects_wrong_category(self):
        # 'modbus' only exists in the ics dict, so asking for it under
        # healthcare should find nothing.
        self.assertIsNone(resolve_family('modbus', category_hint='healthcare'))

    def test_unknown_key_returns_none(self):
        self.assertIsNone(resolve_family('totally_not_a_real_family'))
        self.assertIsNone(resolve_family('totally_not_a_real_family', category_hint='ics'))


class BuildFamilySelectionTests(TestCase):
    def test_all_expands_to_every_family(self):
        selection = build_family_selection(ics=[ALL_FAMILIES])
        self.assertEqual(len(selection), len(ics_queries))
        resolved_keys = {key for key, _query, _category in selection}
        self.assertEqual(resolved_keys, set(ics_queries.keys()))
        for _key, query, category in selection:
            self.assertEqual(category, 'ics')

    def test_direct_and_all_duplicate_collapses(self):
        # 'modbus' selected directly AND pulled in again via __all__ should
        # only appear once in the resolved selection.
        selection = build_family_selection(ics=['modbus', ALL_FAMILIES])
        self.assertEqual(len(selection), len(ics_queries))
        modbus_entries = [s for s in selection if s[0] == 'modbus']
        self.assertEqual(len(modbus_entries), 1)

    def test_mixed_category_selection_resolves_each_correctly(self):
        selection = build_family_selection(
            ics=['modbus'], healthcare=['zoll'], infra=['msf'],
        )
        by_key = {key: (query, category) for key, query, category in selection}
        self.assertEqual(len(selection), 3)
        self.assertEqual(by_key['modbus'], (ics_queries['modbus'], 'ics'))
        self.assertEqual(by_key['zoll'], (healthcare_queries['zoll'], 'healthcare'))
        self.assertEqual(by_key['msf'], (attackers_infra_queries['msf'], 'infra'))

    def test_unknown_keys_are_dropped(self):
        selection = build_family_selection(ics=['not_a_real_key'], healthcare=['also_fake'])
        self.assertEqual(selection, [])

    def test_no_arguments_returns_empty(self):
        self.assertEqual(build_family_selection(), [])


class PartitionGroupableTests(TestCase):
    def test_splits_groupable_ics_from_the_rest(self):
        selection = build_family_selection(
            ics=['niagara', 'dnp3', 'modbus', 'codesys'],
            healthcare=['zoll'],
            infra=None,
        )
        groupable, rest = partition_groupable(selection)

        self.assertEqual({key for key, _q, _c in groupable}, {'niagara', 'dnp3'})
        self.assertTrue(all(category == 'ics' for _k, _q, category in groupable))

        rest_keys = {key for key, _q, _c in rest}
        # non-curated ICS families and the healthcare family both stay in rest.
        self.assertIn('modbus', rest_keys)
        self.assertIn('codesys', rest_keys)
        self.assertIn('zoll', rest_keys)
        self.assertEqual(len(rest), 3)

    def test_infra_and_healthcare_never_grouped_even_if_key_collides(self):
        # None of the curated port-family keys collide with healthcare/infra
        # dicts, but the partition must key off category, not just the name,
        # so healthcare/infra selections always land in `rest`.
        selection = build_family_selection(healthcare=['zoll'], infra=None)
        groupable, rest = partition_groupable(selection)
        self.assertEqual(groupable, [])
        self.assertEqual(len(rest), 1)

    def test_all_ics_expands_and_splits_correctly(self):
        selection = build_family_selection(ics=[ALL_FAMILIES])
        groupable, rest = partition_groupable(selection)

        expected_groupable_keys = set(GROUPABLE_PORT_FAMILIES.keys())
        self.assertEqual({key for key, _q, _c in groupable}, expected_groupable_keys)
        self.assertEqual(len(groupable) + len(rest), len(selection))

    def test_empty_selection(self):
        self.assertEqual(partition_groupable([]), ([], []))


class FakeShodanClient:
    """Stand-in for shodan.Shodan. `search_fn(query, page)` decides the
    behavior/response for every call, and every call is recorded. `count_fn`,
    if given, backs api.count() the same way."""

    def __init__(self, api_key, search_fn, calls, count_fn=None, count_calls=None):
        self.api_key = api_key
        self._search_fn = search_fn
        self._calls = calls
        self._count_fn = count_fn
        self._count_calls = count_calls

    def search(self, query, page=1):
        self._calls.append((query, page))
        return self._search_fn(query, page)

    def count(self, query):
        if self._count_calls is not None:
            self._count_calls.append(query)
        if self._count_fn is None:
            raise AssertionError('count() called but no count_fn was configured')
        return self._count_fn(query)


class ShodanSearchWorkerTests(TestCase):
    def setUp(self):
        self.search = Search.objects.create(
            country='US', ics='modbus', coordinates='', coordinates_search='',
        )
        # Neutralize sleeps used for rate limiting / backoff so retry tests
        # run instantly instead of taking real wall-clock seconds.
        sleep_patcher = mock.patch.object(tasks.time, 'sleep', return_value=None)
        sleep_patcher.start()
        self.addCleanup(sleep_patcher.stop)

    def _patch_shodan(self, search_fn, count_fn=None):
        calls = []
        count_calls = []

        def shodan_factory(api_key):
            return FakeShodanClient(api_key, search_fn, calls, count_fn=count_fn, count_calls=count_calls)

        patcher = mock.patch.object(tasks, 'Shodan', shodan_factory)
        patcher.start()
        self.addCleanup(patcher.stop)
        self._last_count_calls = count_calls
        return calls

    def _patch_save(self):
        saved = []
        patcher = mock.patch.object(
            tasks, '_save_device_from_result',
            side_effect=lambda search, result, search_type, category, query: saved.append(
                (search_type, category, query)
            ),
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        return saved

    def test_query_cache_avoids_duplicate_api_calls(self):
        """Two different family selections resolving to the exact same
        (query, country) should only hit the fake Shodan API once, while
        still producing a saved Device per selection."""

        def search_fn(query, page):
            return {'total': 1, 'matches': [{'ip_str': '1.2.3.4'}]}

        calls = self._patch_shodan(search_fn)
        saved = self._patch_save()

        query_cache = {}
        shodan_search_worker(
            fk=self.search.id, query='same query', search_type='a', category='ics',
            country='US', query_cache=query_cache,
        )
        shodan_search_worker(
            fk=self.search.id, query='same query', search_type='b', category='ics',
            country='US', query_cache=query_cache,
        )

        self.assertEqual(len(calls), 1)
        self.assertEqual(len(saved), 2)
        self.assertEqual({s[0] for s in saved}, {'a', 'b'})

    def test_persistent_failure_retried_then_gives_up(self):
        """A persistently-failing API must be retried exactly
        SHODAN_MAX_ATTEMPTS times and then give up (no infinite loop)."""

        def search_fn(query, page):
            raise RuntimeError('shodan is down')

        calls = self._patch_shodan(search_fn)
        self._patch_save()

        shodan_search_worker(
            fk=self.search.id, query='bad query', search_type='a', category='ics',
            country='US',
        )

        self.assertEqual(len(calls), SHODAN_MAX_ATTEMPTS)

    def test_pagination_fetches_expected_number_of_pages(self):
        """250 results in all_results mode should fetch 3 pages, not 4:
        pages = ceil(250/100) + 1 = 4 is a +1 sentinel used to detect 'no
        more pages', not an extra page to actually fetch."""

        def search_fn(query, page):
            return {'total': 250, 'matches': []}

        calls = self._patch_shodan(search_fn)
        self._patch_save()

        shodan_search_worker(
            fk=self.search.id, query='paged query', search_type='a', category='ics',
            country='US', all_results=True,
        )

        self.assertEqual([page for _query, page in calls], [1, 2, 3])


class ShodanSearchWorkerGroupedTests(TestCase):
    """group_ports=True: several curated ICS families are collapsed into one
    combined port: query, and matches are classified back to their family by
    port -- exactly one api.search call per page, instead of one per
    family."""

    def setUp(self):
        self.search = Search.objects.create(
            country='US', ics='niagara', coordinates='', coordinates_search='',
        )
        sleep_patcher = mock.patch.object(tasks.time, 'sleep', return_value=None)
        sleep_patcher.start()
        self.addCleanup(sleep_patcher.stop)

    def _patch_shodan(self, search_fn, count_fn=None):
        calls = []
        count_calls = []

        def shodan_factory(api_key):
            return FakeShodanClient(api_key, search_fn, calls, count_fn=count_fn, count_calls=count_calls)

        patcher = mock.patch.object(tasks, 'Shodan', shodan_factory)
        patcher.start()
        self.addCleanup(patcher.stop)
        return calls, count_calls

    def _patch_save(self):
        saved = []
        patcher = mock.patch.object(
            tasks, '_save_device_from_result',
            side_effect=lambda search, result, search_type, category, query: saved.append(
                (search_type, category, query)
            ),
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        return saved

    def test_one_combined_search_call_classifies_matches_by_port(self):
        selection = build_family_selection(ics=['niagara', 'dnp3', 'hart'])
        groupable, rest = partition_groupable(selection)
        self.assertEqual(rest, [])
        self.assertEqual(len(groupable), 3)

        def search_fn(query, page):
            # One combined query covering all three families' ports.
            self.assertIn('port:', query)
            for port in (1911, 20000, 5094):
                self.assertIn(str(port), query)
            return {
                'total': 3,
                'matches': [
                    {'port': 1911, 'ip_str': '1.1.1.1'},
                    {'port': 20000, 'ip_str': '2.2.2.2'},
                    {'port': 5094, 'ip_str': '3.3.3.3'},
                ],
            }

        calls, _count_calls = self._patch_shodan(search_fn)
        saved = self._patch_save()

        shodan_search_worker_grouped(fk=self.search.id, groupable=groupable, country='US')

        # Exactly one api.search call for the whole grouped batch (1 page).
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(saved), 3)
        self.assertEqual(
            {s[0] for s in saved},
            {'niagara', 'dnp3', 'hart'},
        )
        for search_type, category, _query in saved:
            self.assertEqual(category, 'ics')

    def test_match_with_unmapped_port_is_skipped(self):
        selection = build_family_selection(ics=['niagara'])
        groupable, _rest = partition_groupable(selection)

        def search_fn(query, page):
            return {
                'total': 2,
                'matches': [
                    {'port': 1911, 'ip_str': '1.1.1.1'},
                    {'port': 9999, 'ip_str': '9.9.9.9'},  # not in the map
                ],
            }

        self._patch_shodan(search_fn)
        saved = self._patch_save()

        shodan_search_worker_grouped(fk=self.search.id, groupable=groupable, country='US')

        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0][0], 'niagara')

    def test_mixed_groupable_and_non_groupable_runs_grouped_plus_individual(self):
        """A mix of groupable + non-groupable families: 1 grouped api.search
        call, plus one individual api.search call per non-groupable
        family -- driven through shodan_search itself."""
        selection = build_family_selection(ics=['niagara', 'dnp3', 'modbus'])
        groupable, rest = partition_groupable(selection)
        self.assertEqual({k for k, _q, _c in groupable}, {'niagara', 'dnp3'})
        self.assertEqual({k for k, _q, _c in rest}, {'modbus'})

        def search_fn(query, page):
            return {'total': 0, 'matches': []}

        calls, _count_calls = self._patch_shodan(search_fn)
        self._patch_save()

        query_cache = {}
        shodan_search_worker_grouped(fk=self.search.id, groupable=groupable, country='US',
                                     query_cache=query_cache)
        for key, query, category in rest:
            shodan_search_worker(fk=self.search.id, query=query, search_type=key, category=category,
                                 country='US', query_cache=query_cache)

        # 1 call for the grouped port query + 1 call for the remaining 'modbus' family.
        self.assertEqual(len(calls), 2)


class ShodanSearchGroupPortsDefaultBehaviorTests(TestCase):
    """Locks in that group_ports=False (including simply not passing it,
    since it defaults to False) leaves shodan_search's per-family search
    shape completely unchanged: still exactly one api.search call per
    selected family, none of them combined."""

    def setUp(self):
        self.search = Search.objects.create(
            country='US', ics='niagara', coordinates='', coordinates_search='',
        )
        sleep_patcher = mock.patch.object(tasks.time, 'sleep', return_value=None)
        sleep_patcher.start()
        self.addCleanup(sleep_patcher.stop)

    def _patch_shodan(self, search_fn):
        calls = []

        def shodan_factory(api_key):
            return FakeShodanClient(api_key, search_fn, calls)

        patcher = mock.patch.object(tasks, 'Shodan', shodan_factory)
        patcher.start()
        self.addCleanup(patcher.stop)
        return calls

    def _patch_save(self):
        saved = []
        patcher = mock.patch.object(
            tasks, '_save_device_from_result',
            side_effect=lambda search, result, search_type, category, query: saved.append(
                (search_type, category, query)
            ),
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        return saved

    def test_group_ports_false_runs_one_search_per_family_uncombined(self):
        def search_fn(query, page):
            self.assertNotIn('port:1911,4911,', query)  # never combined
            return {'total': 0, 'matches': []}

        calls = self._patch_shodan(search_fn)
        self._patch_save()

        # Calling a Celery task object directly (rather than .delay()/
        # .apply_async()) runs it synchronously in-process -- no broker
        # needed for this test.
        tasks.shodan_search(fk=self.search.id, country='US',
                            ics=['niagara', 'dnp3', 'hart'])

        # One api.search call per selected family: no grouping happened.
        self.assertEqual(len(calls), 3)

    def test_group_ports_true_collapses_curated_families_into_one_call(self):
        def search_fn(query, page):
            return {'total': 0, 'matches': []}

        calls = self._patch_shodan(search_fn)
        self._patch_save()

        tasks.shodan_search(fk=self.search.id, country='US',
                            ics=['niagara', 'dnp3', 'hart'], group_ports=True)

        # All three are in the curated allowlist -> exactly one combined call.
        self.assertEqual(len(calls), 1)


class CountDevicesTests(TestCase):
    """count_devices() must use api.count (zero query credits), never
    api.search."""

    def _patch_shodan(self, count_fn):
        search_calls = []
        count_calls = []

        def shodan_factory(api_key):
            return FakeShodanClient(api_key, lambda q, p: (_ for _ in ()).throw(
                AssertionError('api.search should never be called by count_devices')
            ), search_calls, count_fn=count_fn, count_calls=count_calls)

        patcher = mock.patch.object(tasks, 'Shodan', shodan_factory)
        patcher.start()
        self.addCleanup(patcher.stop)
        return search_calls, count_calls

    def test_uses_count_not_search(self):
        def count_fn(query):
            self.assertEqual(query, 'country:US port:1911,4911 product:Niagara')
            return {'total': 42}

        search_calls, count_calls = self._patch_shodan(count_fn)

        total = count_devices('US', 'port:1911,4911 product:Niagara')

        self.assertEqual(total, 42)
        self.assertEqual(search_calls, [])
        self.assertEqual(len(count_calls), 1)

    def test_xx_country_omits_country_prefix(self):
        def count_fn(query):
            self.assertEqual(query, 'some query')
            return {'total': 5}

        self._patch_shodan(count_fn)
        self.assertEqual(count_devices('XX', 'some query'), 5)


class ProviderSettingsTests(TestCase):
    """load_provider_settings()/ProviderSettings: keys.json loads into a
    validated, immutable settings object, and a missing/absent key reports
    as unavailable instead of raising."""

    def test_loads_keys_from_raw_dict(self):
        settings = load_provider_settings({
            'keys': {
                'shodan': 'SHODAN_KEY',
                'binaryedge': 'BE_KEY',
                'whoisxmlapi': 'WHOIS_KEY',
                'google_maps': 'MAPS_KEY',
            }
        })

        self.assertEqual(settings.shodan_key, 'SHODAN_KEY')
        self.assertEqual(settings.binaryedge_key, 'BE_KEY')
        self.assertEqual(settings.whoisxmlapi_key, 'WHOIS_KEY')
        self.assertEqual(settings.google_maps_key, 'MAPS_KEY')
        self.assertTrue(settings.is_configured('shodan'))
        self.assertEqual(settings.unavailable_providers(), [])

    def test_missing_key_is_unavailable_not_a_crash(self):
        settings = load_provider_settings({'keys': {'shodan': 'SHODAN_KEY'}})

        self.assertTrue(settings.is_configured('shodan'))
        self.assertFalse(settings.is_configured('binaryedge'))
        self.assertIsNone(settings.binaryedge_key)
        self.assertIn('binaryedge', settings.unavailable_providers())

        with self.assertRaises(Exception):
            settings.require('binaryedge')

    def test_missing_or_malformed_keys_file_never_raises(self):
        # A dict missing the "keys" section entirely, and one with an empty
        # "keys" section, both yield an all-None, non-crashing
        # ProviderSettings rather than raising.
        for raw in ({}, {'keys': {}}):
            settings = load_provider_settings(raw)
            self.assertIsInstance(settings, ProviderSettings)
            self.assertFalse(settings.is_configured('shodan'))
            self.assertEqual(
                sorted(settings.unavailable_providers()),
                ['binaryedge', 'google_maps', 'shodan', 'whoisxmlapi'],
            )

    def test_tasks_module_exposes_a_provider_settings_instance(self):
        self.assertIsInstance(tasks.provider_settings, ProviderSettings)

    def test_unreadable_keys_file_never_raises(self):
        from kamerka.providers import settings as provider_settings_module

        with mock.patch.object(provider_settings_module, 'get_keys', return_value=None):
            settings = load_provider_settings()

        self.assertIsInstance(settings, ProviderSettings)
        self.assertFalse(settings.is_configured('shodan'))
