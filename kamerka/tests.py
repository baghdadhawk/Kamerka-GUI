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
    SHODAN_MAX_ATTEMPTS,
    attackers_infra_queries,
    build_family_selection,
    expand_families,
    healthcare_queries,
    ics_queries,
    resolve_family,
    shodan_search_worker,
)


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


class FakeShodanClient:
    """Stand-in for shodan.Shodan. `search_fn(query, page)` decides the
    behavior/response for every call, and every call is recorded."""

    def __init__(self, api_key, search_fn, calls):
        self.api_key = api_key
        self._search_fn = search_fn
        self._calls = calls

    def search(self, query, page=1):
        self._calls.append((query, page))
        return self._search_fn(query, page)


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
