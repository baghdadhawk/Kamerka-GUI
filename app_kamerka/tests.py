from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, Client
from django.urls import reverse

from app_kamerka.models import Device, Search
from app_kamerka.views import is_ajax
from kamerka import tasks

User = get_user_model()


AJAX_HEADER = {'HTTP_X_REQUESTED_WITH': 'XMLHttpRequest'}


class IsAjaxHelperTests(TestCase):
    """django.http.HttpRequest.is_ajax() was removed in Django >= 3.1; the
    app defines its own replacement. Lock down that it actually detects the
    header Django's jQuery/etc. AJAX calls send."""

    def test_true_with_header(self):
        request = self.client.get('/admin/login/', **AJAX_HEADER).wsgi_request
        self.assertTrue(is_ajax(request))

    def test_false_without_header(self):
        request = self.client.get('/admin/login/').wsgi_request
        self.assertFalse(is_ajax(request))


class LoginRequiredMiddlewareTests(TestCase):
    """The app is meant to never be reachable anonymously (it launches scans
    and hits paid third-party APIs), except for the login page and static
    assets."""

    def test_anonymous_index_is_redirected_to_login(self):
        response = self.client.get('/index')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/admin/login/', response.url)

    def test_anonymous_search_main_is_redirected_to_login(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/admin/login/', response.url)

    def test_admin_login_page_not_redirected(self):
        response = self.client.get('/admin/login/')
        # Served directly (not bounced back through the login redirect loop).
        self.assertEqual(response.status_code, 200)

    def test_static_path_not_redirected(self):
        response = self.client.get('/static/does-not-exist.png')
        # No matching URL pattern for raw /static/ in this URLConf (it is
        # only served by the dev server / a web server, never through
        # urls.py), so this 404s -- the important assertion is that it is
        # NOT a 302 redirect to the login page, i.e. the middleware treated
        # it as exempt.
        self.assertNotEqual(response.status_code, 302)

    def test_authenticated_user_can_load_search_main(self):
        user = User.objects.create_user(username='tester', password='pw12345')
        client = Client()
        client.force_login(user)
        response = client.get('/')
        self.assertEqual(response.status_code, 200)


class AjaxViewBadRequestTests(TestCase):
    """A handful of AJAX-only views used to fall through and return None
    (=> a 500 from Django) for a plain (non-AJAX) request. They now return an
    explicit 400. These tests lock that fix in for a logged-in user hitting
    each endpoint without the X-Requested-With header."""

    def setUp(self):
        self.user = User.objects.create_user(username='tester', password='pw12345')
        self.client.force_login(self.user)

        search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        self.device = Device.objects.create(search=search, ip='1.2.3.4', type='modbus', category='ics')

    def test_get_nearby_devices_non_ajax_is_400(self):
        response = self.client.get(reverse('get_nearby_devices', args=[self.device.id]))
        self.assertEqual(response.status_code, 400)

    def test_get_nearby_devices_ajax_is_200(self):
        response = self.client.get(reverse('get_nearby_devices', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)

    def test_get_whois_non_ajax_is_400(self):
        response = self.client.get(reverse('get_whois', args=[self.device.id]))
        self.assertEqual(response.status_code, 400)

    def test_get_whois_ajax_is_200(self):
        response = self.client.get(reverse('get_whois', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)


class ShodanScanResultsTests(TestCase):
    """get_shodan_scan_results used to raise IndexError (=> 500) when there
    was no matching ShodanScan row; it now returns a proper 404."""

    def setUp(self):
        self.user = User.objects.create_user(username='tester', password='pw12345')
        self.client.force_login(self.user)

        search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        self.device = Device.objects.create(search=search, ip='1.2.3.4', type='modbus', category='ics')

    def test_no_scan_row_returns_404(self):
        response = self.client.get(
            reverse('get_shodan_scan_results', args=[self.device.id]), **AJAX_HEADER
        )
        self.assertEqual(response.status_code, 404)

    def test_non_ajax_is_400(self):
        response = self.client.get(reverse('get_shodan_scan_results', args=[self.device.id]))
        self.assertEqual(response.status_code, 400)


class SearchEstimateViewTests(TestCase):
    """The free (zero query-credit) estimate endpoint: it must use
    kamerka.tasks.count_devices (api.count) and never touch api.search."""

    def setUp(self):
        self.user = User.objects.create_user(username='tester', password='pw12345')
        self.client.force_login(self.user)

    def _patch_shodan(self, count_fn):
        search_calls = []

        class FakeShodanClient:
            def __init__(self, api_key):
                pass

            def search(self, query, page=1):
                search_calls.append((query, page))
                raise AssertionError('search_estimate must never call api.search')

            def count(self, query):
                return count_fn(query)

        patcher = mock.patch.object(tasks, 'Shodan', FakeShodanClient)
        patcher.start()
        self.addCleanup(patcher.stop)
        return search_calls

    def test_non_ajax_is_not_ok(self):
        response = self.client.get(reverse('search_estimate'), {'country': 'US', 'ics': 'niagara'})
        self.assertContains(response, 'NO OK')

    def test_missing_params_is_400(self):
        response = self.client.get(reverse('search_estimate'), **AJAX_HEADER)
        self.assertEqual(response.status_code, 400)

    def test_returns_per_family_and_total_counts_without_search(self):
        def count_fn(query):
            if 'Niagara' in query:
                return {'total': 7}
            return {'total': 3}

        search_calls = self._patch_shodan(count_fn)

        response = self.client.get(
            reverse('search_estimate'),
            {'country': 'US', 'ics': ['niagara', 'dnp3']},
            **AJAX_HEADER,
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['counts']['niagara'], 7)
        self.assertEqual(data['counts']['dnp3'], 3)
        self.assertEqual(data['total'], 10)
        self.assertEqual(search_calls, [])

    def test_all_families_sentinel_is_expanded(self):
        def count_fn(query):
            return {'total': 1}

        self._patch_shodan(count_fn)

        response = self.client.get(
            reverse('search_estimate'),
            {'country': 'US', 'ics': '__all__'},
            **AJAX_HEADER,
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data['counts']), len(tasks.ics_queries))


class ModelSmokeTests(TestCase):
    """A minimal smoke test that Search/Device save and relate correctly."""

    def test_search_and_device_relate(self):
        search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        device = Device.objects.create(search=search, ip='10.0.0.1', type='modbus', category='ics')

        self.assertEqual(device.search_id, search.id)
        self.assertEqual(Device.objects.filter(search=search).count(), 1)
        self.assertEqual(Device.objects.get(id=device.id).ip, '10.0.0.1')
