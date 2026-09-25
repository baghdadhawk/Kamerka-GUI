from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, Client
from django.urls import reverse

from app_kamerka.banner_utils import looks_like_generic_http_response
from app_kamerka.honeypot import score_device, HONEYPOT_THRESHOLD
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


class DevicesViewFilterTests(TestCase):
    """The `devices` view supports server-side GET filtering so dashboard
    and per-search infographics can link into a filtered device list."""

    def setUp(self):
        self.user = User.objects.create_user(username='tester', password='pw12345')
        self.client.force_login(self.user)

        self.search1 = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        self.search2 = Search.objects.create(country='DE', ics='bacnet', coordinates='', coordinates_search='')

        self.modbus_us = Device.objects.create(
            search=self.search1, ip='10.0.0.1', type='modbus', category='ics',
            port='502', country_code='US', vulns="['CVE-2020-1111']",
        )
        self.bacnet_de = Device.objects.create(
            search=self.search2, ip='10.0.0.2', type='bacnet', category='ics',
            port='47808', country_code='DE', vulns="['CVE-2019-2222']",
        )
        self.webcam_us = Device.objects.create(
            search=self.search1, ip='10.0.0.3', type='webcam', category='coordinates',
            port='80', country_code='US', vulns='',
        )

    def test_no_filters_returns_all(self):
        response = self.client.get(reverse('devices'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.context['devices']), {self.modbus_us, self.bacnet_de, self.webcam_us})
        self.assertEqual(response.context['filters'], {})

    def test_filter_by_port(self):
        response = self.client.get(reverse('devices'), {'port': '502'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context['devices']), [self.modbus_us])

    def test_filter_by_type(self):
        response = self.client.get(reverse('devices'), {'type': 'modbus'})
        self.assertEqual(list(response.context['devices']), [self.modbus_us])

    def test_filter_by_category(self):
        response = self.client.get(reverse('devices'), {'category': 'coordinates'})
        self.assertEqual(list(response.context['devices']), [self.webcam_us])

    def test_filter_by_country(self):
        response = self.client.get(reverse('devices'), {'country': 'US'})
        self.assertEqual(set(response.context['devices']), {self.modbus_us, self.webcam_us})

    def test_filter_by_country_case_insensitive(self):
        response = self.client.get(reverse('devices'), {'country': 'us'})
        self.assertEqual(set(response.context['devices']), {self.modbus_us, self.webcam_us})

    def test_filter_by_search_id(self):
        response = self.client.get(reverse('devices'), {'search_id': self.search2.id})
        self.assertEqual(list(response.context['devices']), [self.bacnet_de])

    def test_filter_by_vuln(self):
        response = self.client.get(reverse('devices'), {'vuln': 'CVE-2020-1111'})
        self.assertEqual(list(response.context['devices']), [self.modbus_us])

    def test_combined_filters(self):
        response = self.client.get(reverse('devices'), {'country': 'US', 'category': 'ics'})
        self.assertEqual(list(response.context['devices']), [self.modbus_us])

    def test_empty_params_return_all(self):
        response = self.client.get(reverse('devices'), {'port': '', 'type': ''})
        self.assertEqual(response.context['devices'].count(), 3)

    def test_honeypot_filter_restricts_to_flagged_devices(self):
        # None of the setUp devices are flagged (honeypot_score defaults to
        # 0), so ?honeypot=1 should return nothing until one is flagged.
        flagged = Device.objects.create(
            search=self.search1, ip='10.0.0.9', type='conpot', category='ics',
            port='102', country_code='US', honeypot_score=HONEYPOT_THRESHOLD,
        )
        response = self.client.get(reverse('devices'), {'honeypot': '1'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context['devices']), [flagged])
        self.assertEqual(response.context['filters'], {'honeypot': '1'})

    def test_honeypot_filter_absent_returns_all(self):
        response = self.client.get(reverse('devices'), {'honeypot': ''})
        self.assertEqual(response.context['devices'].count(), 3)

    def test_no_matches_returns_empty_queryset(self):
        response = self.client.get(reverse('devices'), {'port': '9999'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['devices'].count(), 0)

    def test_active_filters_shown_on_page(self):
        response = self.client.get(reverse('devices'), {'port': '502'})
        self.assertContains(response, 'port')
        self.assertContains(response, '502')
        self.assertContains(response, 'Clear filters')


class BannerUtilsTests(TestCase):
    """looks_like_generic_http_response() flags Shodan banners that are
    really just a generic web-server error page, not device intelligence."""

    def test_html_error_page_is_flagged(self):
        banner = (
            "HTTP/1.1 400 Bad Request\r\n"
            "Server: nginx\r\n\r\n"
            "<html>\r\n<head><title>400 Bad Request</title></head>\r\n"
            "<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n"
            "<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
        )
        self.assertTrue(looks_like_generic_http_response(banner))

    def test_status_line_alone_is_flagged(self):
        banner = "HTTP/1.1 502 Bad Gateway\r\nServer: nginx\r\n\r\n"
        self.assertTrue(looks_like_generic_http_response(banner))

    def test_normal_ics_banner_is_not_flagged(self):
        banner = (
            "Modbus TCP\r\nUnit ID: 1\r\nFunction: Read Holding Registers\r\n"
            "Device: Schneider Electric PLC\r\n"
        )
        self.assertFalse(looks_like_generic_http_response(banner))

    def test_normal_http_200_banner_is_not_flagged(self):
        banner = (
            "HTTP/1.1 200 OK\r\nServer: Boa/0.94.14rc21\r\n\r\n"
            "<html><body><h1>Camera Login</h1></body></html>"
        )
        self.assertFalse(looks_like_generic_http_response(banner))

    def test_empty_banner_is_not_flagged(self):
        self.assertFalse(looks_like_generic_http_response(''))
        self.assertFalse(looks_like_generic_http_response(None))


class DevicePageIntelTests(TestCase):
    """The device page surfaces the raw banner in a collapsed <pre>, only
    shows indicators when there are meaningful ones, and warns when the
    banner looks like a generic HTTP error response."""

    def setUp(self):
        self.user = User.objects.create_user(username='tester', password='pw12345')
        self.client.force_login(self.user)
        self.search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')

    def _device_url(self, device):
        return reverse('device', args=[device.search_id, device.id, device.ip])

    def test_error_banner_shows_warning_and_collapsed_raw_banner(self):
        device = Device.objects.create(
            search=self.search, ip='1.2.3.4', type='webcam', category='coordinates',
            data='<html><body>400 Bad Request</body></html>', indicator='',
        )
        response = self.client.get(self._device_url(device))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'looks like a generic/HTTP-error response')
        self.assertContains(response, '<summary>Raw banner</summary>')
        self.assertContains(response, 'no indicators')

    def test_normal_banner_no_warning(self):
        device = Device.objects.create(
            search=self.search, ip='1.2.3.5', type='modbus', category='ics',
            data='Modbus TCP device banner', indicator="['default creds']",
        )
        response = self.client.get(self._device_url(device))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'looks like a generic/HTTP-error response')
        self.assertContains(response, 'default creds')


class PageSmokeTests(TestCase):
    """Load-test the key pages as a logged-in user."""

    def setUp(self):
        self.user = User.objects.create_user(username='tester', password='pw12345')
        self.client.force_login(self.user)

        self.search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        self.device = Device.objects.create(
            search=self.search, ip='10.0.0.1', type='modbus', category='ics',
            port='502', country_code='US', lat='1.0', lon='2.0',
        )

    def test_index(self):
        response = self.client.get(reverse('index'))
        self.assertEqual(response.status_code, 200)

    def test_devices(self):
        response = self.client.get(reverse('devices'))
        self.assertEqual(response.status_code, 200)

    def test_devices_with_filters(self):
        for params in (
            {'port': '502'},
            {'type': 'modbus'},
            {'category': 'ics'},
            {'country': 'US'},
            {'search_id': self.search.id},
            {'vuln': 'CVE'},
        ):
            response = self.client.get(reverse('devices'), params)
            self.assertEqual(response.status_code, 200, params)

    def test_results(self):
        response = self.client.get(reverse('results', args=[self.search.id]))
        self.assertEqual(response.status_code, 200)

    def test_device_page(self):
        response = self.client.get(
            reverse('device', args=[self.device.search_id, self.device.id, self.device.ip])
        )
        self.assertEqual(response.status_code, 200)

    def test_history(self):
        response = self.client.get(reverse('history'))
        self.assertEqual(response.status_code, 200)

    def test_map(self):
        response = self.client.get(reverse('map'))
        self.assertEqual(response.status_code, 200)

    def test_gallery(self):
        response = self.client.get(reverse('gallery'))
        self.assertEqual(response.status_code, 200)

    def test_sources(self):
        response = self.client.get(reverse('sources'))
        self.assertEqual(response.status_code, 200)


class ScoreDeviceTests(TestCase):
    """app_kamerka.honeypot.score_device is a pure function; test it
    directly with no DB/network involved."""

    def test_conpot_fingerprint_is_flagged(self):
        banner = "Plant: Technodrome\nModule: Mouser Factory\nSerial: 88111222\n"
        score, reasons = score_device(data=banner, category='ics', org='Some Industrial ISP')
        self.assertGreaterEqual(score, HONEYPOT_THRESHOLD)
        self.assertTrue(any('Conpot' in r for r in reasons))

    def test_cloud_hosted_ics_is_flagged(self):
        score, reasons = score_device(
            data='Modbus TCP banner', category='ics', org='DigitalOcean, LLC', hostnames='host.digitalocean.com',
        )
        self.assertGreaterEqual(score, HONEYPOT_THRESHOLD)
        self.assertTrue(any('cloud' in r.lower() for r in reasons))

    def test_normal_ics_on_industrial_isp_is_low_score(self):
        score, reasons = score_device(
            data='Modbus TCP\r\nUnit ID: 1\r\nDevice: Schneider Electric PLC\r\n',
            category='ics', org='Deutsche Telekom AG', hostnames='plc.example-industrial.net',
        )
        self.assertLess(score, HONEYPOT_THRESHOLD)

    def test_empty_input_scores_zero(self):
        score, reasons = score_device()
        self.assertEqual(score, 0)
        self.assertEqual(reasons, [])


class HoneyscoreViewTests(TestCase):
    """get_honeyscore: on-demand Shodan HoneyScore check, mirroring the
    whois/binaryedge AJAX-gated pattern. Shodan itself is mocked -- no
    network involved."""

    def setUp(self):
        self.user = User.objects.create_user(username='tester', password='pw12345')
        self.client.force_login(self.user)
        search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        self.device = Device.objects.create(search=search, ip='1.2.3.4', type='modbus', category='ics')

    def _patch_shodan(self, honeyscore_value):
        class FakeLabs:
            def honeyscore(self, ip):
                if honeyscore_value is _RAISE:
                    raise RuntimeError('boom')
                return honeyscore_value

        class FakeShodanClient:
            def __init__(self, api_key):
                # Mirror the real shodan-python shape: honeyscore lives on
                # the `labs` sub-client (api.labs.honeyscore).
                self.labs = FakeLabs()

        patcher = mock.patch.object(tasks, 'Shodan', FakeShodanClient)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_non_ajax_is_400(self):
        response = self.client.get(reverse('get_honeyscore', args=[self.device.id]))
        self.assertEqual(response.status_code, 400)

    def test_ajax_stores_and_returns_float(self):
        self._patch_shodan(0.87)
        response = self.client.get(reverse('get_honeyscore', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'honeyscore': 0.87})
        self.device.refresh_from_db()
        self.assertEqual(self.device.honeyscore, 0.87)

    def test_ajax_failure_stores_none(self):
        self._patch_shodan(_RAISE)
        response = self.client.get(reverse('get_honeyscore', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'honeyscore': None})
        self.device.refresh_from_db()
        self.assertIsNone(self.device.honeyscore)


_RAISE = object()  # sentinel telling FakeShodanClient.honeyscore to raise


class SaveDeviceFromResultHoneypotTests(TestCase):
    """_save_device_from_result must compute and store honeypot_score/
    honeypot_reasons automatically (no extra API calls) as part of saving
    every Device, mirroring how the existing worker tests mock Shodan."""

    def test_conpot_banner_sets_honeypot_score(self):
        search = Search.objects.create(country='US', ics='siemens', coordinates='', coordinates_search='')
        result = {
            'ip_str': '5.6.7.8',
            'product': 'Siemens S7',
            'org': 'Some Hosting Co',
            'data': 'Plant: Technodrome\nModule: Mouser Factory\n',
            'port': 102,
            'location': {'latitude': 1.0, 'longitude': 2.0, 'city': 'X', 'country_code': 'US'},
        }
        tasks._save_device_from_result(search, result, 'siemens', 'ics', 'Original Siemens Equipment Basic Firmware:')

        device = Device.objects.get(ip='5.6.7.8')
        self.assertGreaterEqual(device.honeypot_score, HONEYPOT_THRESHOLD)
        self.assertIn('Conpot', device.honeypot_reasons)
