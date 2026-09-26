import csv
import json
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, Client, override_settings
from django.urls import reverse

from app_kamerka.banner_utils import looks_like_generic_http_response
from app_kamerka.honeypot import score_device, HONEYPOT_THRESHOLD
from app_kamerka.models import Device, Search
from app_kamerka.sightings import other_sightings
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
            port='80', country_code='US', vulns='', org='Acme Corp',
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

    def test_filter_by_org_icontains(self):
        response = self.client.get(reverse('devices'), {'org': 'acme'})
        self.assertEqual(list(response.context['devices']), [self.webcam_us])
        self.assertEqual(response.context['filters'], {'org': 'acme'})

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

    def test_search_main(self):
        response = self.client.get(reverse('search_main'))
        self.assertEqual(response.status_code, 200)


class HookPreservationTests(TestCase):
    """Stage 1 UI re-skin guard: every id/class that plugins.js, actions.js,
    index_charts.js, draw_charts_results.js, search.js, celery-progress or
    the DataTables/Selectr/Morris/jvectormap/Google-Maps wiring reaches into
    by exact selector must still be present in the rendered HTML. This is
    deliberately dumb string containment (assertContains), not a DOM/JS
    test -- its only job is to fail loudly if a later visual pass silently
    renames or drops a hook these scripts depend on."""

    def setUp(self):
        self.user = User.objects.create_user(username='hooktester', password='pw12345')
        self.client.force_login(self.user)

        self.search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        self.device = Device.objects.create(
            search=self.search, ip='10.0.0.2', type='modbus', category='ics',
            port='502', country_code='US', lat='1.0', lon='2.0',
        )

    def test_index_hooks(self):
        response = self.client.get(reverse('index'))
        self.assertEqual(response.status_code, 200)
        for hook in ('dashboard-bar-1', 'dashboard-donut-1', 'dashboard-donut-1-legend',
                     'dashboard-map-seles'):
            self.assertContains(response, hook)

    def test_index_hooks_with_task_in_progress(self):
        # progress-bar/-message/task-progress-wrapper only render when the
        # session has an in-flight celery task_id (index.html's {% if task_id %}).
        session = self.client.session
        session['task_id'] = 'fake-task-id'
        session.save()
        response = self.client.get(reverse('index'))
        self.assertEqual(response.status_code, 200)
        for hook in ('task-progress-wrapper', 'id=\'progress-bar\'', 'progress-bar-message'):
            self.assertContains(response, hook)

    def test_index_hooks_with_vulns(self):
        Device.objects.create(
            search=self.search, ip='10.0.0.3', type='modbus', category='ics',
            port='502', country_code='US', lat='1.0', lon='2.0',
            vulns="['CVE-2020-0001']",
        )
        response = self.client.get(reverse('index'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'wordcloud')

    def test_devices_hooks(self):
        response = self.client.get(reverse('devices'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'customers2')
        self.assertContains(response, 'class="table datatable"')

    def test_results_hooks(self):
        response = self.client.get(reverse('results', args=[self.search.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'customers2')
        self.assertContains(response, 'class="table datatable"')

    def test_device_page_hooks(self):
        response = self.client.get(
            reverse('device', args=[self.device.search_id, self.device.id, self.device.ip])
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'km-status-btn')
        self.assertContains(response, 'data-status="')
        self.assertContains(response, 'km-notes-box')
        self.assertContains(response, 'km-badge')
        self.assertContains(response, 'csrfmiddlewaretoken')

    def test_search_main_hooks(self):
        response = self.client.get(reverse('search_main'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'estimate_result')
        self.assertContains(response, 'estimate_btn')
        self.assertContains(response, 'csrfmiddlewaretoken')

    def test_map_hooks(self):
        response = self.client.get(reverse('map'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'google_world_map')

    def test_gallery_hooks(self):
        response = self.client.get(reverse('gallery'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'gallery')

    def test_history_hooks(self):
        response = self.client.get(reverse('history'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'customers2')

    def test_sources_loads(self):
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


class SuspectedFalsePositiveTests(TestCase):
    """_save_device_from_result must flag suspected_false_positive when a
    generic/HTTP-error banner (banner_utils.looks_like_generic_http_response)
    is classified under an ICS/healthcare/infra family with no sign of that
    family in the banner -- a persistent, non-destructive flag, not a data
    deletion."""

    def setUp(self):
        self.search = Search.objects.create(
            country='US', ics='mitsubishi', coordinates='', coordinates_search='',
        )

    def _result(self, **overrides):
        result = {
            'ip_str': '9.9.9.9',
            'product': '',
            'org': 'Some Hosting Co',
            'data': (
                "HTTP/1.1 400 Bad Request\r\nServer: nginx\r\n\r\n"
                "<html><head><title>400 Bad Request</title></head>"
                "<body><center><h1>400 Bad Request</h1></center></body></html>"
            ),
            'port': 80,
            'location': {'latitude': 1.0, 'longitude': 2.0, 'city': 'X', 'country_code': 'US'},
        }
        result.update(overrides)
        return result

    def test_generic_http_error_on_ics_family_is_flagged(self):
        # A generic nginx 400 error page classified as "mitsubishi" -- the
        # motivating example from the task: no "mitsubishi" token anywhere
        # in the banner.
        tasks._save_device_from_result(self.search, self._result(), 'mitsubishi', 'ics', 'mitsubishi query')

        device = Device.objects.get(ip='9.9.9.9')
        self.assertTrue(device.suspected_false_positive)

    def test_normal_ics_banner_is_not_flagged(self):
        result = self._result(
            ip_str='9.9.9.8',
            data='Modbus TCP\r\nUnit ID: 1\r\nDevice: Schneider Electric PLC\r\n',
        )
        tasks._save_device_from_result(self.search, result, 'modbus', 'ics', 'modbus query')

        device = Device.objects.get(ip='9.9.9.8')
        self.assertFalse(device.suspected_false_positive)

    def test_family_token_present_in_banner_is_not_flagged(self):
        # Conservative: if the generic-looking banner still mentions the
        # family name itself, don't flag it (favor false negatives).
        result = self._result(
            ip_str='9.9.9.7',
            data=(
                "HTTP/1.1 400 Bad Request\r\nServer: mitsubishi-httpd\r\n\r\n"
                "<html><body>400 Bad Request</body></html>"
            ),
        )
        tasks._save_device_from_result(self.search, result, 'mitsubishi', 'ics', 'mitsubishi query')

        device = Device.objects.get(ip='9.9.9.7')
        self.assertFalse(device.suspected_false_positive)

    def test_non_suspect_category_is_not_flagged(self):
        # "coordinates" is not one of the suspect categories, even with a
        # generic error banner.
        result = self._result(ip_str='9.9.9.6')
        tasks._save_device_from_result(self.search, result, 'webcam', 'coordinates', 'webcam query')

        device = Device.objects.get(ip='9.9.9.6')
        self.assertFalse(device.suspected_false_positive)

    def test_devices_view_false_positive_filter_hides_flagged_rows(self):
        user = User.objects.create_user(username='fp_tester', password='pw12345')
        self.client.force_login(user)

        tasks._save_device_from_result(self.search, self._result(), 'mitsubishi', 'ics', 'mitsubishi query')
        normal_result = self._result(
            ip_str='9.9.9.5', data='Modbus TCP\r\nDevice: Schneider Electric PLC\r\n',
        )
        tasks._save_device_from_result(self.search, normal_result, 'modbus', 'ics', 'modbus query')

        flagged = Device.objects.get(ip='9.9.9.9')
        normal = Device.objects.get(ip='9.9.9.5')
        self.assertTrue(flagged.suspected_false_positive)
        self.assertFalse(normal.suspected_false_positive)

        response = self.client.get(reverse('devices'), {'false_positive': '0'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context['devices']), [normal])

        response = self.client.get(reverse('devices'), {'hide_fp': '1'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context['devices']), [normal])

        response = self.client.get(reverse('devices'))
        self.assertEqual(set(response.context['devices']), {flagged, normal})


class SetDeviceStatusTests(TestCase):
    """set_device_status: AJAX-gated endpoint to update Device.status,
    mirroring the whois/get_binaryedge_score pattern."""

    def setUp(self):
        self.user = User.objects.create_user(username='status_tester', password='pw12345')
        self.client.force_login(self.user)
        search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        self.device = Device.objects.create(search=search, ip='1.2.3.4', type='modbus', category='ics')

    def test_valid_status_saves_and_returns_json(self):
        response = self.client.get(
            reverse('set_device_status', args=[self.device.id]), {'status': 'confirmed'}, **AJAX_HEADER
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'status': 'confirmed'})
        self.device.refresh_from_db()
        self.assertEqual(self.device.status, 'confirmed')

    def test_default_status_is_new(self):
        self.assertEqual(self.device.status, 'new')

    def test_invalid_status_is_rejected(self):
        response = self.client.get(
            reverse('set_device_status', args=[self.device.id]), {'status': 'bogus'}, **AJAX_HEADER
        )
        self.assertEqual(response.status_code, 400)
        self.device.refresh_from_db()
        self.assertEqual(self.device.status, 'new')

    def test_missing_status_is_rejected(self):
        response = self.client.get(reverse('set_device_status', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 400)

    def test_non_ajax_is_400(self):
        response = self.client.get(
            reverse('set_device_status', args=[self.device.id]), {'status': 'confirmed'}
        )
        self.assertEqual(response.status_code, 400)
        self.device.refresh_from_db()
        self.assertEqual(self.device.status, 'new')

    def test_post_also_works(self):
        response = self.client.post(
            reverse('set_device_status', args=[self.device.id]), {'status': 'reviewed'}, **AJAX_HEADER
        )
        self.assertEqual(response.status_code, 200)
        self.device.refresh_from_db()
        self.assertEqual(self.device.status, 'reviewed')

    def test_devices_view_status_filter(self):
        search = self.device.search
        reviewed = Device.objects.create(
            search=search, ip='1.2.3.5', type='modbus', category='ics', status='reviewed',
        )
        response = self.client.get(reverse('devices'), {'status': 'reviewed'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context['devices']), [reviewed])


class OtherSightingsTests(TestCase):
    """other_sightings(device) surfaces other Device rows with the same ip,
    across all searches, excluding the device itself, most-recent first."""

    def setUp(self):
        self.search1 = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        self.search2 = Search.objects.create(country='DE', ics='bacnet', coordinates='', coordinates_search='')

    def test_returns_same_ip_devices_excluding_self(self):
        first = Device.objects.create(search=self.search1, ip='1.2.3.4', type='modbus', category='ics')
        second = Device.objects.create(search=self.search2, ip='1.2.3.4', type='bacnet', category='ics')
        other_ip = Device.objects.create(search=self.search2, ip='5.6.7.8', type='bacnet', category='ics')

        result = list(other_sightings(first))
        self.assertEqual(result, [second])
        self.assertNotIn(first, result)
        self.assertNotIn(other_ip, result)

    def test_no_other_sightings_returns_empty(self):
        only = Device.objects.create(search=self.search1, ip='9.9.9.9', type='modbus', category='ics')
        self.assertEqual(list(other_sightings(only)), [])

    def test_most_recent_first(self):
        first = Device.objects.create(search=self.search1, ip='1.2.3.4', type='modbus', category='ics')
        second = Device.objects.create(search=self.search2, ip='1.2.3.4', type='bacnet', category='ics')
        third = Device.objects.create(search=self.search2, ip='1.2.3.4', type='bacnet', category='ics')

        result = list(other_sightings(first))
        self.assertEqual(result, [third, second])

    def test_falsy_device_returns_empty(self):
        self.assertEqual(list(other_sightings(None)), [])

    def test_device_view_passes_other_sightings_into_context(self):
        user = User.objects.create_user(username='sightings_tester', password='pw12345')
        self.client.force_login(user)
        first = Device.objects.create(search=self.search1, ip='1.2.3.4', type='modbus', category='ics')
        second = Device.objects.create(search=self.search2, ip='1.2.3.4', type='bacnet', category='ics')

        response = self.client.get(reverse('device', args=[first.search_id, first.id, first.ip]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context['other_sightings']), [second])
        self.assertEqual(response.context['sightings_count'], 1)


class CelerySettingsTests(TestCase):
    """Celery 5 (kamerka/celery.py's config_from_object(..., namespace='CELERY'))
    requires these settings to be CELERY_-prefixed."""

    def test_broker_url_is_set(self):
        from django.conf import settings
        self.assertTrue(settings.CELERY_BROKER_URL)
        self.assertIn('redis://', settings.CELERY_BROKER_URL)

    def test_broker_connection_retry_on_startup_is_true(self):
        from django.conf import settings
        self.assertIs(settings.CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP, True)


class ExportDevicesViewTests(TestCase):
    """export_devices streams the SAME filtered device list as devices()
    (they share filter_devices()), as CSV (default) or JSON."""

    def setUp(self):
        self.user = User.objects.create_user(username='export_tester', password='pw12345')
        self.client.force_login(self.user)

        self.search1 = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        self.search2 = Search.objects.create(country='DE', ics='bacnet', coordinates='', coordinates_search='')

        self.modbus_us = Device.objects.create(
            search=self.search1, ip='10.0.0.1', product='Modbus PLC', org='ACME', type='modbus',
            category='ics', port='502', country_code='US', city='NYC', lat='1.0', lon='2.0',
            vulns="['CVE-2020-1111']", hostnames='plc.example.com', honeypot_score=10,
        )
        self.bacnet_de = Device.objects.create(
            search=self.search2, ip='10.0.0.2', product='BACnet Ctrl', org='OtherOrg', type='bacnet',
            category='ics', port='47808', country_code='DE', vulns='',
        )

    def test_csv_export_default_format(self):
        response = self.client.get(reverse('export_devices'), {'country': 'US'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/csv')
        self.assertIn('attachment', response['Content-Disposition'])
        self.assertIn('devices.csv', response['Content-Disposition'])

        content = response.content.decode('utf-8')
        reader = csv.DictReader(content.splitlines())
        rows = list(reader)
        self.assertEqual(reader.fieldnames, [
            'ip', 'product', 'org', 'port', 'type', 'category', 'country_code',
            'city', 'lat', 'lon', 'vulns', 'honeypot_score', 'status',
            'suspected_false_positive', 'hostnames',
        ])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['ip'], '10.0.0.1')
        self.assertEqual(rows[0]['vulns'], 'CVE-2020-1111')
        self.assertEqual(rows[0]['hostnames'], 'plc.example.com')

    def test_explicit_csv_format(self):
        response = self.client.get(reverse('export_devices'), {'format': 'csv'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/csv')
        content = response.content.decode('utf-8')
        reader = csv.DictReader(content.splitlines())
        self.assertEqual(len(list(reader)), 2)

    def test_json_export(self):
        response = self.client.get(reverse('export_devices'), {'format': 'json', 'country': 'DE'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')
        self.assertIn('devices.json', response['Content-Disposition'])

        data = json.loads(response.content)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['ip'], '10.0.0.2')
        self.assertEqual(data[0]['vulns'], '')

    def test_json_export_all_devices(self):
        response = self.client.get(reverse('export_devices'), {'format': 'json'})
        data = json.loads(response.content)
        self.assertEqual(len(data), 2)

    def test_filters_respected_search_id(self):
        response = self.client.get(reverse('export_devices'), {'search_id': self.search1.id})
        content = response.content.decode('utf-8')
        reader = csv.DictReader(content.splitlines())
        rows = list(reader)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['ip'], '10.0.0.1')


class HoneypotFilterEverywhereTests(TestCase):
    """?hide_honeypot=1 (new) and ?honeypot=1 (existing) on the devices
    view, kept in sync via the shared filter_devices() helper."""

    def setUp(self):
        self.user = User.objects.create_user(username='hp_tester', password='pw12345')
        self.client.force_login(self.user)

        search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        self.normal = Device.objects.create(
            search=search, ip='1.1.1.1', type='modbus', category='ics', honeypot_score=0,
        )
        self.flagged = Device.objects.create(
            search=search, ip='2.2.2.2', type='conpot', category='ics', honeypot_score=HONEYPOT_THRESHOLD,
        )

    def test_hide_honeypot_excludes_flagged_rows(self):
        response = self.client.get(reverse('devices'), {'hide_honeypot': '1'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context['devices']), [self.normal])
        self.assertEqual(response.context['filters'], {'hide_honeypot': '1'})

    def test_honeypot_only_includes_flagged_rows(self):
        response = self.client.get(reverse('devices'), {'honeypot': '1'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context['devices']), [self.flagged])

    def test_no_filter_returns_both(self):
        response = self.client.get(reverse('devices'))
        self.assertEqual(set(response.context['devices']), {self.normal, self.flagged})

    def test_map_hide_honeypot_excludes_flagged(self):
        response = self.client.get(reverse('map'), {'hide_honeypot': '1'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.context['devices']), {self.normal})

    def test_map_without_filter_includes_all(self):
        response = self.client.get(reverse('map'))
        self.assertEqual(set(response.context['devices']), {self.normal, self.flagged})

    def test_results_honeypot_filters(self):
        response = self.client.get(reverse('results', args=[self.normal.search_id]), {'hide_honeypot': '1'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context['search']), [self.normal])

        response = self.client.get(reverse('results', args=[self.normal.search_id]), {'honeypot': '1'})
        self.assertEqual(list(response.context['search']), [self.flagged])


class GetCreditsViewTests(TestCase):
    """get_credits: thin AJAX-gated wrapper around kamerka.tasks.check_credits,
    used by the search_main pre-search credit-guard UI."""

    def setUp(self):
        self.user = User.objects.create_user(username='credits_tester', password='pw12345')
        self.client.force_login(self.user)

    def test_non_ajax_is_not_ok(self):
        response = self.client.get(reverse('get_credits'))
        self.assertContains(response, 'NO OK')

    def test_ajax_returns_credits(self):
        with mock.patch('app_kamerka.views.check_credits', return_value=[123, 456]):
            response = self.client.get(reverse('get_credits'), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'shodan_credits': 123, 'binaryedge_credits': 456})

    def test_ajax_handles_partial_credits(self):
        with mock.patch('app_kamerka.views.check_credits', return_value=[42]):
            response = self.client.get(reverse('get_credits'), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'shodan_credits': 42, 'binaryedge_credits': None})

    def test_ajax_handles_no_credits(self):
        with mock.patch('app_kamerka.views.check_credits', return_value=[]):
            response = self.client.get(reverse('get_credits'), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'shodan_credits': None, 'binaryedge_credits': None})


class NearbyDevicesTwinTests(TestCase):
    """get_nearby_devices and get_nearby_devices_coordinates now share one
    implementation (they were byte-identical), but both URL names must keep
    working for the templates/JS that call each of them."""

    def setUp(self):
        self.user = User.objects.create_user(username='nearby_tester', password='pw12345')
        self.client.force_login(self.user)
        search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        self.device = Device.objects.create(search=search, ip='1.2.3.4', type='modbus', category='ics')

    def test_both_endpoints_share_implementation(self):
        from app_kamerka import views
        self.assertIs(views.get_nearby_devices, views.get_nearby_devices_coordinates)

    def test_get_nearby_devices_coordinates_ajax_is_200(self):
        response = self.client.get(
            reverse('get_nearby_devices_coordinates', args=[self.device.id]), **AJAX_HEADER
        )
        self.assertEqual(response.status_code, 200)

    def test_get_nearby_devices_coordinates_non_ajax_is_400(self):
        response = self.client.get(reverse('get_nearby_devices_coordinates', args=[self.device.id]))
        self.assertEqual(response.status_code, 400)


class IndexDashboardCreditsTests(TestCase):
    """Stage 2: the dashboard no longer blocks its render on check_credits()
    (a live Shodan + BinaryEdge call) -- that used to make every dashboard
    load slow, and hang/fail outright when offline. The Shodan/BinaryEdge
    tiles now load asynchronously via the existing `get_credits` AJAX
    endpoint (JS fetch, see index.html), so `index()` itself must never call
    check_credits() and must render instantly regardless of its outcome."""

    def setUp(self):
        self.user = User.objects.create_user(username='dash_tester', password='pw12345')
        self.client.force_login(self.user)

    def test_index_does_not_call_check_credits(self):
        with mock.patch('app_kamerka.views.check_credits') as mocked:
            response = self.client.get(reverse('index'))
        self.assertEqual(response.status_code, 200)
        mocked.assert_not_called()

    def test_index_renders_even_if_check_credits_would_raise(self):
        # Belt-and-suspenders: even if something were to make check_credits()
        # blow up, index() no longer calls it at all, so the dashboard still
        # renders fine.
        with mock.patch('app_kamerka.views.check_credits', side_effect=Exception("offline")):
            response = self.client.get(reverse('index'))
        self.assertEqual(response.status_code, 200)

    def test_credits_tiles_render_skeleton_and_load_async_via_get_credits(self):
        response = self.client.get(reverse('index'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'id="km-shodan-credits"')
        self.assertContains(response, 'id="km-binaryedge-credits"')
        self.assertContains(response, 'km-skeleton')
        # The page must fetch the credits via the existing AJAX endpoint
        # after paint, not render them inline server-side.
        self.assertContains(response, reverse('get_credits'))
        self.assertNotIn('shodan_credits', response.context)
        self.assertNotIn('binaryedge_credits', response.context)


class IndexDashboardAggregationsTests(TestCase):
    """Stage 2: dashboard aggregations (honeypot/country counts, top device
    types, top orgs, recent devices) that make the dashboard useful at 100+
    devices instead of empty-looking."""

    def setUp(self):
        self.user = User.objects.create_user(username='agg_tester', password='pw12345')
        self.client.force_login(self.user)
        self.search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')

        Device.objects.create(
            search=self.search, ip='10.0.0.1', type='modbus', category='ics',
            org='Acme Corp', port='502', country_code='US',
        )
        Device.objects.create(
            search=self.search, ip='10.0.0.2', type='modbus', category='ics',
            org='Acme Corp', port='502', country_code='DE',
        )
        Device.objects.create(
            search=self.search, ip='10.0.0.3', type='bacnet', category='ics',
            org='Globex', port='47808', country_code='DE',
            honeypot_score=HONEYPOT_THRESHOLD,
        )

    def test_honeypot_and_country_counts(self):
        response = self.client.get(reverse('index'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['honeypot_count'], 1)
        self.assertEqual(response.context['country_count'], 2)

    def test_top_types_and_top_orgs(self):
        response = self.client.get(reverse('index'))
        types = {row['type']: row['c'] for row in response.context['top_types']}
        orgs = {row['org']: row['c'] for row in response.context['top_orgs']}
        self.assertEqual(types, {'modbus': 2, 'bacnet': 1})
        self.assertEqual(orgs, {'Acme Corp': 2, 'Globex': 1})

    def test_recent_devices_present_most_recent_first(self):
        response = self.client.get(reverse('index'))
        recent_ips = [d.ip for d in response.context['recent_devices']]
        self.assertEqual(recent_ips, ['10.0.0.3', '10.0.0.2', '10.0.0.1'])

    def test_dashboard_kpi_tiles_render(self):
        response = self.client.get(reverse('index'))
        self.assertContains(response, 'Honeypots flagged')
        self.assertContains(response, 'Countries')
        self.assertContains(response, '?honeypot=1')

    def test_dashboard_cards_render_with_links(self):
        response = self.client.get(reverse('index'))
        self.assertContains(response, 'Top device types')
        self.assertContains(response, 'Top orgs')
        self.assertContains(response, 'Recent devices')
        self.assertContains(response, '/devices?type=modbus')
        self.assertContains(response, '/devices?org=Acme')

    def test_empty_state_when_no_devices(self):
        Device.objects.all().delete()
        response = self.client.get(reverse('index'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'No devices yet')
        self.assertEqual(response.context['honeypot_count'], 0)
        self.assertEqual(response.context['country_count'], 0)

    def test_progress_bar_hidden_without_active_task(self):
        response = self.client.get(reverse('index'))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'id="task-progress-wrapper"')

    def test_progress_bar_shown_with_active_task(self):
        session = self.client.session
        session['task_id'] = 'fake-task-id'
        session.save()
        response = self.client.get(reverse('index'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'id="task-progress-wrapper"')


class DeviceTriagePageTests(TestCase):
    """UI wiring for Device.status / set_device_status and the "other
    sightings" cross-search de-dupe: the device page now shows a status
    control built from Device.STATUS_CHOICES and an other-sightings list."""

    def setUp(self):
        self.user = User.objects.create_user(username='triage_tester', password='pw12345')
        self.client.force_login(self.user)
        self.search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')

    def _device_url(self, device):
        return reverse('device', args=[device.search_id, device.id, device.ip])

    def test_status_choices_in_context_and_rendered(self):
        device = Device.objects.create(
            search=self.search, ip='1.2.3.4', type='modbus', category='ics', status='new',
        )
        response = self.client.get(self._device_url(device))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context['status_choices']), list(Device.STATUS_CHOICES))
        for value, display in Device.STATUS_CHOICES:
            self.assertContains(response, 'data-status="%s"' % value)
        self.assertContains(response, 'km-status-active')

    def test_summary_header_shows_key_facts(self):
        device = Device.objects.create(
            search=self.search, ip='10.20.30.40', type='modbus', category='ics',
            product='Acme PLC', org='Acme Corp', country_code='US', port='502',
        )
        response = self.client.get(self._device_url(device))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '10.20.30.40')
        self.assertContains(response, 'Acme PLC')
        self.assertContains(response, 'Acme Corp')
        self.assertContains(response, '502')

    def test_no_other_sightings_shows_none_message(self):
        device = Device.objects.create(search=self.search, ip='1.1.1.1', type='modbus', category='ics')
        response = self.client.get(self._device_url(device))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'None')

    def test_other_sightings_links_to_device_page(self):
        other_search = Search.objects.create(country='DE', ics='bacnet', coordinates='', coordinates_search='')
        device = Device.objects.create(search=self.search, ip='2.2.2.2', type='modbus', category='ics')
        other = Device.objects.create(search=other_search, ip='2.2.2.2', type='bacnet', category='ics')

        response = self.client.get(self._device_url(device))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse('device', args=[other.search_id, other.id, other.ip]))

    def test_set_device_status_updates_and_page_reflects_it(self):
        device = Device.objects.create(search=self.search, ip='3.3.3.3', type='modbus', category='ics', status='new')

        response = self.client.get(
            reverse('set_device_status', args=[device.id]), {'status': 'confirmed'}, **AJAX_HEADER
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'status': 'confirmed'})

        device.refresh_from_db()
        self.assertEqual(device.status, 'confirmed')

        page = self.client.get(self._device_url(device))
        self.assertContains(page, 'km-status-active" data-status="confirmed"')


class PastebinRemovalTests(TestCase):
    """The Pastebin "field agent" exfiltration subsystem has been removed
    entirely. send_to_field_agent now only persists notes locally."""

    def setUp(self):
        self.user = User.objects.create_user(username='tester', password='pw12345')
        self.client.force_login(self.user)

        self.search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        self.device = Device.objects.create(search=self.search, ip='9.9.9.9', type='modbus', category='ics')

    def test_send_to_field_agent_task_no_longer_exists(self):
        self.assertFalse(hasattr(tasks, 'send_to_field_agent_task'))

    def test_pastebin_helpers_no_longer_exist(self):
        for name in ('paste_login', 'retrieve_pastes', 'delete_paste', 'create_paste'):
            self.assertFalse(hasattr(tasks, name), "%s should have been removed" % name)

    def test_send_to_field_agent_persists_notes_and_returns_ok(self):
        response = self.client.get(
            reverse('send_to_field_agent', args=[self.device.id, 'some notes']), **AJAX_HEADER
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'Status': 'OK'})

        self.device.refresh_from_db()
        self.assertEqual(self.device.notes, 'some notes')

    def test_send_to_field_agent_non_ajax_returns_no_task_id(self):
        response = self.client.get(reverse('send_to_field_agent', args=[self.device.id, 'notes']))
        self.assertEqual(response.json(), {'task_id': None})


class ActiveOpsFeatureFlagTests(TestCase):
    """scan_dev/exploit_dev are gated behind KAMERKA_ENABLE_ACTIVE_SCAN /
    KAMERKA_ENABLE_EXPLOITATION, both False by default."""

    def setUp(self):
        self.user = User.objects.create_user(username='tester', password='pw12345')
        self.client.force_login(self.user)

        self.search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        self.device = Device.objects.create(search=self.search, ip='5.5.5.5', type='modbus', category='ics')

    def test_scan_disabled_by_default_returns_403_and_does_not_scan(self):
        with mock.patch('app_kamerka.views.scan') as mocked_scan:
            response = self.client.get(reverse('scan', args=[self.device.id]), **AJAX_HEADER)
            self.assertEqual(response.status_code, 403)
            self.assertIn('disabled', response.json()['Error'].lower())
            mocked_scan.assert_not_called()

    def test_exploit_disabled_by_default_returns_403_and_does_not_exploit(self):
        with mock.patch('app_kamerka.views.exploit') as mocked_exploit:
            response = self.client.get(reverse('exploit', args=[self.device.id]), **AJAX_HEADER)
            self.assertEqual(response.status_code, 403)
            self.assertIn('disabled', response.json()['Error'].lower())
            mocked_exploit.assert_not_called()

    @override_settings(KAMERKA_ENABLE_ACTIVE_SCAN=True)
    def test_scan_enabled_calls_through_and_returns_200(self):
        with mock.patch('app_kamerka.views.scan', return_value={'State': 'open'}) as mocked_scan:
            response = self.client.get(reverse('scan', args=[self.device.id]), **AJAX_HEADER)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {'State': 'open'})
            mocked_scan.assert_called_once_with(str(self.device.id))

    @override_settings(KAMERKA_ENABLE_EXPLOITATION=True)
    def test_exploit_enabled_calls_through_and_returns_200(self):
        with mock.patch('app_kamerka.views.exploit', return_value={'Success': 'done'}) as mocked_exploit:
            response = self.client.get(reverse('exploit', args=[self.device.id]), **AJAX_HEADER)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {'Success': 'done'})
            mocked_exploit.assert_called_once_with(str(self.device.id))

    def test_scan_disabled_non_ajax_is_400(self):
        response = self.client.get(reverse('scan', args=[self.device.id]))
        self.assertEqual(response.status_code, 400)

    def test_exploit_disabled_non_ajax_is_400(self):
        response = self.client.get(reverse('exploit', args=[self.device.id]))
        self.assertEqual(response.status_code, 400)
