import csv
import json
from importlib import import_module
from unittest import mock

import requests
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.utils import timezone

from app_kamerka.authz import is_target_authorized
from app_kamerka.banner_utils import looks_like_generic_http_response
from app_kamerka.honeypot import score_device, HONEYPOT_THRESHOLD
from app_kamerka.models import (
    AuditLog, Device, ExploitTaskAccess, GeneralTaskResultAccess, Operation, ScanAuthorization, Search,
)
from app_kamerka.net import (
    ActiveClient,
    ACTIVE_TIMEOUT,
    PASSIVE_TIMEOUT,
    PassiveClient,
    ResponseTooLarge,
)
from app_kamerka.sightings import other_sightings
from app_kamerka.views import is_ajax
from kamerka import tasks

User = get_user_model()


AJAX_HEADER = {'HTTP_X_REQUESTED_WITH': 'XMLHttpRequest'}


def make_user(username, groups=(), password='pw12345', superuser=False):
    """Test helper: create a user, optionally a superuser, and add it to
    zero or more of the Viewer/Analyst/Active Scanner/Exploit Operator/
    Administrator groups created by the 0007_capability_groups data
    migration (so this also exercises that migration's group/permission
    wiring, not just hand-rolled permissions)."""
    if superuser:
        user = User.objects.create_superuser(
            username=username, email='%s@example.invalid' % username, password=password,
        )
    else:
        user = User.objects.create_user(username=username, password=password)
    for group_name in groups:
        user.groups.add(Group.objects.get(name=group_name))
    return user


def make_authorization(cidr='0.0.0.0/0', allow_port_scan=True, allow_exploit=True,
                        expires_at=None, name='test scope'):
    """Test helper: create a ScanAuthorization row covering `cidr`."""
    return ScanAuthorization.objects.create(
        name=name, cidr=cidr, allow_port_scan=allow_port_scan, allow_exploit=allow_exploit,
        expires_at=expires_at,
    )


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
            port='502', country_code='US', vulns=['CVE-2020-1111'],
        )
        self.bacnet_de = Device.objects.create(
            search=self.search2, ip='10.0.0.2', type='bacnet', category='ics',
            port='47808', country_code='DE', vulns=['CVE-2019-2222'],
        )
        self.webcam_us = Device.objects.create(
            search=self.search1, ip='10.0.0.3', type='webcam', category='coordinates',
            port='80', country_code='US', vulns=[], org='Acme Corp',
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
            data='<html><body>400 Bad Request</body></html>', indicator=[],
        )
        response = self.client.get(self._device_url(device))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'looks like a generic/HTTP-error response')
        self.assertContains(response, '<summary>Raw banner</summary>')
        self.assertContains(response, 'no indicators')

    def test_normal_banner_no_warning(self):
        device = Device.objects.create(
            search=self.search, ip='1.2.3.5', type='modbus', category='ics',
            data='Modbus TCP device banner', indicator=['default creds'],
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
            vulns=['CVE-2020-0001'],
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
        self.user = make_user('tester', groups=['Analyst'])
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

    def test_get_is_405(self):
        response = self.client.get(reverse('get_honeyscore', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 405)

    def test_non_ajax_post_is_400(self):
        response = self.client.post(reverse('get_honeyscore', args=[self.device.id]))
        self.assertEqual(response.status_code, 400)

    def test_ajax_stores_and_returns_float(self):
        self._patch_shodan(0.87)
        response = self.client.post(reverse('get_honeyscore', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'honeyscore': 0.87})
        self.device.refresh_from_db()
        self.assertEqual(self.device.honeyscore, 0.87)

    def test_ajax_failure_stores_none(self):
        self._patch_shodan(_RAISE)
        response = self.client.post(reverse('get_honeyscore', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'honeyscore': None})
        self.device.refresh_from_db()
        self.assertIsNone(self.device.honeyscore)

    def test_creates_audit_log_row(self):
        self._patch_shodan(0.5)
        response = self.client.post(reverse('get_honeyscore', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(AuditLog.objects.count(), 1)
        row = AuditLog.objects.get()
        self.assertEqual(row.action, 'honeyscore')
        self.assertEqual(row.device_id, self.device.id)


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
        self.user = make_user('status_tester', groups=['Analyst'])
        self.client.force_login(self.user)
        search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        self.device = Device.objects.create(search=search, ip='1.2.3.4', type='modbus', category='ics')

    def test_valid_status_saves_and_returns_json(self):
        response = self.client.post(
            reverse('set_device_status', args=[self.device.id]), {'status': 'confirmed'}, **AJAX_HEADER
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'status': 'confirmed'})
        self.device.refresh_from_db()
        self.assertEqual(self.device.status, 'confirmed')

    def test_default_status_is_new(self):
        self.assertEqual(self.device.status, 'new')

    def test_invalid_status_is_rejected(self):
        response = self.client.post(
            reverse('set_device_status', args=[self.device.id]), {'status': 'bogus'}, **AJAX_HEADER
        )
        self.assertEqual(response.status_code, 400)
        self.device.refresh_from_db()
        self.assertEqual(self.device.status, 'new')

    def test_missing_status_is_rejected(self):
        response = self.client.post(reverse('set_device_status', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 400)

    def test_get_is_405(self):
        # Side-effecting endpoint: GET is no longer accepted at all, even
        # with the AJAX header.
        response = self.client.get(
            reverse('set_device_status', args=[self.device.id]), {'status': 'confirmed'}, **AJAX_HEADER
        )
        self.assertEqual(response.status_code, 405)
        self.device.refresh_from_db()
        self.assertEqual(self.device.status, 'new')

    def test_non_ajax_post_is_400(self):
        response = self.client.post(
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

    def test_creates_audit_log_row(self):
        self.assertEqual(AuditLog.objects.count(), 0)
        response = self.client.post(
            reverse('set_device_status', args=[self.device.id]), {'status': 'confirmed'}, **AJAX_HEADER
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(AuditLog.objects.count(), 1)
        row = AuditLog.objects.get()
        self.assertEqual(row.action, 'set_status')
        self.assertEqual(row.device_id, self.device.id)
        self.assertEqual(row.user_id, self.user.id)
        self.assertTrue(row.success)

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
        self.user = make_user('export_tester', groups=['Analyst'])
        self.client.force_login(self.user)

        self.search1 = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        self.search2 = Search.objects.create(country='DE', ics='bacnet', coordinates='', coordinates_search='')

        self.modbus_us = Device.objects.create(
            search=self.search1, ip='10.0.0.1', product='Modbus PLC', org='ACME', type='modbus',
            category='ics', port='502', country_code='US', city='NYC', lat='1.0', lon='2.0',
            vulns=['CVE-2020-1111'], hostnames=['plc.example.com'], honeypot_score=10,
        )
        self.bacnet_de = Device.objects.create(
            search=self.search2, ip='10.0.0.2', product='BACnet Ctrl', org='OtherOrg', type='bacnet',
            category='ics', port='47808', country_code='DE', vulns=[],
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
        self.user = make_user('triage_tester', groups=['Analyst'])
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

        response = self.client.post(
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
        self.user = make_user('tester', groups=['Analyst'])
        self.client.force_login(self.user)

        self.search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        self.device = Device.objects.create(search=self.search, ip='9.9.9.9', type='modbus', category='ics')

    def test_send_to_field_agent_task_no_longer_exists(self):
        self.assertFalse(hasattr(tasks, 'send_to_field_agent_task'))

    def test_pastebin_helpers_no_longer_exist(self):
        for name in ('paste_login', 'retrieve_pastes', 'delete_paste', 'create_paste'):
            self.assertFalse(hasattr(tasks, name), "%s should have been removed" % name)

    def test_send_to_field_agent_persists_notes_and_returns_ok(self):
        url = reverse('send_to_field_agent', args=[self.device.id])
        notes = 'notes with / and ? & credentials=private'
        response = self.client.post(
            url, {'notes': notes}, **AJAX_HEADER
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'Status': 'OK'})
        self.assertEqual(response.wsgi_request.path, url)
        self.assertNotIn(notes, response.wsgi_request.get_full_path())

        self.device.refresh_from_db()
        self.assertEqual(self.device.notes, notes)

    def test_send_to_field_agent_get_is_405(self):
        response = self.client.get(
            reverse('send_to_field_agent', args=[self.device.id]), **AJAX_HEADER
        )
        self.assertEqual(response.status_code, 405)

    def test_send_to_field_agent_non_ajax_returns_no_task_id(self):
        response = self.client.post(reverse('send_to_field_agent', args=[self.device.id]), {'notes': 'notes'})
        self.assertEqual(response.json(), {'task_id': None})

    def test_send_to_field_agent_creates_audit_log_row(self):
        response = self.client.post(
            reverse('send_to_field_agent', args=[self.device.id]), {'notes': 'audited notes'}, **AJAX_HEADER
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(AuditLog.objects.count(), 1)
        row = AuditLog.objects.get()
        self.assertEqual(row.action, 'notes')
        self.assertEqual(row.device_id, self.device.id)


class ActiveOpsFeatureFlagTests(TestCase):
    """scan_dev/exploit_dev are gated behind KAMERKA_ENABLE_ACTIVE_SCAN /
    KAMERKA_ENABLE_EXPLOITATION, both False by default. This class is only
    about that feature-flag gate (capability and target-scope authorization
    are covered separately by CapabilityRoleTests/TargetScopeAuthorizationTests
    below), so the caller here is a superuser with a scope covering every
    IPv4 address -- both the active_scan/exploit capability check and the
    is_target_authorized() scope check are satisfied unconditionally,
    leaving only the feature flag itself under test."""

    def setUp(self):
        self.user = make_user('tester', superuser=True)
        self.client.force_login(self.user)
        make_authorization(cidr='0.0.0.0/0', allow_port_scan=True, allow_exploit=True)

        self.search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        self.device = Device.objects.create(search=self.search, ip='5.5.5.5', type='modbus', category='ics')

    def test_scan_disabled_by_default_returns_403_and_does_not_scan(self):
        with mock.patch('app_kamerka.views.scan_task.apply_async') as mocked_scan:
            response = self.client.post(reverse('scan', args=[self.device.id]), **AJAX_HEADER)
            self.assertEqual(response.status_code, 403)
            self.assertIn('disabled', response.json()['Error'].lower())
            mocked_scan.assert_not_called()

    def test_exploit_disabled_by_default_returns_403_and_does_not_exploit(self):
        with mock.patch('app_kamerka.views.exploit_task.apply_async') as mocked_exploit:
            response = self.client.post(reverse('exploit', args=[self.device.id]), **AJAX_HEADER)
            self.assertEqual(response.status_code, 403)
            self.assertIn('disabled', response.json()['Error'].lower())
            mocked_exploit.assert_not_called()

    @override_settings(KAMERKA_ENABLE_ACTIVE_SCAN=True)
    def test_scan_enabled_enqueues_task_and_returns_task_id(self):
        with mock.patch(
            'app_kamerka.views.scan_task.apply_async', return_value=_FakeAsyncResult('scan-task')
        ) as mocked_scan:
            response = self.client.post(reverse('scan', args=[self.device.id]), **AJAX_HEADER)
            self.assertEqual(response.status_code, 200)
            self.assertIn('task_id', response.json())
            self.assertIn('operation_id', response.json())
            self.assertEqual(mocked_scan.call_args.kwargs['args'], [str(self.device.id)])
            self.assertTrue(GeneralTaskResultAccess.objects.filter(task_id=response.json()['task_id']).exists())

    @override_settings(KAMERKA_ENABLE_EXPLOITATION=True)
    def test_exploit_enabled_enqueues_task_and_returns_task_id(self):
        with mock.patch(
            'app_kamerka.views.exploit_task.apply_async', return_value=_FakeAsyncResult('exploit-task')
        ) as mocked_exploit:
            response = self.client.post(reverse('exploit', args=[self.device.id]), **AJAX_HEADER)
            self.assertEqual(response.status_code, 200)
            task_id = response.json()['task_id']
            self.assertTrue(task_id.startswith('exploit-'))
            self.assertTrue(ExploitTaskAccess.objects.filter(task_id=task_id).exists())
            self.assertEqual(mocked_exploit.call_count, 1)
            self.assertEqual(mocked_exploit.call_args.kwargs['args'], [str(self.device.id)])
            self.assertTrue(mocked_exploit.call_args.kwargs['task_id'].startswith('exploit-'))

    def test_scan_get_is_405(self):
        response = self.client.get(reverse('scan', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 405)

    def test_exploit_get_is_405(self):
        response = self.client.get(reverse('exploit', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 405)

    def test_scan_disabled_non_ajax_post_is_400(self):
        response = self.client.post(reverse('scan', args=[self.device.id]))
        self.assertEqual(response.status_code, 400)

    def test_exploit_disabled_non_ajax_post_is_400(self):
        response = self.client.post(reverse('exploit', args=[self.device.id]))
        self.assertEqual(response.status_code, 400)

    @override_settings(KAMERKA_ENABLE_ACTIVE_SCAN=True)
    def test_scan_creates_audit_log_row(self):
        with mock.patch(
            'app_kamerka.views.scan_task.apply_async', return_value=_FakeAsyncResult('scan-task')
        ):
            response = self.client.post(reverse('scan', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(AuditLog.objects.count(), 1)
        row = AuditLog.objects.get()
        self.assertEqual(row.action, 'operation_queued')
        self.assertEqual(row.device_id, self.device.id)
        self.assertTrue(row.success)

    @override_settings(KAMERKA_ENABLE_EXPLOITATION=True)
    def test_exploit_creates_audit_log_row(self):
        with mock.patch(
            'app_kamerka.views.exploit_task.apply_async', return_value=_FakeAsyncResult('exploit-task')
        ):
            response = self.client.post(reverse('exploit', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(AuditLog.objects.count(), 1)
        row = AuditLog.objects.get()
        self.assertEqual(row.action, 'operation_queued')
        self.assertEqual(row.device_id, self.device.id)
        self.assertTrue(row.success)

    def test_scan_disabled_by_config_is_audited_as_failure(self):
        # A capable caller whose active-scan attempt is refused purely because
        # the feature flag is off must still leave an audit trail (the denial
        # is recorded before the 403 returns), same as capability/scope denials.
        with mock.patch('app_kamerka.views.scan_task.apply_async') as mocked_scan:
            response = self.client.post(reverse('scan', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 403)
        mocked_scan.assert_not_called()
        self.assertEqual(AuditLog.objects.count(), 1)
        row = AuditLog.objects.get()
        self.assertEqual(row.action, 'scan')
        self.assertEqual(row.device_id, self.device.id)
        self.assertFalse(row.success)

    def test_exploit_disabled_by_config_is_audited_as_failure(self):
        with mock.patch('app_kamerka.views.exploit_task.apply_async') as mocked_exploit:
            response = self.client.post(reverse('exploit', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 403)
        mocked_exploit.assert_not_called()
        self.assertEqual(AuditLog.objects.count(), 1)
        row = AuditLog.objects.get()
        self.assertEqual(row.action, 'exploit')
        self.assertEqual(row.device_id, self.device.id)
        self.assertFalse(row.success)


class CapabilityGroupMigrationTests(TestCase):
    """0007_capability_groups must actually create the five groups with the
    right cumulative custom permissions (app_kamerka.<capability> on the
    Device content type -- see Device.Meta.permissions)."""

    def test_groups_exist_with_cumulative_permissions(self):
        expected = {
            'Viewer': {'view_capability'},
            'Analyst': {'view_capability', 'run_search'},
            'Active Scanner': {'view_capability', 'run_search', 'active_scan'},
            'Exploit Operator': {'view_capability', 'run_search', 'active_scan', 'exploit', 'view_exploit_results'},
            'Administrator': {'view_capability', 'run_search', 'active_scan', 'exploit', 'view_exploit_results', 'administer'},
        }
        for group_name, expected_codenames in expected.items():
            group = Group.objects.get(name=group_name)
            codenames = {p.codename for p in group.permissions.all()}
            self.assertEqual(codenames, expected_codenames, group_name)


class SensitiveExploitResultTests(TestCase):
    def setUp(self):
        self.search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        self.device = Device.objects.create(
            search=self.search, ip='6.6.6.6', type='modbus', category='ics',
            scan={'Output': 'safe scan output'},
            exploit={'Credentials': 'operator:secret', 'Output': 'exploit output'},
        )
        self.task_id = 'classified-exploit-task'
        ExploitTaskAccess.objects.create(task_id=self.task_id)

    def _client_for(self, username, groups):
        client = Client()
        client.force_login(make_user(username, groups=groups))
        return client

    def _get_device_page(self, client):
        with mock.patch('app_kamerka.views.keys', {'keys': {'google_maps': ''}}):
            return client.get(reverse('device', args=[self.search.id, self.device.id, self.device.ip]))

    def test_json_script_payload_is_inert(self):
        self.device.scan = {'Output': '</script><script>alert(1)</script>'}
        self.device.exploit = {'Output': '</script><script>alert(2)</script>'}
        self.device.save()
        client = self._client_for('json_script_exploiter', ['Exploit Operator'])
        response = self._get_device_page(client)
        html = response.content.decode()
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('</script><script>alert(1)', html)
        self.assertNotIn('</script><script>alert(2)', html)
        self.assertIn('\\u003C/script\\u003E', html)

    def test_viewer_cannot_access_exploit_payload_or_task_result(self):
        client = self._client_for('result_viewer', ['Viewer'])
        page = self._get_device_page(client)
        self.assertEqual(page.status_code, 200)
        self.assertNotIn('operator:secret', page.content.decode())
        self.assertNotIn('exploit-results-data', page.content.decode())

        with mock.patch('app_kamerka.views.AsyncResult') as async_result:
            async_result.return_value.state = 'SUCCESS'
            async_result.return_value.result = {'Credentials': 'operator:secret'}
            status = client.get(reverse('get_task_info'), {'task_id': self.task_id})
            self.assertEqual(status.status_code, 200)
            self.assertEqual(status.json(), {'state': 'SUCCESS'})
            progress = client.get(reverse('secure_celery_progress', args=[self.task_id]))
            self.assertEqual(progress.status_code, 200)
            self.assertNotIn('result', progress.json())
            result = client.get(reverse('get_exploit_task_result'), {'task_id': self.task_id})
            self.assertEqual(result.status_code, 403)
            self.assertEqual(async_result.call_count, 2)


    def test_exploit_operator_can_view_initial_and_polled_result(self):
        client = self._client_for('result_operator', ['Exploit Operator'])
        page = self._get_device_page(client)
        self.assertIn('operator:secret', page.content.decode())

        with mock.patch('app_kamerka.views.AsyncResult') as async_result:
            async_result.return_value.state = 'SUCCESS'
            async_result.return_value.result = {'Credentials': 'operator:secret'}
            result = client.get(reverse('get_exploit_task_result'), {'task_id': self.task_id})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()['result'], {'Credentials': 'operator:secret'})
        unknown = client.get(reverse('get_exploit_task_result'), {'task_id': 'not-a-recorded-task'})
        self.assertEqual(unknown.status_code, 404)

        client.logout()
        operator = User.objects.get(username='result_operator')
        operator.groups.clear()
        client.force_login(operator)
        revoked = client.get(reverse('get_exploit_task_result'), {'task_id': self.task_id})
        self.assertEqual(revoked.status_code, 403)

    def test_unknown_task_status_does_not_expose_raw_result(self):
        client = self._client_for('unknown_status_viewer', ['Viewer'])
        with mock.patch('app_kamerka.views.AsyncResult') as async_result:
            async_result.return_value.state = 'SUCCESS'
            async_result.return_value.result = {'Credentials': 'must-not-leak'}
            response = client.get(reverse('get_task_info'), {'task_id': 'legacy-exploit-id'})
            progress = client.get(reverse('secure_celery_progress', args=['legacy-exploit-id']))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'state': 'SUCCESS'})
        self.assertEqual(progress.status_code, 200)
        self.assertNotIn('result', progress.json())

    def test_explicitly_registered_passive_task_keeps_its_result(self):
        client = self._client_for('passive_status_viewer', ['Viewer'])
        GeneralTaskResultAccess.objects.create(task_id='passive-task')
        with mock.patch('app_kamerka.views.AsyncResult') as async_result:
            async_result.return_value.state = 'PROGRESS'
            async_result.return_value.result = {'percent': 37}
            response = client.get(reverse('get_task_info'), {'task_id': 'passive-task'})
        self.assertEqual(response.json(), {'state': 'PROGRESS', 'result': {'percent': 37}})


class CapabilityRoleTests(TestCase):
    """Capability-based role enforcement (S4): a Viewer can only reach the
    read-only pages, an Analyst additionally reaches run_search/enrichment
    endpoints, an Active Scanner additionally reaches scan_dev (given an
    authorized scope), an Exploit Operator additionally reaches exploit_dev
    (given an authorized scope), and a superuser passes every check
    regardless of group membership."""

    def setUp(self):
        self.search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        self.device = Device.objects.create(search=self.search, ip='6.6.6.6', type='modbus', category='ics')
        # Covers the device's IP for both active operations, so the
        # capability checks in this class are exercised independently of
        # target-scope authorization (that is TargetScopeAuthorizationTests'
        # job).
        make_authorization(cidr='6.6.6.6/32', allow_port_scan=True, allow_exploit=True)

    def _login(self, username, groups=(), superuser=False):
        user = make_user(username, groups=groups, superuser=superuser)
        client = Client()
        client.force_login(user)
        return client

    # -- read-only pages: every authenticated user, capability or not ------

    def test_plain_authenticated_user_can_read_pages(self):
        # Login middleware already requires authentication for every page;
        # "view" is not gated behind a group, per spec every authenticated
        # user effectively has it.
        client = self._login('plain_user')
        for name, args in (
            ('index', []), ('devices', []), ('results', [self.search.id]),
            ('map', []), ('gallery', []), ('history', []), ('sources', []),
            ('device', [self.device.search_id, self.device.id, self.device.ip]),
        ):
            response = client.get(reverse(name, args=args))
            self.assertEqual(response.status_code, 200, name)

    def test_viewer_gets_200_on_read_pages(self):
        client = self._login('viewer_user', groups=['Viewer'])
        response = client.get(reverse('devices'))
        self.assertEqual(response.status_code, 200)
        response = client.get(reverse('device', args=[self.device.search_id, self.device.id, self.device.ip]))
        self.assertEqual(response.status_code, 200)

    # -- Viewer: 403 on run_search/active_scan/exploit ----------------------

    def test_viewer_gets_403_on_run_search_endpoint(self):
        client = self._login('viewer2', groups=['Viewer'])
        response = client.post(reverse('whois', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 403)

    def test_viewer_gets_403_on_export_devices(self):
        client = self._login('viewer3', groups=['Viewer'])
        response = client.get(reverse('export_devices'))
        self.assertEqual(response.status_code, 403)

    @override_settings(KAMERKA_ENABLE_ACTIVE_SCAN=True)
    def test_viewer_gets_403_on_active_scan_endpoint(self):
        client = self._login('viewer4', groups=['Viewer'])
        with mock.patch('app_kamerka.views.scan_task.apply_async') as mocked_scan:
            response = client.post(reverse('scan', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 403)
        mocked_scan.assert_not_called()

    @override_settings(KAMERKA_ENABLE_EXPLOITATION=True)
    def test_viewer_gets_403_on_exploit_endpoint(self):
        client = self._login('viewer5', groups=['Viewer'])
        with mock.patch('app_kamerka.views.exploit_task.apply_async') as mocked_exploit:
            response = client.post(reverse('exploit', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 403)
        mocked_exploit.assert_not_called()

    # -- Analyst: run_search/enrichment ok, scan/exploit still 403 ---------

    def test_analyst_can_run_search_and_enrichment(self):
        client = self._login('analyst1', groups=['Analyst'])
        with mock.patch('app_kamerka.views.whoisxml.delay', return_value=mock.Mock(id='t1')):
            response = client.post(reverse('whois', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)

        response = client.get(reverse('export_devices'))
        self.assertEqual(response.status_code, 200)

    @override_settings(KAMERKA_ENABLE_ACTIVE_SCAN=True)
    def test_analyst_gets_403_on_active_scan(self):
        client = self._login('analyst2', groups=['Analyst'])
        with mock.patch('app_kamerka.views.scan_task.apply_async') as mocked_scan:
            response = client.post(reverse('scan', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 403)
        mocked_scan.assert_not_called()

    @override_settings(KAMERKA_ENABLE_EXPLOITATION=True)
    def test_analyst_gets_403_on_exploit(self):
        client = self._login('analyst3', groups=['Analyst'])
        with mock.patch('app_kamerka.views.exploit_task.apply_async') as mocked_exploit:
            response = client.post(reverse('exploit', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 403)
        mocked_exploit.assert_not_called()

    # -- Active Scanner: can scan (with scope), not exploit -----------------

    @override_settings(KAMERKA_ENABLE_ACTIVE_SCAN=True)
    def test_active_scanner_can_scan_with_scope(self):
        client = self._login('scanner1', groups=['Active Scanner'])
        with mock.patch('app_kamerka.views.scan_task.apply_async', return_value=_FakeAsyncResult('scan-task')) as mocked_scan:
            response = client.post(reverse('scan', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(mocked_scan.call_args.kwargs['args'], [str(self.device.id)])

    @override_settings(KAMERKA_ENABLE_EXPLOITATION=True)
    def test_active_scanner_gets_403_on_exploit(self):
        client = self._login('scanner2', groups=['Active Scanner'])
        with mock.patch('app_kamerka.views.exploit_task.apply_async') as mocked_exploit:
            response = client.post(reverse('exploit', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 403)
        mocked_exploit.assert_not_called()

    # -- Exploit Operator: can exploit (with scope) --------------------------

    @override_settings(KAMERKA_ENABLE_EXPLOITATION=True)
    def test_exploit_operator_can_exploit_with_scope(self):
        client = self._login('exploiter1', groups=['Exploit Operator'])
        with mock.patch('app_kamerka.views.exploit_task.apply_async', return_value=_FakeAsyncResult('exploit-task')) as mocked_exploit:
            response = client.post(reverse('exploit', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(mocked_exploit.call_count, 1)
        self.assertEqual(mocked_exploit.call_args.kwargs['args'], [str(self.device.id)])
        self.assertTrue(mocked_exploit.call_args.kwargs['task_id'].startswith('exploit-'))

    @override_settings(KAMERKA_ENABLE_ACTIVE_SCAN=True)
    def test_exploit_operator_can_also_scan_with_scope(self):
        # Exploit Operator is cumulative: it also holds active_scan.
        client = self._login('exploiter2', groups=['Exploit Operator'])
        with mock.patch('app_kamerka.views.scan_task.apply_async', return_value=_FakeAsyncResult('scan-task')) as mocked_scan:
            response = client.post(reverse('scan', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(mocked_scan.call_args.kwargs['args'], [str(self.device.id)])

    # -- superuser: passes every check regardless of group ------------------

    @override_settings(KAMERKA_ENABLE_ACTIVE_SCAN=True, KAMERKA_ENABLE_EXPLOITATION=True)
    def test_superuser_passes_all_capability_checks(self):
        client = self._login('root_user', superuser=True)

        response = client.get(reverse('export_devices'))
        self.assertEqual(response.status_code, 200)

        with mock.patch('app_kamerka.views.whoisxml.delay', return_value=mock.Mock(id='t2')):
            response = client.post(reverse('whois', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)

        with mock.patch('app_kamerka.views.scan_task.apply_async', return_value=_FakeAsyncResult('scan-task')):
            response = client.post(reverse('scan', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)

        with mock.patch('app_kamerka.views.exploit_task.apply_async', return_value=_FakeAsyncResult('exploit-task')):
            response = client.post(reverse('exploit', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)

    def test_capability_denial_creates_audit_log_row(self):
        client = self._login('viewer6', groups=['Viewer'])
        response = client.post(reverse('whois', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(AuditLog.objects.count(), 1)
        row = AuditLog.objects.get()
        self.assertEqual(row.action, 'capability_denied')
        self.assertFalse(row.success)


class TargetScopeAuthorizationTests(TestCase):
    """Target-scope authorization (S4): active_scan/exploit capability
    alone is not enough for scan_dev/exploit_dev -- the device's IP must
    also fall within a non-expired ScanAuthorization row with the matching
    allow_* flag."""

    def setUp(self):
        self.search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        self.device = Device.objects.create(search=self.search, ip='203.0.113.7', type='modbus', category='ics')

        self.scanner = make_user('scoped_scanner', groups=['Active Scanner'])
        self.exploiter = make_user('scoped_exploiter', groups=['Exploit Operator'])
        self.scanner_client = Client()
        self.scanner_client.force_login(self.scanner)
        self.exploiter_client = Client()
        self.exploiter_client.force_login(self.exploiter)

    # -- is_target_authorized() unit-level checks ---------------------------

    def test_is_target_authorized_true_for_in_scope_ip(self):
        make_authorization(cidr='203.0.113.0/24', allow_port_scan=True, allow_exploit=False)
        self.assertTrue(is_target_authorized('203.0.113.7', 'port_scan'))
        self.assertFalse(is_target_authorized('203.0.113.7', 'exploit'))

    def test_is_target_authorized_false_for_out_of_scope_ip(self):
        make_authorization(cidr='203.0.113.0/24', allow_port_scan=True, allow_exploit=True)
        self.assertFalse(is_target_authorized('198.51.100.7', 'port_scan'))

    def test_is_target_authorized_false_when_expired(self):
        make_authorization(
            cidr='203.0.113.0/24', allow_port_scan=True,
            expires_at=timezone.now() - timezone.timedelta(days=1),
        )
        self.assertFalse(is_target_authorized('203.0.113.7', 'port_scan'))

    def test_is_target_authorized_true_when_expires_in_future(self):
        make_authorization(
            cidr='203.0.113.0/24', allow_port_scan=True,
            expires_at=timezone.now() + timezone.timedelta(days=1),
        )
        self.assertTrue(is_target_authorized('203.0.113.7', 'port_scan'))

    def test_is_target_authorized_false_without_any_scope(self):
        self.assertFalse(is_target_authorized('203.0.113.7', 'port_scan'))

    # -- scan_dev end-to-end --------------------------------------------------

    @override_settings(KAMERKA_ENABLE_ACTIVE_SCAN=True)
    def test_scan_denied_with_no_authorization(self):
        with mock.patch('app_kamerka.views.scan_task.apply_async') as mocked_scan:
            response = self.scanner_client.post(reverse('scan', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 403)
        self.assertIn('scope', response.json()['Error'].lower())
        mocked_scan.assert_not_called()

    @override_settings(KAMERKA_ENABLE_ACTIVE_SCAN=True)
    def test_scan_succeeds_with_in_scope_authorization(self):
        make_authorization(cidr='203.0.113.0/24', allow_port_scan=True, allow_exploit=False)
        with mock.patch('app_kamerka.views.scan_task.apply_async', return_value=_FakeAsyncResult('scan-task')) as mocked_scan:
            response = self.scanner_client.post(reverse('scan', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(mocked_scan.call_args.kwargs['args'], [str(self.device.id)])

    @override_settings(KAMERKA_ENABLE_ACTIVE_SCAN=True)
    def test_scan_denied_when_authorization_expired(self):
        make_authorization(
            cidr='203.0.113.0/24', allow_port_scan=True,
            expires_at=timezone.now() - timezone.timedelta(minutes=1),
        )
        with mock.patch('app_kamerka.views.scan_task.apply_async') as mocked_scan:
            response = self.scanner_client.post(reverse('scan', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 403)
        mocked_scan.assert_not_called()

    @override_settings(KAMERKA_ENABLE_ACTIVE_SCAN=True)
    def test_scan_denied_when_authorization_lacks_port_scan_flag(self):
        make_authorization(cidr='203.0.113.0/24', allow_port_scan=False, allow_exploit=True)
        with mock.patch('app_kamerka.views.scan_task.apply_async') as mocked_scan:
            response = self.scanner_client.post(reverse('scan', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 403)
        mocked_scan.assert_not_called()

    @override_settings(KAMERKA_ENABLE_ACTIVE_SCAN=True)
    def test_scan_denied_when_ip_outside_cidr(self):
        make_authorization(cidr='198.51.100.0/24', allow_port_scan=True, allow_exploit=True)
        with mock.patch('app_kamerka.views.scan_task.apply_async') as mocked_scan:
            response = self.scanner_client.post(reverse('scan', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 403)
        mocked_scan.assert_not_called()

    @override_settings(KAMERKA_ENABLE_ACTIVE_SCAN=True)
    def test_scan_scope_denial_creates_audit_log_row(self):
        response = self.scanner_client.post(reverse('scan', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(AuditLog.objects.count(), 1)
        row = AuditLog.objects.get()
        self.assertEqual(row.action, 'scope_denied')
        self.assertFalse(row.success)
        self.assertEqual(row.device_id, self.device.id)

    # -- exploit_dev end-to-end -----------------------------------------------

    @override_settings(KAMERKA_ENABLE_EXPLOITATION=True)
    def test_exploit_denied_with_no_authorization(self):
        with mock.patch('app_kamerka.views.exploit_task.apply_async') as mocked_exploit:
            response = self.exploiter_client.post(reverse('exploit', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 403)
        self.assertIn('scope', response.json()['Error'].lower())
        mocked_exploit.assert_not_called()

    @override_settings(KAMERKA_ENABLE_EXPLOITATION=True)
    def test_exploit_succeeds_with_in_scope_authorization(self):
        make_authorization(cidr='203.0.113.0/24', allow_port_scan=False, allow_exploit=True)
        with mock.patch('app_kamerka.views.exploit_task.apply_async', return_value=_FakeAsyncResult('exploit-task')) as mocked_exploit:
            response = self.exploiter_client.post(reverse('exploit', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(mocked_exploit.call_count, 1)
        self.assertEqual(mocked_exploit.call_args.kwargs['args'], [str(self.device.id)])
        self.assertTrue(mocked_exploit.call_args.kwargs['task_id'].startswith('exploit-'))

    @override_settings(KAMERKA_ENABLE_EXPLOITATION=True)
    def test_exploit_denied_when_authorization_expired(self):
        make_authorization(
            cidr='203.0.113.0/24', allow_exploit=True,
            expires_at=timezone.now() - timezone.timedelta(minutes=1),
        )
        with mock.patch('app_kamerka.views.exploit_task.apply_async') as mocked_exploit:
            response = self.exploiter_client.post(reverse('exploit', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 403)
        mocked_exploit.assert_not_called()

    @override_settings(KAMERKA_ENABLE_EXPLOITATION=True)
    def test_exploit_denied_when_authorization_lacks_exploit_flag(self):
        make_authorization(cidr='203.0.113.0/24', allow_port_scan=True, allow_exploit=False)
        with mock.patch('app_kamerka.views.exploit_task.apply_async') as mocked_exploit:
            response = self.exploiter_client.post(reverse('exploit', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 403)
        mocked_exploit.assert_not_called()

    @override_settings(KAMERKA_ENABLE_EXPLOITATION=True)
    def test_exploit_denied_when_ip_outside_cidr(self):
        make_authorization(cidr='198.51.100.0/24', allow_port_scan=True, allow_exploit=True)
        with mock.patch('app_kamerka.views.exploit_task.apply_async') as mocked_exploit:
            response = self.exploiter_client.post(reverse('exploit', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 403)
        mocked_exploit.assert_not_called()

    @override_settings(KAMERKA_ENABLE_EXPLOITATION=True)
    def test_exploit_scope_denial_creates_audit_log_row(self):
        response = self.exploiter_client.post(reverse('exploit', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(AuditLog.objects.count(), 1)
        row = AuditLog.objects.get()
        self.assertEqual(row.action, 'scope_denied')
        self.assertFalse(row.success)
        self.assertEqual(row.device_id, self.device.id)


def _fake_response(body=b'{}', status_code=200, chunk_size=8):
    """Build a real requests.Response with a canned body.

    iter_content() streams the body back in chunks (as PassiveClient's size
    guard expects), while .content/.text/.json() also work directly for
    tests that use this response standalone, without going through the
    size guard at all.
    """
    resp = requests.Response()
    resp.status_code = status_code
    resp._content = body
    resp._content_consumed = False
    resp.raw = mock.Mock(close=mock.Mock())

    def _iter_content(chunk_size=None, decode_unicode=False):
        for i in range(0, len(body), 8):
            yield body[i:i + 8]

    resp.iter_content = _iter_content
    return resp


class NetModuleTests(TestCase):
    """Unit tests for the shared HTTP safety layer (app_kamerka.net). No
    real network calls are made anywhere in this class."""

    def setUp(self):
        sleep_patcher = mock.patch('app_kamerka.net.time.sleep')
        sleep_patcher.start()
        self.addCleanup(sleep_patcher.stop)

    def test_passive_client_sets_timeout_and_user_agent(self):
        client = PassiveClient()
        with mock.patch.object(client.session, 'request', return_value=_fake_response()) as mocked:
            client.get('https://example.invalid/api')

        self.assertEqual(mocked.call_count, 1)
        _, kwargs = mocked.call_args
        self.assertEqual(kwargs['timeout'], PASSIVE_TIMEOUT)
        self.assertEqual(kwargs['headers']['User-Agent'], client.user_agent)
        self.assertTrue(kwargs['verify'])

    def test_passive_client_retries_transient_error_then_succeeds(self):
        client = PassiveClient()
        good_response = _fake_response(b'{"ok": true}')
        with mock.patch.object(
            client.session,
            'request',
            side_effect=[requests.exceptions.ConnectionError('reset'), good_response],
        ) as mocked:
            response = client.get('https://example.invalid/api')

        self.assertEqual(mocked.call_count, 2)
        self.assertEqual(response.content, b'{"ok": true}')

    def test_passive_client_raises_after_exhausting_retries(self):
        client = PassiveClient(max_retries=1)
        with mock.patch.object(
            client.session,
            'request',
            side_effect=requests.exceptions.ConnectionError('down'),
        ) as mocked:
            with self.assertRaises(requests.exceptions.ConnectionError):
                client.get('https://example.invalid/api')

        # Initial attempt + 1 retry = 2 calls, then it gives up.
        self.assertEqual(mocked.call_count, 2)

    def test_passive_client_size_guard_rejects_oversized_response(self):
        client = PassiveClient(max_response_bytes=16)
        oversized = _fake_response(b'x' * 1024)
        with mock.patch.object(client.session, 'request', return_value=oversized):
            with self.assertRaises(ResponseTooLarge):
                client.get('https://example.invalid/big')

    def test_active_client_sets_short_timeout_and_user_agent_and_no_retry(self):
        client = ActiveClient()
        with mock.patch('app_kamerka.net.requests.request', return_value=_fake_response()) as mocked:
            client.get('http://10.0.0.5:80/status')

        self.assertEqual(mocked.call_count, 1)
        _, kwargs = mocked.call_args
        self.assertEqual(kwargs['timeout'], ACTIVE_TIMEOUT)
        self.assertEqual(kwargs['headers']['User-Agent'], client.user_agent)
        self.assertTrue(kwargs['verify'])
        self.assertFalse(kwargs['allow_redirects'])

    def test_active_client_rejects_redirect_following(self):
        client = ActiveClient()
        with mock.patch('app_kamerka.net.requests.request') as mocked:
            with self.assertRaisesRegex(ValueError, 'does not follow redirects'):
                client.get('http://10.0.0.5:80/status', allow_redirects=True)
        mocked.assert_not_called()

    def test_active_client_does_not_retry_on_error(self):
        client = ActiveClient()
        with mock.patch(
            'app_kamerka.net.requests.request',
            side_effect=requests.exceptions.ConnectionError('device unreachable'),
        ) as mocked:
            with self.assertRaises(requests.exceptions.ConnectionError):
                client.get('http://10.0.0.5:80/status')

        # Exactly one attempt: active/target-facing calls must never be
        # auto-retried.
        self.assertEqual(mocked.call_count, 1)

    def test_active_client_honors_explicit_verify_false(self):
        client = ActiveClient()
        with mock.patch('app_kamerka.net.requests.request', return_value=_fake_response()) as mocked:
            client.post('https://10.0.0.5:443/cgi', data='action=getInfo', verify=False)

        _, kwargs = mocked.call_args
        self.assertFalse(kwargs['verify'])
        self.assertEqual(kwargs['timeout'], ACTIVE_TIMEOUT)

    def test_active_client_verify_defaults_true(self):
        client = ActiveClient()
        with mock.patch('app_kamerka.net.requests.request', return_value=_fake_response()) as mocked:
            client.get('https://10.0.0.5:443/deviceIP')

        _, kwargs = mocked.call_args
        self.assertTrue(kwargs['verify'])

    def test_active_client_streams_and_caps_response_bytes(self):
        client = ActiveClient(max_response_bytes=16)
        response = _fake_response(b'x' * 40)
        with mock.patch('app_kamerka.net.requests.request', return_value=response) as mocked:
            with self.assertRaises(ResponseTooLarge):
                client.get('http://10.0.0.5:80/large')
        self.assertTrue(mocked.call_args.kwargs['stream'])
        response.raw.close.assert_called_once()

    def test_active_client_enforces_total_response_duration(self):
        client = ActiveClient(max_duration=1)
        response = _fake_response(b'{}')
        with mock.patch('app_kamerka.net.requests.request', return_value=response):
            with mock.patch('app_kamerka.net.time.monotonic', side_effect=[0, 2]):
                with self.assertRaises(requests.exceptions.Timeout):
                    client.get('http://10.0.0.5:80/slow')
        response.raw.close.assert_called_once()


class PassiveCallSitesUseSharedClientTests(TestCase):
    """Regression: BinaryEdge and WhoisXML lookups in kamerka.tasks must go
    through the shared PassiveClient (timeouts, retries, UA), not a bare
    `requests.get(...)`."""

    def _patch_shodan_info(self):
        class FakeShodanClient:
            def __init__(self, api_key):
                pass

            def info(self):
                return {'query_credits': 111}

        patcher = mock.patch.object(tasks, 'Shodan', FakeShodanClient)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_check_credits_uses_passive_client_for_binaryedge(self):
        self._patch_shodan_info()
        fake_client = mock.Mock()
        fake_client.get.return_value = _fake_response(json.dumps({'requests_left': 42}).encode())

        with mock.patch.object(tasks, 'PassiveClient', return_value=fake_client) as mocked_cls:
            credits = tasks.check_credits()

        mocked_cls.assert_called_once_with()
        self.assertTrue(fake_client.get.called)
        called_url = fake_client.get.call_args[0][0]
        self.assertIn('binaryedge.io', called_url)
        self.assertIn(111, credits)
        self.assertIn(42, credits)

    def test_whoisxml_uses_passive_client(self):
        search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        device = Device.objects.create(search=search, ip='8.8.8.8', port='80')
        fake_client = mock.Mock()
        fake_body = {
            'WhoisRecord': {
                'registryData': {},
            }
        }
        fake_client.get.return_value = _fake_response(json.dumps(fake_body).encode())

        with mock.patch.object(tasks, 'PassiveClient', return_value=fake_client) as mocked_cls:
            tasks.whoisxml(device.id)

        mocked_cls.assert_called_once_with()
        self.assertTrue(fake_client.get.called)
        called_url = fake_client.get.call_args[0][0]
        self.assertIn('whoisxmlapi.com', called_url)


class _FakeAsyncResult:
    def __init__(self, task_id='fake-task-id'):
        self.id = task_id
        self.task_id = task_id


class SideEffectingEndpointsPostOnlyTests(TestCase):
    """update_coordinates/nearby/shodan_scan/whois/get_binaryedge_score used
    to be GET, gated only by the is_ajax() check -- a GET is treated by
    browsers/caches/tooling as safe and idempotent, so a mutating/
    side-effecting operation must never be reachable that way. They are now
    POST-only (still AJAX-gated) and CSRF-protected via Django's
    CsrfViewMiddleware. Any celery `.delay(...)` call is mocked -- no broker
    involved."""

    def setUp(self):
        self.user = make_user('postonly_tester', groups=['Analyst'])
        self.client.force_login(self.user)
        search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        self.device = Device.objects.create(
            search=search, ip='1.2.3.4', type='modbus', category='ics', lat='1.0', lon='2.0',
        )

    # -- update_coordinates ------------------------------------------------

    def test_update_coordinates_get_is_405(self):
        response = self.client.get(
            reverse('update_coordinates', args=[self.device.id, '3.0,4.0']), **AJAX_HEADER
        )
        self.assertEqual(response.status_code, 405)

    def test_update_coordinates_post_updates_device_and_logs(self):
        response = self.client.post(
            reverse('update_coordinates', args=[self.device.id, '3.0,4.0']), **AJAX_HEADER
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'Status': 'OK'})
        self.device.refresh_from_db()
        self.assertEqual(self.device.lat, '3.0')
        self.assertEqual(self.device.lon, '4.0')
        self.assertTrue(self.device.located)

        self.assertEqual(AuditLog.objects.count(), 1)
        row = AuditLog.objects.get()
        self.assertEqual(row.action, 'update_coordinates')
        self.assertEqual(row.device_id, self.device.id)
        self.assertEqual(row.target, '3.0,4.0')

    def test_update_coordinates_non_ajax_post_is_400(self):
        response = self.client.post(reverse('update_coordinates', args=[self.device.id, '3.0,4.0']))
        self.assertEqual(response.status_code, 400)

    # -- nearby --------------------------------------------------------

    def test_nearby_get_is_405(self):
        response = self.client.get(reverse('nearby', args=[self.device.id, 'webcam']), **AJAX_HEADER)
        self.assertEqual(response.status_code, 405)

    def test_nearby_post_queues_task_and_logs(self):
        with mock.patch(
            'app_kamerka.views.devices_nearby.delay', return_value=_FakeAsyncResult('nearby-task')
        ) as mocked_delay:
            response = self.client.post(reverse('nearby', args=[self.device.id, 'webcam']), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'task_id': 'nearby-task'})
        mocked_delay.assert_called_once()

        self.assertEqual(AuditLog.objects.count(), 1)
        row = AuditLog.objects.get()
        self.assertEqual(row.action, 'nearby')
        self.assertEqual(row.target, 'webcam')

    def test_nearby_non_ajax_post_is_400(self):
        response = self.client.post(reverse('nearby', args=[self.device.id, 'webcam']))
        self.assertEqual(response.status_code, 400)

    # -- shodan_scan -----------------------------------------------------

    def test_shodan_scan_get_is_405(self):
        response = self.client.get(reverse('shodan_scan', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 405)

    def test_shodan_scan_post_queues_task_and_logs(self):
        with mock.patch(
            'app_kamerka.views.shodan_scan_task.delay', return_value=_FakeAsyncResult('shodan-task')
        ) as mocked_delay:
            response = self.client.post(reverse('shodan_scan', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'task_id': 'shodan-task'})
        mocked_delay.assert_called_once_with(id=str(self.device.id))

        self.assertEqual(AuditLog.objects.count(), 1)
        self.assertEqual(AuditLog.objects.get().action, 'shodan_scan')

    def test_shodan_scan_non_ajax_post_is_400(self):
        response = self.client.post(reverse('shodan_scan', args=[self.device.id]))
        self.assertEqual(response.status_code, 400)

    # -- whois -------------------------------------------------------------

    def test_whois_get_is_405(self):
        response = self.client.get(reverse('whois', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 405)

    def test_whois_post_queues_task_and_logs(self):
        with mock.patch(
            'app_kamerka.views.whoisxml.delay', return_value=_FakeAsyncResult('whois-task')
        ) as mocked_delay:
            response = self.client.post(reverse('whois', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'task_id': 'whois-task'})
        mocked_delay.assert_called_once_with(id=str(self.device.id))

        self.assertEqual(AuditLog.objects.count(), 1)
        self.assertEqual(AuditLog.objects.get().action, 'whois')

    def test_whois_non_ajax_post_is_400(self):
        response = self.client.post(reverse('whois', args=[self.device.id]))
        self.assertEqual(response.status_code, 400)

    # -- get_binaryedge_score -----------------------------------------------

    def test_get_binaryedge_score_get_is_405(self):
        response = self.client.get(reverse('get_binaryedge_score', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 405)

    def test_get_binaryedge_score_post_queues_task_and_logs(self):
        with mock.patch(
            'app_kamerka.views.binary_edge_scan.delay', return_value=_FakeAsyncResult('be-task')
        ) as mocked_delay:
            response = self.client.post(reverse('get_binaryedge_score', args=[self.device.id]), **AJAX_HEADER)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'task_id': 'be-task'})
        mocked_delay.assert_called_once_with(id=str(self.device.id))

        self.assertEqual(AuditLog.objects.count(), 1)
        self.assertEqual(AuditLog.objects.get().action, 'binaryedge')

    def test_get_binaryedge_score_non_ajax_post_is_400(self):
        response = self.client.post(reverse('get_binaryedge_score', args=[self.device.id]))
        self.assertEqual(response.status_code, 400)


class CsrfProtectionTests(TestCase):
    """The side-effecting endpoints are now POST + CsrfViewMiddleware, so a
    real browser POST without a valid CSRF token must be rejected. The
    default test Client disables CSRF checks (so the AJAX-gate tests above
    can POST freely); this class turns enforcement back on to prove the
    protection is actually wired up, using set_device_status (no external
    call/celery task involved) as the representative endpoint."""

    def setUp(self):
        self.user = make_user('csrf_tester', groups=['Analyst'])
        search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        self.device = Device.objects.create(search=search, ip='1.2.3.4', type='modbus', category='ics')

    def test_post_without_csrf_token_is_rejected(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response = client.post(
            reverse('set_device_status', args=[self.device.id]), {'status': 'confirmed'}, **AJAX_HEADER
        )
        self.assertEqual(response.status_code, 403)
        self.device.refresh_from_db()
        self.assertEqual(self.device.status, 'new')

    def test_post_with_csrf_token_succeeds(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)

        # A GET first, so Django sets the csrftoken cookie (mirroring
        # {% csrf_token %} / @ensure_csrf_cookie on the real pages).
        client.get(reverse('index'))
        csrftoken = client.cookies['csrftoken'].value

        response = client.post(
            reverse('set_device_status', args=[self.device.id]),
            {'status': 'confirmed'},
            secure=False,
            **AJAX_HEADER,
            HTTP_X_CSRFTOKEN=csrftoken,
        )
        self.assertEqual(response.status_code, 200)
        self.device.refresh_from_db()
        self.assertEqual(self.device.status, 'confirmed')


class JSONFieldTruncationFixTests(TestCase):
    """Device.vulns/indicator/hostnames used to be CharField(max_length=100),
    which silently truncated (data loss, not an error) any real CVE list,
    indicator list, or hostnames list past 100 characters. They are now
    JSONField, so a value of any length round-trips through the DB with no
    truncation and no stringify/ast.literal_eval round-trip required."""

    def setUp(self):
        self.search = Search.objects.create(
            country='US', ics='modbus', coordinates='', coordinates_search='',
        )

    def test_long_vulns_list_round_trips_without_truncation(self):
        # 20 CVE ids, comfortably over the old 100-char CharField limit.
        long_cves = ['CVE-2020-%04d' % i for i in range(20)]
        self.assertGreater(len(str(long_cves)), 100)

        device = Device.objects.create(
            search=self.search, ip='10.0.0.9', type='modbus', category='ics',
            vulns=long_cves,
            indicator=['indicator-%d' % i for i in range(20)],
            hostnames=['host-%d.example.com' % i for i in range(20)],
        )
        device.refresh_from_db()

        self.assertEqual(device.vulns, long_cves)
        self.assertEqual(len(device.vulns), 20)
        self.assertIn('CVE-2020-0019', device.vulns)
        self.assertIsInstance(device.vulns, list)
        self.assertIsInstance(device.indicator, list)
        self.assertIsInstance(device.hostnames, list)
        self.assertEqual(len(device.indicator), 20)
        self.assertEqual(len(device.hostnames), 20)

    def test_vulns_indicator_hostnames_default_to_empty_list(self):
        device = Device.objects.create(search=self.search, ip='10.0.0.10', type='modbus', category='ics')
        self.assertEqual(device.vulns, [])
        self.assertEqual(device.indicator, [])
        self.assertEqual(device.hostnames, [])

    def test_scan_and_exploit_round_trip_as_dicts(self):
        device = Device.objects.create(
            search=self.search, ip='10.0.0.11', type='modbus', category='ics',
            scan={'ID': 'nmap-script', 'Output': 'x' * 200},
            exploit={'Reason': 'Connection error'},
        )
        device.refresh_from_db()
        self.assertEqual(device.scan, {'ID': 'nmap-script', 'Output': 'x' * 200})
        self.assertEqual(device.exploit, {'Reason': 'Connection error'})

    def test_search_ics_and_coordinates_search_round_trip_as_lists(self):
        search = Search.objects.create(
            country='US', ics=['modbus', 'bacnet', 'siemens'], coordinates='',
            coordinates_search=['1.0,2.0', '3.0,4.0'],
        )
        search.refresh_from_db()
        self.assertEqual(search.ics, ['modbus', 'bacnet', 'siemens'])
        self.assertEqual(search.coordinates_search, ['1.0,2.0', '3.0,4.0'])


class LegacyJsonFieldMigrationConversionTests(TestCase):
    """Direct tests of the conversion helpers used by the
    0008_convert_legacy_json_string_fields data migration, which rewrite the
    old ast.literal_eval-able CharField string values into the native
    list/dict values now expected by the JSONField columns. Every helper
    must never raise -- a malformed/legacy value always falls back to []
    or {}."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        migration_module = import_module(
            'app_kamerka.migrations.0008_convert_legacy_json_string_fields'
        )
        cls.parse_list_like = staticmethod(migration_module._parse_list_like)
        cls.parse_hostnames = staticmethod(migration_module._parse_hostnames)
        cls.parse_dict_like = staticmethod(migration_module._parse_dict_like)

    def test_parse_list_like_valid_list_repr(self):
        long_cves = ['CVE-2020-%04d' % i for i in range(20)]
        self.assertEqual(self.parse_list_like(str(long_cves)), long_cves)

    def test_parse_list_like_empty_string_is_empty_list(self):
        self.assertEqual(self.parse_list_like(''), [])

    def test_parse_list_like_malformed_string_is_empty_list(self):
        self.assertEqual(self.parse_list_like('not a list {{{'), [])

    def test_parse_list_like_non_list_repr_is_empty_list(self):
        # A stray scalar repr (e.g. a bare number or dict) isn't a
        # list/tuple, so it must not leak through as some other JSON type.
        self.assertEqual(self.parse_list_like('42'), [])
        self.assertEqual(self.parse_list_like("{'a': 1}"), [])

    def test_parse_hostnames_single_value_becomes_single_item_list(self):
        self.assertEqual(self.parse_hostnames('plc.example.com'), ['plc.example.com'])

    def test_parse_hostnames_empty_is_empty_list(self):
        self.assertEqual(self.parse_hostnames(''), [])

    def test_parse_dict_like_valid_dict_repr(self):
        self.assertEqual(
            self.parse_dict_like(str({'ID': 'x', 'Output': 'y'})),
            {'ID': 'x', 'Output': 'y'},
        )

    def test_parse_dict_like_empty_is_empty_dict(self):
        self.assertEqual(self.parse_dict_like(''), {})

    def test_parse_dict_like_malformed_is_empty_dict(self):
        self.assertEqual(self.parse_dict_like('garbage((('), {})

    def test_parse_dict_like_non_dict_repr_is_empty_dict(self):
        self.assertEqual(self.parse_dict_like("['not', 'a', 'dict']"), {})


@override_settings(KAMERKA_ENABLE_ACTIVE_SCAN=True, KAMERKA_ENABLE_EXPLOITATION=True)
class ScanExploitTaskTests(TestCase):
    """Direct tests of the scan_task/exploit_task Celery task functions
    (kamerka/tasks.py), with Nmap and the exploit probes mocked out -- no
    real network access or nmap binary is used. These confirm the tasks
    persist their result to the device row and return the expected dict,
    independent of the (now async) scan_dev/exploit_dev views that enqueue
    them -- see ActiveOpsFeatureFlagTests/TargetScopeAuthorizationTests for
    the view-level enqueue behaviour."""

    def setUp(self):
        self.search = Search.objects.create(country='US', ics='modbus', coordinates='', coordinates_search='')
        self.actor = make_user('active_task_actor', superuser=True)
        self.authorization = make_authorization()

    def _worker_context(self, device, kind):
        operation = Operation.objects.create(
            kind=kind, actor=self.actor, device=device, authorization_id=self.authorization.pk,
            target_ip=device.ip, target_port=device.port, target_type=device.type,
        )
        context = dict(operation_id=str(operation.pk), authorization_id=self.authorization.pk,
                    actor_id=self.actor.pk, expected_ip=device.ip, expected_port=device.port,
                    expected_type=device.type)
        return operation, context

    def _fake_nmap(self, stdout):
        instance = mock.Mock()
        instance.is_running.return_value = False
        instance.run_background.return_value = None
        instance.stdout = stdout
        return mock.Mock(return_value=instance)

    def test_scan_task_plain_nmap_scan_persists_and_returns_state(self):
        # A non-ICS device type takes the plain "-p <port>" nmap branch
        # (no nmap_scripts/*.nse), which reports open/closed state.
        device = Device.objects.create(
            search=self.search, ip='10.0.0.20', port='80', type='hikvision', category='ipcam',
        )
        xml = (
            b'<nmaprun><host><ports><port>'
            b'<state state="open" reason="syn-ack"/>'
            b'</port></ports></host></nmaprun>'
        )
        with mock.patch.object(tasks, 'NmapProcess', self._fake_nmap(xml)) as mocked_cls:
            operation, context = self._worker_context(device, 'scan')
            result = tasks.scan_task(device.id, **context)

        mocked_cls.assert_called_once()
        self.assertEqual(result, {'State': 'open', 'Reason': 'syn-ack'})
        operation.refresh_from_db()
        self.assertEqual(operation.status, 'succeeded')
        self.assertIsNotNone(operation.started_at)
        self.assertIsNotNone(operation.finished_at)
        device.refresh_from_db()
        self.assertEqual(device.scan, {'State': 'open', 'Reason': 'syn-ack'})
        self.assertTrue(device.exploited_scanned)

    def test_scan_task_ics_nmap_script_scan_persists_and_returns_output(self):
        # An ICS device type (modbus is in tasks.ics_scan) instead runs the
        # matching NSE script and reports its @id/@output.
        device = Device.objects.create(
            search=self.search, ip='10.0.0.21', port='502', type='modbus', category='ics',
        )
        xml = (
            b'<nmaprun><host><ports><port>'
            b'<script id="modbus-discover" output="Slave ID data: 1"/>'
            b'</port></ports></host></nmaprun>'
        )
        with mock.patch.object(tasks, 'NmapProcess', self._fake_nmap(xml)) as mocked_cls:
            operation, context = self._worker_context(device, 'scan')
            result = tasks.scan_task(device.id, **context)

        mocked_cls.assert_called_once()
        self.assertEqual(result, {'ID': 'modbus-discover', 'Output': 'Slave ID data: 1'})
        device.refresh_from_db()
        self.assertEqual(device.scan, {'ID': 'modbus-discover', 'Output': 'Slave ID data: 1'})
        self.assertTrue(device.exploited_scanned)

    def test_scan_task_is_routed_to_the_active_queue(self):
        self.assertEqual(tasks.scan_task.queue, 'active')

    def test_exploit_task_is_routed_to_the_active_queue(self):
        self.assertEqual(tasks.exploit_task.queue, 'active')

    def test_exploit_task_unknown_type_returns_no_exploit_assigned(self):
        device = Device.objects.create(
            search=self.search, ip='10.0.0.22', port='80', type='some_unhandled_type', category='ipcam',
        )
        _operation, context = self._worker_context(device, 'exploit')
        result = tasks.exploit_task(device.id, **context)
        self.assertEqual(result, {'Reason': 'No exploit assigned'})

    def test_exploit_task_dispatches_to_matching_exploit_and_persists(self):
        # exploit_task() itself just routes by device.type to the matching
        # app_kamerka.exploits.* probe; persistence to device.exploit
        # happens inside that probe (see app_kamerka/exploits.py). Mock the
        # probe (no real network/credential-guessing) but have it persist,
        # the way the real ones do, to confirm the task's return value and
        # the persisted row line up.
        device = Device.objects.create(
            search=self.search, ip='10.0.0.23', port='23', type='lutron', category='ics',
        )

        def fake_lutron(dev):
            dev.exploit = {'Success': 'lutron config retrieved'}
            dev.exploited_scanned = True
            dev.save()
            return {'Success': 'lutron config retrieved'}

        with mock.patch.object(tasks.exploits, 'lutron', side_effect=fake_lutron) as mocked_lutron:
            operation, context = self._worker_context(device, 'exploit')
            result = tasks.exploit_task(device.id, **context)

        mocked_lutron.assert_called_once()
        self.assertEqual(result, {'Success': 'lutron config retrieved'})
        device.refresh_from_db()
        self.assertEqual(device.exploit, {'Success': 'lutron config retrieved'})
        self.assertTrue(device.exploited_scanned)
        operation.refresh_from_db()
        self.assertEqual(operation.status, 'succeeded')

    def test_worker_direct_invocation_without_context_is_blocked(self):
        device = Device.objects.create(
            search=self.search, ip='10.0.0.24', port='80', type='hikvision', category='ipcam',
        )
        with mock.patch.object(tasks, 'NmapProcess') as nmap:
            result = tasks.scan_task(device.id)
        self.assertEqual(result, {'Error': 'Active operation blocked'})
        nmap.assert_not_called()
        self.assertEqual(Operation.objects.get(kind='scan').status, 'blocked')

    def test_worker_blocks_revoked_pinned_authorization(self):
        device = Device.objects.create(
            search=self.search, ip='10.0.0.25', port='80', type='hikvision', category='ipcam',
        )
        operation, context = self._worker_context(device, 'scan')
        self.authorization.delete()
        with mock.patch.object(tasks, 'NmapProcess') as nmap:
            result = tasks.scan_task(device.id, **context)
        self.assertEqual(result, {'Error': 'Active operation blocked'})
        nmap.assert_not_called()
        operation.refresh_from_db()
        self.assertEqual(operation.status, 'blocked')

    def test_worker_blocks_expired_pinned_authorization(self):
        device = Device.objects.create(
            search=self.search, ip='10.0.0.26', port='80', type='hikvision', category='ipcam',
        )
        operation, context = self._worker_context(device, 'scan')
        self.authorization.expires_at = timezone.now() - timezone.timedelta(seconds=1)
        self.authorization.save(update_fields=['expires_at'])
        with mock.patch.object(tasks, 'NmapProcess') as nmap:
            result = tasks.scan_task(device.id, **context)
        self.assertEqual(result, {'Error': 'Active operation blocked'})
        nmap.assert_not_called()
        operation.refresh_from_db()
        self.assertEqual(operation.status, 'blocked')

    def test_worker_blocks_target_mutation_after_enqueue(self):
        device = Device.objects.create(
            search=self.search, ip='10.0.0.27', port='80', type='hikvision', category='ipcam',
        )
        operation, context = self._worker_context(device, 'scan')
        device.ip = '10.0.0.28'
        device.save(update_fields=['ip'])
        with mock.patch.object(tasks, 'NmapProcess') as nmap:
            result = tasks.scan_task(device.id, **context)
        self.assertEqual(result, {'Error': 'Active operation blocked'})
        nmap.assert_not_called()
        operation.refresh_from_db()
        self.assertEqual(operation.status, 'blocked')

    def test_worker_blocks_actor_after_capability_revocation(self):
        actor = make_user('revoked_task_actor', groups=['Active Scanner'])
        device = Device.objects.create(
            search=self.search, ip='10.0.0.30', port='80', type='hikvision', category='ipcam',
        )
        operation = Operation.objects.create(
            kind='scan', actor=actor, device=device, authorization_id=self.authorization.pk,
            target_ip=device.ip, target_port=device.port, target_type=device.type,
        )
        context = dict(operation_id=str(operation.pk), authorization_id=self.authorization.pk,
                       actor_id=actor.pk, expected_ip=device.ip, expected_port=device.port,
                       expected_type=device.type)
        actor.groups.clear()
        with mock.patch.object(tasks, 'NmapProcess') as nmap:
            result = tasks.scan_task(device.id, **context)
        self.assertEqual(result, {'Error': 'Active operation blocked'})
        nmap.assert_not_called()
        operation.refresh_from_db()
        self.assertEqual(operation.status, 'blocked')

    def test_worker_blocks_when_feature_flag_is_disabled_after_enqueue(self):
        device = Device.objects.create(
            search=self.search, ip='10.0.0.31', port='80', type='hikvision', category='ipcam',
        )
        operation, context = self._worker_context(device, 'scan')
        with override_settings(KAMERKA_ENABLE_ACTIVE_SCAN=False):
            with mock.patch.object(tasks, 'NmapProcess') as nmap:
                result = tasks.scan_task(device.id, **context)
        self.assertEqual(result, {'Error': 'Active operation blocked'})
        nmap.assert_not_called()
        operation.refresh_from_db()
        self.assertEqual(operation.status, 'blocked')

    def test_worker_blocks_when_pinned_authorization_flags_change(self):
        device = Device.objects.create(
            search=self.search, ip='10.0.0.32', port='80', type='hikvision', category='ipcam',
        )
        operation, context = self._worker_context(device, 'scan')
        self.authorization.allow_port_scan = False
        self.authorization.save(update_fields=['allow_port_scan'])
        with mock.patch.object(tasks, 'NmapProcess') as nmap:
            result = tasks.scan_task(device.id, **context)
        self.assertEqual(result, {'Error': 'Active operation blocked'})
        nmap.assert_not_called()
        operation.refresh_from_db()
        self.assertEqual(operation.status, 'blocked')

    def test_worker_blocks_when_pinned_authorization_cidr_changes(self):
        device = Device.objects.create(
            search=self.search, ip='10.0.0.33', port='80', type='hikvision', category='ipcam',
        )
        operation, context = self._worker_context(device, 'scan')
        self.authorization.cidr = '192.0.2.0/24'
        self.authorization.save(update_fields=['cidr'])
        with mock.patch.object(tasks, 'NmapProcess') as nmap:
            result = tasks.scan_task(device.id, **context)
        self.assertEqual(result, {'Error': 'Active operation blocked'})
        nmap.assert_not_called()
        operation.refresh_from_db()
        self.assertEqual(operation.status, 'blocked')

    def test_duplicate_task_does_not_repeat_network_or_overwrite_outcome(self):
        device = Device.objects.create(
            search=self.search, ip='10.0.0.34', port='80', type='hikvision', category='ipcam',
        )
        operation, context = self._worker_context(device, 'scan')
        xml = b'<nmaprun><host><ports><port><state state="open" reason="syn-ack"/></port></ports></host></nmaprun>'
        with mock.patch.object(tasks, 'NmapProcess', self._fake_nmap(xml)) as nmap:
            first = tasks.scan_task(device.id, **context)
            second = tasks.scan_task(device.id, **context)
        self.assertEqual(first, {'State': 'open', 'Reason': 'syn-ack'})
        self.assertEqual(second, {'Error': 'Active operation blocked'})
        nmap.assert_called_once()
        operation.refresh_from_db()
        self.assertEqual(operation.status, 'succeeded')

    def test_worker_failure_is_persisted_and_audited(self):
        device = Device.objects.create(
            search=self.search, ip='10.0.0.29', port='80', type='hikvision', category='ipcam',
        )
        operation, context = self._worker_context(device, 'scan')
        with mock.patch.object(tasks, 'NmapProcess', side_effect=RuntimeError('nmap failed')):
            with self.assertRaisesRegex(RuntimeError, 'nmap failed'):
                tasks.scan_task(device.id, **context)
        operation.refresh_from_db()
        self.assertEqual(operation.status, 'failed')
        self.assertIn('nmap failed', operation.error)
        self.assertFalse(AuditLog.objects.filter(action='scan', success=True).exists())
