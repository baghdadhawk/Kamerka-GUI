import ast
import csv
import json
import logging
import os
from collections import Counter
from urllib.parse import urlencode
import requests
from django.core.files.storage import FileSystemStorage
from .forms import UploadFileForm
import pycountry
from celery.result import AsyncResult
from django.core import serializers
from django.db.models import Count
from django.http import HttpResponse, JsonResponse
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.views.decorators.csrf import ensure_csrf_cookie

from app_kamerka import forms
from app_kamerka.models import Search, Device, DeviceNearby, ShodanScan, BinaryEdgeScore, Whois, \
    Bosch, AuditLog
from django.conf import settings
from kamerka.tasks import shodan_search, devices_nearby, shodan_scan_task, \
    binary_edge_scan, whoisxml, check_credits, nmap_scan, validate_nmap, validate_maxmind, scan, \
    exploit, build_family_selection, count_devices, honeyscore
from app_kamerka.banner_utils import looks_like_generic_http_response
from app_kamerka.honeypot import HONEYPOT_THRESHOLD
from app_kamerka.sightings import other_sightings

logger = logging.getLogger(__name__)


# Create your views here.

def is_ajax(request):
    """Replacement for the removed HttpRequest.is_ajax() (Django >= 3.1)."""
    return request.headers.get('x-requested-with') == 'XMLHttpRequest'


def method_not_allowed(allowed='POST'):
    """405 JSON response for the side-effecting endpoints below, which now
    require POST (they used to be GET, gated only by the is_ajax() check --
    unsafe, since a GET is treated by browsers/caches/tooling as safe and
    idempotent)."""
    response = HttpResponse(
        json.dumps({'Error': 'Method not allowed, use POST'}),
        content_type='application/json', status=405,
    )
    response['Allow'] = allowed
    return response


def _get_device_or_none(id):
    """Best-effort Device lookup for audit logging -- never raises."""
    try:
        return Device.objects.get(id=id)
    except Exception:
        return None


def record_audit(request, action, device=None, target='', detail='', success=True):
    """Write one AuditLog row for a sensitive/side-effecting operation.
    Never raises -- an audit-logging failure must not break the operation it
    is recording."""
    try:
        user = request.user if getattr(request, 'user', None) and request.user.is_authenticated else None
        AuditLog.objects.create(
            user=user,
            action=action,
            device=device,
            target=target or '',
            detail=detail if isinstance(detail, str) else json.dumps(detail, default=str),
            success=success,
        )
    except Exception as e:
        logger.warning("record_audit failed for action=%s: %s", action, e)

passwds = {"bosch_security":"""The Bosch Video Recorder 630/650 Series is an 8/16 
          channel digital recorder that uses the latest H.264 
          compression technology. With the supplied PC
          software and built-in web server, the 630/650 Series is
          a fully integrated, stand-alone video management
          solution that's ready to go, straight out of the box.
          Available with a variety of storage capacities, the
          630/650 Series features a highly reliable embedded
          design that minimizes maintenance and reduces
          operational costs. The recorder is also available with a
          built-in DVD writer <br>
          https://www.exploit-db.com/exploits/34956 """,
           "niagara":"Tridium is the developer of Niagara Framework® — a comprehensive software platform for the development and deployment of connected products and device-to-enterprise applications. Niagara provides the critical device connectivity, cyber security, control, data management, device management and user presentation capabilities needed to extract value and insight from real-time operational data <br> Default credentials: <br>tridium:niagara",
           "siemens":"S7 (S7 Communication) is a Siemens proprietary protocol that runs between programmable logic controllers (PLCs) of the Siemens S7 family. <br>Default credentials: <br> Hardcoded password: Basisk:Basisk <br> admin:blank",
           "bacnet":"BACnet is a communications protocol for building automation and control networks. It was designed to allow communication of building automation and control systems for applications such as heating, air-conditioning, lighting, and fire detection systems.",
           "modbus":"Modbus is a popular protocol for industrial control systems (ICS). It provides easy, raw access to the control system without requiring any authentication.",
           "dnp3":"DNP3 (Distributed Network Protocol) is a set of communications protocols used between components in process automation systems. Its main use is in utilities such as electric and water companies.",
           "plantivosr":"PlantVisor Enhanced is monitoring and telemaintenance software for refrigeration and air-conditioning systems controlled by CAREL instruments. PlantVisor, thanks to the embedded Web Server, can be used on a series of PCs connected to a TCP/IP network. In this way, the information can be shared by a number of users at the same time. <br> Default credentials: <br> admin:admin",
           "iologik":"The ioLogik E1200 Series supports the most often-used protocols for retrieving I/O data, making it capable of handling a wide variety of applications. Most IT engineers use SNMP or RESTful API protocols, but OT engineers are more familiar with OT-based protocols, such as Modbus and EtherNet/IP. <br>Default credentials: <br> administrator:blank",
           "akcp":"The AKCP sensorProbe+ series of base units are our flagship Remote Environmental Sensor Monitoring Device. Our sensor monitoring systems are deployed in a wide variety of industries including Data Center Environmental Monitoring, Warehouse Temperature Monitoring, Cold Storage Temperature Monitoring, Fuel / Generator Monitoring, and other Remote Site Monitoring applications.<br>Default credentials: <br> administrator:public <br> admin:public",
           "vtscada":"https://www.vtscada.com/wp-content/uploads/2016/09/VTScada11-2-AdminGuide.pdf",
           "sailor":"<br>Default credentials: <br> admin:1234 <br> https://www.livewire-connections.com/sites/default/files/files/documents/Sailor%20900%20Ka%20Installation%20Manual.pdf",
           "digi":"Digi TransPort WR21 is a full-featured cellular router offering the flexibility to scale from basic connectivity applications to enterprise class routing and security solutions. With its high-performance architecture, Digi TransPort WR21 provides primary and backup WWAN connectivity over 3G/4G/LTE. The platform includes software selectable multi-carrier and regional LTE variants. <br>Default credentials:<br>username:password",
           "ilon":"The i.LON® SmartServer is a low-cost, high-performance controller, network manager, router, remote network interface, and Web server that you can use to connect LONWORKS®, Modbus, and M-Bus devices to corporate IP networks or the Internet.  <br>Default credentials: <br> for ftp and lns servers:, ilon:ilon <br> ",
           "eig":"<br>Default credentials: <br> anonymous:anonymous <br> eignet:inp100",
            "mitsubishi":"<br>Default credentials: <br> MELSEC:MELSEC <br> QNUDECPU:QNUDECPU <br> MELSEC-Q Series use a proprietary network protocol for communication. The devices are used by equipment and manufacturing facilities to provide high-speed, large volume data processing and machine control.",
           "moxahttp": "NPort® 5100 device servers are designed to make serial devices network-ready in an instant. The small size of the servers makes them ideal for connecting devices such as card readers and payment terminals to an IP-based Ethernet LAN. Use the NPort 5100 device servers to give your PC software direct access to serial devices from anywhere on the network. <br>Default credentials: <br> admmin:moxa",
           "omron":"FINS, Factory Interface Network Service, is a network protocol used by Omron PLCs, over different physical networks like Ethernet, Controller Link, DeviceNet and RS-232C. <br>Default credentials: <br> for http: ETHERNET, for ftp: CONFIDENTIAL <br> default:default",
            "power_logic":"https://www.se.com/ww/en/product-range/62252-powerlogic-pm8000-series/?selected-node-id=12146165208#tabs-top <br>Default credentials: <br> 0000 <br> 0 <br> Administrator:Gateway <br> Administrator:admin, User 1:master, User 2:engineer, User 3:operator",
            "scalance":"SCALANCE network components form the basis of communication networks in manufacturing and process automation. Make your industrial networks fit for the future! SCALANCE products have been specially designed for use in industrial applications. As a result, they fulfill all requirements for ultra-efficient industrial networks and bus systems. Whether switching, routing, security applications, remote access or Industrial Wireless LAN – SCALANCE is the solution!  <br>Default credentials: <br> admin:admin (HTTP), user:user (HTTP), siemens:siemens (FTP)",
            "stulz_klimatechnik":"he WIB (Web Interface Board) is an interface between STULZ air conditioning units and the intranet or inter-net via an ethernet connection. This connection allows monitoring and control of  A/C units. On the operators’s side the appropriate hardware (PC or server) and the appropriate software (SNMP client and/or web browser) are necessary. <br>Default credentials: <br> Administrator, highest authorization:, ganymed, Medium authorization:, kallisto, Lowest authorization:, europa ",
           "wago":"<br>Default credentials: <br> admin:wago, user:user, guest:guest <br> http, ftp:, user:user00 , administrator:, su:ko2003wa <br> root:wago , admin:wago, user:user , guest:guest ",
           "axis":"<br>Default credentials: <br> root:pass",
           "intellislot":"Provides Web access, environmental sensor data, and third-party customer protocols for Vertiv™ equipment. The cards employ Ethernet and RS-485 networks to monitor and manage a wide range of operating parameters, alarms and notifications. Provides a communication interface to Trellis™, LIFE™ Services, Liebert® Nform, and third-party building and network management applications. <br>Default credentials: <br> Liebert:Liebert, User:User",
           "iqinvision":"<br>Default credentials: <br> root:system",
           "lantronix":"Lantronix EDS-MD is specifically designed for the medical industry, allowing for remote access and management of electronic and medical devices. <br>Default credentials: <br> admin:PASS ",
           "loytec":"https://www.loytec.com/support/download/lvis-3me7-g2 <br>Default credentials: <br> admin:loytec4u",
           "videoiq" : "VideoIQ develops intelligent video surveillance cameras using edge video IP security cameras paired with video analytics. <br> VideoIQ is vulnerable to remote file disclosure which allows to any unauthenticated user read any file system including file configurations.<br>Default credentials"
                       "<br>supervisor:supervisor <br> https://www.exploit-db.com/exploits/40284",
           "webcamxp":"""webcamXP is the most popular webcam and network camera software for Windows.It allows you to monitor your belongings from any location with access to Internet by turning your computer into a security system.
            Connect remotely by using other computers or your mobile phone. Broadcast live video to your website. Schedule automatic captures or recordings. Trig specific actions using the motion detector. You can easily use those features among others with webcamXP.<br>Default credentials:<br>admin:<blank>""",
           "vivotek":"Default credentials:<br>root:<blank>",
           "mobotix":"https://www.mobotix.com/en/products/outdoor-cameras<br>Default credentials:<br>admin:meinsm",
           "grandstream":"Create and customize a security environment with Grandstream’s range of Full HD IP cameras. Easy to setup, deploy and manage, these cameras offer a proactive security system to keep a user’s facility secured and protected. The GSC3600 series of HD IP cameras feature full HD resolution and include weatherproof casing designed for increased security and facility management in any indoor or outdoor area for wide-angle monitoring of nearby subjects.<br>Default credentials:<br>admin:meinsm<br>https://www.exploit-db.com/exploits/48247",
           "contec":"http://www.contec-touch.com/wireless-smart-home/ <br> https://www.exploit-db.com/exploits/44295",
           "netwave":"https://www.exploit-db.com/exploits/41236",
           "CirCarLife":"CirCarlife Scada represents an integral software solution that focuses on the control and parameterisation of smart electric vehicle charging points and units. It gives centralised control of the whole installation for management and maintenance purposes.<br>https://www.exploit-db.com/exploits/45384",
           "amcrest":"https://www.exploit-db.com/exploits/47188",
           "lutron":"Quantum is a lighting control and energy management system that provides total light management by tying the most complete line of lighting controls, motorized window shades, digital ballasts and LED drivers, and sensors together under one software umbrella. Quantum is ideal for new construction or retrofit applications and can easily scale from a single area to a building, or to a campus with many buildings.<br>https://www.exploit-db.com/exploits/44488",
           }

# API keys are read from a JSON file resolved relative to the project root
# (or from the path in the KAMERKA_KEYS_FILE environment variable), so the
# location no longer depends on the current working directory.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS_FILE = os.environ.get('KAMERKA_KEYS_FILE', os.path.join(_PROJECT_ROOT, 'keys.json'))


def get_keys():
    try:
        with open(KEYS_FILE) as keys:
            keys_json = json.load(keys)

        return keys_json
    except Exception as e:
        logger.warning("Failed to load keys file %s: %s", KEYS_FILE, e)


keys = get_keys()


def search_main(request):
    if request.method == 'POST':

        # create a form instance and populate it with data from the request:
        coordinates_form = forms.CoordinatesForm(request.POST)
        ics_form = forms.CountryForm(request.POST)
        healthcare_form = forms.CountryHealthcareForm(request.POST)
        infra_form = forms.InfraForm(request.POST)

        if ics_form.is_valid():
            code = ics_form.cleaned_data['country']

            ics_country = request.POST.getlist('ics_country')

            # Optional "also include everything in this other category" checkboxes
            # on the ICS tab, so a single run/Search row can span ICS +
            # healthcare + infra together (each Device is still tagged with its
            # own correct category by shodan_search/shodan_search_worker).
            extra_healthcare = ['__all__'] if request.POST.get('include_healthcare_all') else []
            extra_infra = ['__all__'] if request.POST.get('include_infra_all') else []

            if len(ics_country) == 0 and not extra_healthcare and not extra_infra:
                form = forms.CountryForm()
                return render(request, 'search_main.html', {'form': form})

            # Keep the stored `ics` field consistent with what is actually
            # searched: the selected ICS families plus a marker for any
            # whole extra category that was included.
            stored_selection = list(ics_country)
            if extra_healthcare:
                stored_selection.append('healthcare:__all__')
            if extra_infra:
                stored_selection.append('infra:__all__')

            search = Search(country=code, ics=stored_selection)
            search.save()

            if ics_form.cleaned_data['all'] == True:
                all_results = True
            else:
                all_results = False

            # Opt-in query-credit optimization (default off): collapse the
            # curated set of port-identifiable ICS families into a single
            # combined Shodan search instead of one search per family. See
            # kamerka.tasks.GROUPABLE_PORT_FAMILIES/partition_groupable.
            group_ports = bool(request.POST.get('group_ports'))

            shodan_search_task = shodan_search.delay(fk=search.id, country=code, ics=ics_country,
                                                      healthcare=extra_healthcare, infra=extra_infra,
                                                      all_results=all_results, group_ports=group_ports)
            request.session['task_id'] = shodan_search_task.task_id

            return HttpResponseRedirect('index')


        elif healthcare_form.is_valid():
            code = healthcare_form.cleaned_data['country_healthcare']

            healthcare_country = request.POST.getlist('healthcare')


            if len(healthcare_country) == 0:

                form = forms.CountryHealthcareForm()
                return render(request, 'search_main.html', {'form': form})

            search = Search(country=code, ics=healthcare_country)
            search.save()

            if healthcare_form.cleaned_data['all'] == True:
                all_results = True
            else:
                all_results = False

            shodan_search_task = shodan_search.delay(fk=search.id, country=code, healthcare=healthcare_country,
                                                      all_results=all_results)
            request.session['task_id'] = shodan_search_task.task_id

            return HttpResponseRedirect('index')

        elif coordinates_form.is_valid():

            coordinates = coordinates_form.cleaned_data['coordinates']
            if len(coordinates) == 0:
                form = forms.CountryForm()
                return render(request, 'search_main.html', {'form': form})

            search = Search(coordinates=coordinates_form.cleaned_data['coordinates'],
                            coordinates_search=request.POST.getlist('coordinates_search'))

            search.save()
            shodan_search_task = shodan_search.delay(fk=search.id, coordinates=coordinates,
                                     coordinates_search=request.POST.getlist('coordinates_search'))

            request.session['task_id'] = shodan_search_task.task_id

            return HttpResponseRedirect('index')

        elif infra_form.is_valid():

            code = infra_form.cleaned_data['country_infra']

            # NOTE: this used to read request.POST.getlist('country_infra'),
            # but 'country_infra' is the (single-value) country field, not the
            # family multiselect, which is named 'infra' in the template. That
            # meant the family selection was never actually read here. Fixed
            # to read the right field.
            infra_country = request.POST.getlist('infra')

            if len(infra_country) == 0:
                form = forms.InfraForm()
                return render(request, 'search_main.html', {'form': form})

            search = Search(country=code, ics=infra_country)
            search.save()

            if infra_form.cleaned_data['all'] == True:
                all_results = True
            else:
                all_results = False

            shodan_search_task = shodan_search.delay(fk=search.id, country=code, infra=infra_country,
                                                      all_results=all_results)
            request.session['task_id'] = shodan_search_task.task_id

            return HttpResponseRedirect('index')

        try:
            myfile = request.FILES['myfile']
        except Exception:
            form = forms.CountryForm()
            return render(request, 'search_main.html', {'form': form})

        if request.method == 'POST' and request.FILES['myfile']:
            myfile = request.FILES['myfile']
            try:
                fs = FileSystemStorage()
                filename = fs.save(myfile.name, myfile)
                uploaded_file_url = fs.url(filename)
                logger.info("Uploaded nmap file: %s", uploaded_file_url)
                validate_nmap(uploaded_file_url)
                validate_maxmind()
                search = Search(country="NMAP Scan", ics=myfile.name,nmap=True)
                search.save()
                nmap_task = nmap_scan.delay(uploaded_file_url ,fk=search.id)

                request.session['task_id'] = nmap_task.task_id
                logger.info("nmap_task queued: %s", nmap_task.task_id)
            except Exception as e:
                logger.exception("nmap file upload/scan failed: %s", e)
                return JsonResponse({'message':str(e)}, status=500)

            return HttpResponseRedirect('index')

        else:

            form = forms.CountryForm()
            return render(request, 'search_main.html', {'form': form})

    else:
        form = forms.CountryForm()
        return render(request, 'search_main.html', {'form': form})

@ensure_csrf_cookie
def index(request):
    all_devices = Device.objects.all()
    last_5_searches = Search.objects.filter().order_by('-id')[:5]
    ics_len = Device.objects.filter(category="ics")
    coordinates_search_len = Device.objects.filter(category="coordinates")
    healthcare_len = Device.objects.filter(category="healthcare")
    search_all = Search.objects.all()
    task = request.session.get('task_id')
    ports = Device.objects.values('port').annotate(c=Count('port')).order_by('-c')[:7]
    ports_list = list(ports)

    # Dashboard density (Stage 2): a handful of extra one-line aggregations
    # so the dashboard is useful at 100+ devices instead of just showing the
    # same handful of small charts. All plain ORM, no extra queries beyond
    # what's already here.
    honeypot_count = Device.objects.filter(honeypot_score__gte=HONEYPOT_THRESHOLD).count()
    country_count = Device.objects.exclude(country_code__isnull=True).exclude(country_code='') \
        .values('country_code').distinct().count()
    top_types = list(
        Device.objects.exclude(type='').values('type').annotate(c=Count('type')).order_by('-c')[:8]
    )
    top_orgs = list(
        Device.objects.exclude(org__isnull=True).exclude(org='')
        .values('org').annotate(c=Count('org')).order_by('-c')[:8]
    )
    recent_devices = list(
        Device.objects.order_by('-id')
        .only('id', 'ip', 'type', 'org', 'country_code', 'port', 'honeypot_score', 'search_id')[:10]
    )

    vulns = Device.objects.exclude(vulns__isnull=True).exclude(vulns__exact='')

    vulns_list = []

    for i in vulns:
        vulns_list.append(ast.literal_eval(i.vulns))

    cves = []
    for i in vulns_list:
        for j in i:
            cves.append(j)

    countr_cves = {}
    c = Counter(cves)
    for key, value in c.items():
        countr_cves[key] = value

    sort = sorted(countr_cves.items())[:7]

    countries = {}
    for i in search_all:
        countries[i.country] = "1"

    #make list out of last 5 searches
    for j in last_5_searches:
        try:
            j.country = pycountry.countries.get(alpha_2=j.country).name
            j.ics = ast.literal_eval(j.ics)
        except Exception as e:
            logger.info("index: failed to parse country/ics for search %s: %s", j.id, e)
        try:
            j.coordinates_search = ast.literal_eval(j.coordinates_search)
        except Exception as e:
            logger.info("index: failed to parse coordinates_search for search %s: %s", j.id, e)

    # NOTE: this used to call check_credits() synchronously here, which hits
    # both the Shodan and BinaryEdge APIs on every single dashboard render --
    # slow, and it hangs/fails the whole page if either is offline or
    # unconfigured. The credits tile now loads via the existing `get_credits`
    # AJAX endpoint (index.html JS, fired after page paint), so the page
    # itself never blocks on a remote API call.

    context = {'device': all_devices,
               "search": last_5_searches,
               "ics": ics_len,
               "coordinates": coordinates_search_len,
               "healthcare":healthcare_len,
               "ports": ports_list,
               "countries": countries,
               'vulns': sort,
               "task_id": task,
               "search_len": search_all,
               "honeypot_count": honeypot_count,
               "country_count": country_count,
               "top_types": top_types,
               "top_orgs": top_orgs,
               "recent_devices": recent_devices}
    return render(request, 'index.html', context)


def filter_devices(request):
    """Apply the GET-param device filters shared by the `devices` list view
    and `export_devices`, so the two can never drift apart.

    Supported params (all optional, combined with AND; unknown/empty
    params are ignored):
      - port: exact match on Device.port
      - type: exact match on Device.type (device family)
      - category: exact match on Device.category (ics/healthcare/infra/coordinates)
      - country: match on Device.country_code (case-insensitive)
      - org: substring match (case-insensitive) against Device.org
      - search_id: restrict to a single Search's devices
      - vuln: substring match against the stored vulns (a CVE id)
      - honeypot: truthy (e.g. "1") restricts to devices whose local
        heuristic honeypot_score is at/above HONEYPOT_THRESHOLD.
      - hide_honeypot: truthy -- the inverse of `honeypot`, excludes devices
        whose honeypot_score is at/above HONEYPOT_THRESHOLD.
      - status: exact match on Device.status (new/reviewed/confirmed/
        false_positive, see Device.STATUS_CHOICES).
      - false_positive=0 (or hide_fp, truthy): excludes devices flagged
        suspected_false_positive=True.

    Returns (queryset, filters) where `filters` is an ordered dict of the
    params that were actually applied, suitable both for the "active
    filters" UI and for rebuilding the querystring (e.g. on export links).
    """
    all_devices = Device.objects.all()

    filters = {}

    port = request.GET.get('port')
    if port:
        all_devices = all_devices.filter(port=port)
        filters['port'] = port

    device_type = request.GET.get('type')
    if device_type:
        all_devices = all_devices.filter(type=device_type)
        filters['type'] = device_type

    category = request.GET.get('category')
    if category:
        all_devices = all_devices.filter(category=category)
        filters['category'] = category

    country = request.GET.get('country')
    if country:
        all_devices = all_devices.filter(country_code__iexact=country)
        filters['country'] = country

    org = request.GET.get('org')
    if org:
        all_devices = all_devices.filter(org__icontains=org)
        filters['org'] = org

    search_id = request.GET.get('search_id')
    if search_id:
        all_devices = all_devices.filter(search_id=search_id)
        filters['search_id'] = search_id

    vuln = request.GET.get('vuln')
    if vuln:
        all_devices = all_devices.filter(vulns__icontains=vuln)
        filters['vuln'] = vuln

    honeypot = request.GET.get('honeypot')
    hide_honeypot = request.GET.get('hide_honeypot')
    if honeypot:
        all_devices = all_devices.filter(honeypot_score__gte=HONEYPOT_THRESHOLD)
        filters['honeypot'] = honeypot
    elif hide_honeypot:
        all_devices = all_devices.exclude(honeypot_score__gte=HONEYPOT_THRESHOLD)
        filters['hide_honeypot'] = hide_honeypot

    status = request.GET.get('status')
    if status:
        all_devices = all_devices.filter(status=status)
        filters['status'] = status

    false_positive = request.GET.get('false_positive')
    hide_fp = request.GET.get('hide_fp')
    if hide_fp:
        all_devices = all_devices.exclude(suspected_false_positive=True)
        filters['hide_fp'] = hide_fp
    elif false_positive == '0':
        all_devices = all_devices.exclude(suspected_false_positive=True)
        filters['false_positive'] = false_positive

    return all_devices, filters


def parse_cves(vulns):
    """Safely parse a Device.vulns value (an ast.literal_eval-able string,
    e.g. "['CVE-2020-1111']") into a plain list of CVE id strings, for the
    devices/results tables to render as individual badges. Never raises --
    anything that doesn't parse to a list/tuple/set just yields [].
    """
    if not vulns:
        return []
    try:
        parsed = ast.literal_eval(vulns)
    except Exception:
        return []
    if isinstance(parsed, (list, tuple, set)):
        return [str(v) for v in parsed if v]
    return []


def honeypot_toggle_qs(filters):
    """urlencode() the active filters minus honeypot/hide_honeypot, so
    templates can build the "Only honeypots"/"Hide honeypots"/"All" toggle
    links (each just appends its own honeypot param) without dropping any
    other active filter (port/type/country/search_id/...).
    """
    base = {k: v for k, v in filters.items() if k not in ('honeypot', 'hide_honeypot')}
    return urlencode(base)


def devices(request):
    """List devices, optionally filtered by GET params so infographics
    (ports/type/category/country/vuln charts) and the history/search pages
    can link straight into a filtered device list. See filter_devices() for
    the supported params -- also used, unchanged, by export_devices().
    """

    all_devices, filters = filter_devices(request)

    for i in all_devices:
        try:
            i.indicator = ast.literal_eval(i.indicator)
        except Exception as e:
            logger.info("devices: failed to parse indicator for device %s: %s", i.id, e)
        i.cves = parse_cves(i.vulns)

    context = {
        "devices": all_devices,
        "filters": filters,
        "export_qs": urlencode(filters),
        "honeypot_base_qs": honeypot_toggle_qs(filters),
    }

    return render(request, "devices.html", context=context)


EXPORT_FIELDS = [
    'ip', 'product', 'org', 'port', 'type', 'category', 'country_code',
    'city', 'lat', 'lon', 'vulns', 'honeypot_score', 'status',
    'suspected_false_positive', 'hostnames',
]


def export_devices(request):
    """Stream the SAME filtered device list as `devices()` (via
    filter_devices(), so the two views can't drift) as a CSV or JSON
    download. `format=csv|json` GET param, default csv.
    """
    all_devices, _filters = filter_devices(request)
    export_format = (request.GET.get('format') or 'csv').lower()

    def row_dict(device):
        try:
            vulns = ast.literal_eval(device.vulns) if device.vulns else []
            vulns_str = ';'.join(vulns) if isinstance(vulns, (list, tuple, set)) else str(vulns)
        except Exception:
            vulns_str = device.vulns

        return {
            'ip': device.ip,
            'product': device.product,
            'org': device.org,
            'port': device.port,
            'type': device.type,
            'category': device.category,
            'country_code': device.country_code,
            'city': device.city,
            'lat': device.lat,
            'lon': device.lon,
            'vulns': vulns_str,
            'honeypot_score': device.honeypot_score,
            'status': device.status,
            'suspected_false_positive': device.suspected_false_positive,
            'hostnames': device.hostnames,
        }

    if export_format == 'json':
        data = [row_dict(d) for d in all_devices]
        response = HttpResponse(json.dumps(data, default=str), content_type='application/json')
        response['Content-Disposition'] = 'attachment; filename="devices.json"'
        return response

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="devices.csv"'
    writer = csv.DictWriter(response, fieldnames=EXPORT_FIELDS)
    writer.writeheader()
    for d in all_devices:
        writer.writerow(row_dict(d))
    return response

@ensure_csrf_cookie
def map(request):
    all_devices = Device.objects.all()

    hide_honeypot = request.GET.get('hide_honeypot')
    if hide_honeypot:
        all_devices = all_devices.exclude(honeypot_score__gte=HONEYPOT_THRESHOLD)

    google_maps_key = keys['keys']['google_maps']

    context = {"devices": all_devices, 'google_maps_key': google_maps_key, 'hide_honeypot': hide_honeypot}

    return render(request, "map.html", context=context)

def gallery(request):
    all_devices = Device.objects.filter(screenshot__gt='',screenshot__isnull=False)
    context = {"devices": all_devices}

    return render(request, "gallery.html", context=context)


@ensure_csrf_cookie
def results(request, id):

    all_devices = Device.objects.filter(search_id=id)

    honeypot = request.GET.get('honeypot')
    hide_honeypot = request.GET.get('hide_honeypot')
    if honeypot:
        all_devices = all_devices.filter(honeypot_score__gte=HONEYPOT_THRESHOLD)
    elif hide_honeypot:
        all_devices = all_devices.exclude(honeypot_score__gte=HONEYPOT_THRESHOLD)
    ports = Device.objects.filter(search_id=id).values('port').annotate(c=Count('port')).order_by('-c')[:7]
    city = Device.objects.filter(search_id=id).values('city').annotate(c=Count('city')).order_by('-c')[:7]
    category = Device.objects.filter(search_id=id).values('type').annotate(c=Count('type')).order_by('-c')
    google_maps_key = keys['keys']['google_maps']


    categories_list = list(category)
    ports_list = list(ports)
    cities_list = list(city)

    for i in categories_list:
        i['label'] = i.pop('type')
        i['value'] = i.pop('c')

    vulns = Device.objects.exclude(vulns__isnull=True).exclude(vulns__exact='')

    cves_list = []

    for i in vulns:
        cves_list.append(ast.literal_eval(i.vulns))
    cves = []
    for i in cves_list:
        for j in i:
            cves.append(j)

    cves_counter = {}
    c = Counter(cves)
    for key, value in c.items():
        cves_counter[key] = value

    sort = sorted(cves_counter.items())[:7]

    for i in all_devices:
        try:
            i.indicator = ast.literal_eval(i.indicator)

        except Exception as e:
            logger.info("results: failed to parse indicator for device %s: %s", i.id, e)
        i.cves = parse_cves(i.vulns)


    result_filters = {'search_id': id}
    if honeypot:
        result_filters['honeypot'] = honeypot
    elif hide_honeypot:
        result_filters['hide_honeypot'] = hide_honeypot

    context = {'search': all_devices,
               'ports': ports_list,
               "vulns": sort,
               "category": categories_list,
               "city": cities_list,
               'google_maps_key': google_maps_key,
               'search_id': id,
               'export_qs': urlencode(result_filters),
               'honeypot_base_qs': urlencode({'search_id': id})}

    return render(request, 'results.html', context)


def history(request):
    all_searches = Search.objects.all()

    for i in all_searches:
        try:
            i.coordinates_search = ast.literal_eval(i.coordinates_search)
        except Exception as e:
            logger.info("history: failed to parse coordinates_search for search %s: %s", i.id, e)

        try:
            i.ics = ast.literal_eval(i.ics)
        except Exception as e:
            logger.info("history: failed to parse ics for search %s: %s", i.id, e)

    context = {'history': all_searches}
    return render(request, 'history.html', context)


def update_coordinates(request,id, coordinates):
    if request.method != 'POST':
        return method_not_allowed()
    if is_ajax(request):
        dev = Device.objects.get(id=id)
        splitted_coord = coordinates.split(",")
        dev.lat = splitted_coord[0]
        dev.lon = splitted_coord[1]
        dev.located = True
        dev.save()
        record_audit(request, 'update_coordinates', device=dev, target=coordinates)
        return HttpResponse(json.dumps({'Status': "OK"}), content_type='application/json')
    else:
        return HttpResponse(json.dumps({'Status': "NO OK"}), content_type='application/json', status=400)


def search_estimate(request):
    """AJAX preview of how many devices a search would return, WITHOUT
    running a paid search: uses Shodan's api.count (zero query credits) per
    selected ICS family instead of api.search.

    GET params: `country` (country code, or "XX" for a global search) and one
    or more `ics` values (family keys, or "__all__" for every ICS family).
    Returns JSON: {"counts": {family_key: count, ...}, "total": int}. A
    family whose count() call fails is reported as null and excluded from
    the total, rather than failing the whole estimate.
    """
    if is_ajax(request) and request.method == 'GET':
        country = request.GET.get('country')
        ics_keys = request.GET.getlist('ics')

        if not country or not ics_keys:
            return HttpResponse(json.dumps({'error': 'country and ics are required'}),
                                content_type='application/json', status=400)

        selection = build_family_selection(ics=ics_keys)

        counts = {}
        total = 0
        for key, query, category in selection:
            try:
                count = count_devices(country, query)
            except Exception as e:
                logger.warning("search_estimate: count_devices failed for %s/%s: %s", country, query, e)
                count = None
            counts[key] = count
            if isinstance(count, int):
                total += count

        return HttpResponse(json.dumps({'counts': counts, 'total': total}), content_type='application/json')
    else:
        return HttpResponse(json.dumps({'Status': "NO OK"}), content_type='application/json')


def get_credits(request):
    """AJAX endpoint exposing check_credits() (Shodan query credits +
    BinaryEdge requests remaining) to the search_main pre-search credit-guard
    UI, without making the template call into kamerka.tasks directly.

    Returns JSON: {"shodan_credits": int|null, "binaryedge_credits": int|null}.
    check_credits() returns a plain list (index 0 = shodan, index 1 =
    binaryedge), each entry only present if that API call succeeded.
    """
    if is_ajax(request) and request.method == 'GET':
        credits_list = check_credits()
        shodan_credits = credits_list[0] if len(credits_list) > 0 else None
        binaryedge_credits = credits_list[1] if len(credits_list) > 1 else None
        return HttpResponse(
            json.dumps({'shodan_credits': shodan_credits, 'binaryedge_credits': binaryedge_credits}),
            content_type='application/json',
        )
    else:
        return HttpResponse(json.dumps({'Status': "NO OK"}), content_type='application/json')


@ensure_csrf_cookie
def device(request, id, device_id, ip):
    all_devices = Device.objects.get(search_id=id, id=device_id)
    nearby = DeviceNearby.objects.filter(device_id=all_devices.id)
    shodan = ShodanScan.objects.filter(device_id=all_devices.id)
    google_maps_key = keys['keys']['google_maps']

    try:
        parsed_indicator = ast.literal_eval(all_devices.indicator)
    except Exception:
        parsed_indicator = all_devices.indicator

    if isinstance(parsed_indicator, (list, tuple, set)):
        indicator_list = list(parsed_indicator)
    elif parsed_indicator:
        indicator_list = [parsed_indicator]
    else:
        indicator_list = []

    all_devices.indicator = indicator_list

    # Only keep truthy/non-blank entries so an empty or all-blank indicator
    # list renders as "no indicators" instead of empty bullet noise.
    meaningful_indicators = [i for i in indicator_list if i]

    if all_devices.type in passwds.keys():
        info = passwds[all_devices.type]
    else:
        info = ""

    try:
        honeypot_reasons = json.loads(all_devices.honeypot_reasons) if all_devices.honeypot_reasons else []
    except Exception:
        honeypot_reasons = []

    # Cross-search de-dupe: other Device rows sharing this IP, from any
    # other search, most-recent first (see app_kamerka.sightings). UI
    # wiring for this comes in a later batch; the data is ready here.
    sightings = other_sightings(all_devices)

    context = {'device': all_devices,
               'nearby': nearby,
               "shodan": shodan,
               'google_maps_key': google_maps_key,
               "passwd": info,
               "indicators": meaningful_indicators,
               "banner_warning": looks_like_generic_http_response(all_devices.data),
               "honeypot_reasons": honeypot_reasons,
               "honeypot_threshold": HONEYPOT_THRESHOLD,
               "is_likely_honeypot": all_devices.honeypot_score >= HONEYPOT_THRESHOLD,
               "other_sightings": sightings,
               "sightings_count": sightings.count(),
               "status_choices": Device.STATUS_CHOICES,
               "active_scan_enabled": settings.KAMERKA_ENABLE_ACTIVE_SCAN,
               "exploitation_enabled": settings.KAMERKA_ENABLE_EXPLOITATION}

    return render(request, 'device.html', context)


def nearby(request, id, query):
    if request.method != 'POST':
        return method_not_allowed()
    if is_ajax(request):
        all_devices = Device.objects.filter(id=id)
        device_nearby_task = devices_nearby.delay(lat=all_devices[0].lat, lon=all_devices[0].lon, id=id, query=query)
        record_audit(request, 'nearby', device=all_devices[0] if all_devices else None, target=query)
        return HttpResponse(json.dumps({'task_id': device_nearby_task.id}), content_type='application/json')
    else:
        return HttpResponse(json.dumps({'task_id': None}), content_type='application/json', status=400)


def sources(request):
    return render(request, 'sources.html', {})


def shodan_scan(request, id):
    if request.method != 'POST':
        return method_not_allowed()
    if is_ajax(request):

        shodan_scan2 = ShodanScan.objects.filter(device_id=id)

        if shodan_scan2:
            logger.info("shodan_scan: already in database for device %s", id)
            return HttpResponse(json.dumps({'Error': "Already in database"}), content_type='application/json')

        shodan_scan_task2 = shodan_scan_task.delay(id=id)
        record_audit(request, 'shodan_scan', device=_get_device_or_none(id), target=str(id))
        return HttpResponse(json.dumps({'task_id': shodan_scan_task2.id}), content_type='application/json')
    else:
        return HttpResponse(json.dumps({'task_id': None}), content_type='application/json', status=400)


def get_task_info(request):
    task_id = request.GET.get('task_id', None)
    try:
        if task_id is not None:
            task = AsyncResult(task_id)
            data = {
                'state': task.state,
                'result': task.result,
            }
            return HttpResponse(json.dumps(data), content_type='application/json')
        else:
            return HttpResponse('No job id given.')
    except Exception as e:
        logger.exception("get_task_info failed for task_id=%s: %s", task_id, e)
        return HttpResponse(json.dumps({'Error': str(e)}), content_type='application/json', status=500)


def get_shodan_scan_results(request, id):
    if is_ajax(request) and request.method == 'GET':
        shodan_scan2 = ShodanScan.objects.filter(device_id=id)

        if not shodan_scan2:
            return HttpResponse(json.dumps({'Error': "No records"}), content_type='application/json', status=404)

        response_data = serializers.serialize('json', shodan_scan2)

        return HttpResponse(response_data, content_type="application/json")
    else:
        return HttpResponse(json.dumps({'Error': "Bad request"}), content_type='application/json', status=400)


def get_nearby_devices(request, id):
    if is_ajax(request) and request.method == 'GET':
        nearby_devices = DeviceNearby.objects.filter(device_id=id)

        response_data = serializers.serialize('json', nearby_devices)

        return HttpResponse(response_data, content_type="application/json")
    else:
        return HttpResponse(json.dumps({'Error': "Bad request"}), content_type='application/json', status=400)

def scan_dev(request, id):
    if request.method != 'POST':
        return method_not_allowed()
    if is_ajax(request):
        if not settings.KAMERKA_ENABLE_ACTIVE_SCAN:
            return HttpResponse(
                json.dumps({'Error': "Active scanning is disabled"}),
                content_type='application/json', status=403,
            )
        res = scan(id)
        if res:
            record_audit(request, 'scan', device=_get_device_or_none(id), target=str(id), detail=res)
            return HttpResponse(json.dumps(res), content_type='application/json')
        else:
            record_audit(request, 'scan', device=_get_device_or_none(id), target=str(id), success=False,
                         detail='Connection Error')
            return HttpResponse(json.dumps({'Error': "Connection Error"}), content_type='application/json')
    else:
        return HttpResponse(json.dumps({'Error': "Bad request"}), content_type='application/json', status=400)

def exploit_dev(request, id):
    if request.method != 'POST':
        return method_not_allowed()
    if is_ajax(request):
        if not settings.KAMERKA_ENABLE_EXPLOITATION:
            return HttpResponse(
                json.dumps({'Error': "Exploitation is disabled"}),
                content_type='application/json', status=403,
            )
        res = exploit(id)
        if res:
            record_audit(request, 'exploit', device=_get_device_or_none(id), target=str(id), detail=res)
            return HttpResponse(json.dumps(res), content_type='application/json')
        else:
            record_audit(request, 'exploit', device=_get_device_or_none(id), target=str(id), success=False,
                         detail='Connection Error')
            return HttpResponse(json.dumps({'Error': "Connection Error"}), content_type='application/json')
    else:
        return HttpResponse(json.dumps({'Error': "Bad request"}), content_type='application/json', status=400)

# get_nearby_devices_coordinates used to be a byte-identical copy of
# get_nearby_devices. Both URL names are kept (the coordinates-search UI and
# the ICS/etc UI each hit their own endpoint name), but they now share one
# implementation so there is only one place to fix bugs in.
get_nearby_devices_coordinates = get_nearby_devices

def send_to_field_agent(request, id, notes):
    """Persist a Device's notes locally. Kept under its original name/URL
    since the device page's "Save notes" UI already posts here; it no
    longer exfiltrates anything externally (the old Pastebin publishing
    step has been removed)."""
    if request.method != 'POST':
        return method_not_allowed()
    if is_ajax(request):
        logger.info("send_to_field_agent for device %s", id)

        host = Device.objects.get(id=id)
        host.notes = notes
        host.save()
        record_audit(request, 'notes', device=host, target=str(id))

        return HttpResponse(json.dumps({'Status': "OK"}), content_type='application/json')
    else:
        return HttpResponse(json.dumps({'task_id': None}), content_type='application/json', status=400)


def get_binaryedge_score(request, id):
    if request.method != 'POST':
        return method_not_allowed()
    if is_ajax(request):

        be = BinaryEdgeScore.objects.filter(device_id=id)

        if be:
            logger.info("get_binaryedge_score: already in database for device %s", id)
            return HttpResponse(json.dumps({'Error': "Already in database"}), content_type='application/json')

        be_task = binary_edge_scan.delay(id=id)
        record_audit(request, 'binaryedge', device=_get_device_or_none(id), target=str(id))

        return HttpResponse(json.dumps({'task_id': be_task.id}), content_type='application/json')
    else:
        return HttpResponse(json.dumps({'task_id': None}), content_type='application/json', status=400)


def get_binaryedge_score_results(request, id):
    if is_ajax(request) and request.method == 'GET':
        be = BinaryEdgeScore.objects.filter(device_id=id)

        response_data = serializers.serialize('json', be)

        return HttpResponse(response_data, content_type="application/json")
    else:
        return HttpResponse(json.dumps({'Error': "Bad request"}), content_type='application/json', status=400)


def whois(request, id):
    if request.method != 'POST':
        return method_not_allowed()
    if is_ajax(request):

        whoiss = Whois.objects.filter(device_id=id)

        if whoiss:
            logger.info("whois: already in database for device %s", id)
            return HttpResponse(json.dumps({'Error': "Already in database"}), content_type='application/json')

        wh_task = whoisxml.delay(id=id)
        record_audit(request, 'whois', device=_get_device_or_none(id), target=str(id))

        return HttpResponse(json.dumps({'task_id': wh_task.id}), content_type='application/json')
    else:
        return HttpResponse(json.dumps({'task_id': None}), content_type='application/json', status=400)


def get_honeyscore(request, id):
    """On-demand Shodan HoneyScore check (the 2nd, network-based honeypot
    signal, complementing the automatic local heuristic in honeypot_score).
    Synchronous (not a celery task): Shodan's honeyscore call is a single
    lightweight request, unlike the paginated scan/search calls elsewhere in
    this app. Best-effort: kamerka.tasks.honeyscore() itself never raises,
    it returns None on any failure.
    """
    if request.method != 'POST':
        return method_not_allowed()
    if is_ajax(request):
        device1 = Device.objects.get(id=id)
        result = honeyscore(device1.ip)
        device1.honeyscore = result
        device1.save()
        record_audit(request, 'honeyscore', device=device1, target=device1.ip, detail={'honeyscore': result})
        return HttpResponse(json.dumps({'honeyscore': result}), content_type='application/json')
    else:
        return HttpResponse(json.dumps({'Error': "Bad request"}), content_type='application/json', status=400)


def get_whois(request, id):
    if is_ajax(request) and request.method == 'GET':
        whoiss = Whois.objects.filter(device_id=id)

        response_data = serializers.serialize('json', whoiss)

        return HttpResponse(response_data, content_type="application/json")
    else:
        return HttpResponse(json.dumps({'Error': "Bad request"}), content_type='application/json', status=400)


def set_device_status(request, id):
    """AJAX endpoint to set a Device's manual triage status (see
    Device.STATUS_CHOICES). Requires POST (`status` param) -- this mutates
    state, so it is no longer accepted over GET.
    """
    if request.method != 'POST':
        return method_not_allowed()
    if is_ajax(request):
        new_status = request.POST.get('status')
        valid_statuses = {choice[0] for choice in Device.STATUS_CHOICES}

        if new_status not in valid_statuses:
            return HttpResponse(
                json.dumps({'Error': "Invalid status", 'valid_statuses': sorted(valid_statuses)}),
                content_type='application/json', status=400,
            )

        try:
            device1 = Device.objects.get(id=id)
        except Device.DoesNotExist:
            return HttpResponse(json.dumps({'Error': "No such device"}), content_type='application/json', status=404)

        device1.status = new_status
        device1.save()
        record_audit(request, 'set_status', device=device1, target=str(id), detail={'status': new_status})

        return HttpResponse(json.dumps({'status': device1.status}), content_type='application/json')
    else:
        return HttpResponse(json.dumps({'Error': "Bad request"}), content_type='application/json', status=400)
