import json
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

import urllib.parse
import urllib.request
import xml.etree.ElementTree as et

from app_kamerka import exploits

from app_kamerka.models import Device, DeviceNearby, Search, ShodanScan, BinaryEdgeScore, \
    Whois, Bosch

healthcare_queries = {"zoll": "http.favicon.hash:-236942626",
                      'dicom': "dicom",
                      "perioperative": "HoF Perioperative",
                      "wall_of_analytics": "title:'Wall of Analytics'",
                      "viztek_exa": "X-Super-Powered-By: VIZTEK EXA",
                      "medweb": "html:'DBA Medweb. All rights reserved.'",
                      "intuitim": "http.favicon.hash:159662640",
                      "medcon_archiving_system": "http.favicon.hash:-897903496",
                      "orthanc_explorer": "title:'Orthanc Explorer'",
                      "Marco Pacs": "title:'Marco pacs'",
                      "osirix": "title:OsiriX",
                      "clari_pacs": "title:ClariPACS",
                      "siste_lab": "http.html:SisteLAB",
                      "opalweb": "html:opalweb",
                      "neuropro": "title:'EEG Laboratory'",
                      "tmw_document_imaging": "title:'TMW Document Imaging'",
                      "erez": "title:'eRez Imaging'",
                      "gluco_care": "html:'GlucoCare igc'",
                      "glucose_guide": "title:'glucose guide'",
                      "grandmed_glucose": "title:'Grandmed Glucose'",
                      "philips_digital_pathology": "title:'Philips Digital Pathology'",
                      "tricore_pathology": "title:'TriCore Pathology'",
                      "appsmart_ophthalmology": "title:'Appsmart Ophthalmology'",
                      "chs_ophthalmology": "title:'CHS Ophthalmology'",
                      "ram_soft": "html:powerreader",
                      "xnat": "http.favicon.hash:-230640598",
                      "iris_emr": "title:'Iris EMR'",
                      "eclinicalworks_emr": "title:'Web EMR Login Page'",
                      "open_emr": "http.favicon.hash:1971268439",
                      "oscar_emr": "title:'OSCAR EMR'",
                      "wm_emr": "http.favicon.hash:1617804812",
                      "doctors_partner_emr": "title:'DoctorsPartner'",
                      "mckesson_radiology": "title:'McKesson Radiology'",
                      "kodak_carestream": "title:'Carestream PACS'",
                      "meded": "title:meded",
                      "centricity_radiology": "http.favicon.hash:-458315012",
                      "openeyes": "http.favicon.hash:-885931907",
                      "orthanc": "orthanc",
                      "horos": "http.favicon.hash:398467600",
                      "open_mrs": "title:openmrs",
                      "mirth_connect": "http.favicon.hash:1502215759",
                      "acuity_logic": "title:AcuityLogic",
                      "optical_coherence_tomography": "title:'OCT Webview'",
                      "philips_intellispace": "title:INTELLISPACE",
                      "vitrea_intelligence": "title:'Vitrea intelligence'",
                      "phenom_electron_microscope": "title:'Phenom-World'",
                      "meddream_dicom_viewer": "html:Softneta",
                      "merge_pacs": "http.favicon.hash:-74870968",
                      "synapse_3d": "http.favicon.hash:394706326",
                      "navify": "title:navify",
                      "telemis_tmp": "http.favicon.hash:220883165",
                      "brainlab": "title:'Brainlab Origin Server'",
                      "nexus360": "http.favicon.hash:125825464",
                      "brain_scope": "title:BrainScope",
                      "omero_microscopy": "http.favicon.hash:2140687598",
                      "meditech": "Meditech",
                      "cynetics": "cynetics",
                      "promed": "Promed",
                      "carestream": "Carestream",
                      "carestream_web": "title:Carestream",
                      "vet_rocket": "http.html:'Vet Rocket'",
                      "planmeca": "Planmeca",
                      "vet_view": "http.favicon.hash:1758472204",
                      "lumed": "http.html:'LUMED'",
                      "infinitt": "http.favicon.hash:-255936262",
                      "labtech": "labtech",
                      "progetti": "http.html:'Progetti S.r.l.'",
                      "qt_medical": "http.html:'QT Medical'",
                      "aspel": "ASPEL",
                      "huvitz_optometric": "http.html:'Huvitz'",
                      "optovue": "Optovue",
                      "optos_advance": "http.title:'OptosAdvance'",
                      "asthma_monitoring_adamm": "http.title:'HCO Telemedicine'",
                      "pregnabit": "http.html:'Pregnabit'",
                      "prime_clinical_systems": "http.html:'Prime Clinical Systems'",
                      "omni_explorer": "http.title:OmniExplorer",
                      "avizia": "http.html:'Avizia'",
                      "operamed": "Operamed",
                      "early_sense": "http.favicon.hash:-639764351",
                      "tunstall": "http.html:'Tunstall'",
                      "clini_net": "http.html:'CliniNet®'",
                      "intelesens": "title:'zensoronline)) - online monitoring'",
                      "kb_port": "http.html:'KbPort'",
                      "nursecall_message_service": "http.title:'N.M.S. - Nursecall Message Service'",
                      "image_information_systems": "http.html:'IMAGE Information Systems'",
                      "agilent_technologies": "Agilent Technologies port:5025",
                      "praxis_portal2": "http.html:'Medigration'",
                      "xero_viewer": "http.title:'XERO Viewer'"}

ics_queries = {"niagara": "port:1911,4911 product:Niagara",
               'bacnet': '"Instance ID:" "Object Name:"',
               'modbus': "Unit ID: 0",
               'siemens': 'Original Siemens Equipment Basic Firmware:',
               'dnp3': "port:20000 source address",
               "ethernetip": '"Product name:" "Vendor ID:"',
               "gestrip": 'port:18245,18246 product:"general electric"',
               'hart': "port:5094 hart-ip",
               'pcworx': "port:1962 PLC",
               "mitsubishi": "port:5006,5007 product:mitsubishi",
               "omron": "port:9600 response code",
               "redlion": 'port:789 product:"Red Lion Controls"',
               'codesys': 'product:"3S-Smart Software Solutions"',
               "iec": "port:2404 asdu address",
               'proconos': "port:20547 PLC",

               "plantvisor": "Server: CarelDataServer",
               "iologik": "iologik",
               "moxa": "Moxa",
               "akcp": "Server: AKCP Embedded Web Server",
               "spidercontrol": "powered by SpiderControl TM",
               "tank": "port:10001 tank",
               "iq3": "Server: IQ3",
               "is2": "IS2 Web Server",
               "vtscada": "Server: VTScada",
               'zworld': "Z-World Rabbit 200 OK",
               "nordex": "html:nordex",
               "sailor": 'title:Sailor title:VSAT',
               'nmea': "$GPGGA",

               "axc": "PLC Type: AXC",
               "modicon": "modicon",
               "xp277": "HMI, XP277",
               "vxworks": "vxworks",
               "eig": "EIG Embedded Web Server",
               "digi": "TransPort WR21",
               "windweb": "server: WindWeb",
               "moxahttp": "MoxaHttp",
               "lantronix": "lantronix",
               "entelitouch": "Server: DELTA enteliTOUCH",
               "energyict_rtu": "EnergyICT RTU",
               "crestron": "crestron",
               "saphir": 'Server: "Microsoft-WinCE" "Content-Length: 12581"',
               "ipc@chip": "IPC@CHIP",
               "addup": "addUPI",
               "anybus": '"anybus-s"',
               "windriver": "WindRiver-WebServer",
               "wago": "wago",
               "niagara_audit": "niagara_audit",
               "niagara_web_server": "Niagara Web Server",
               "trendnet": "trendnet",
               "stulz_klimatechnik": "Stulz GmbH Klimatechnik",
               "somfy": "title:Somfy",
               "scalance": "scalance",
               "simatic": "simatic",
               "simatic_s7": "Portal0000",
               "schneider_electric": "Schneider Electric",
               "power_measurement": "Power Measurement Ltd",
               "power_logic": "title:PowerLogic",
               "telemecanique_bxm": "TELEMECANIQUE BMX",
               "schneider_web": "Schneider-WEB",
               "fujitsu_serverview": "serverview",
               "eiportal": "eiPortal",
               "ilon": "i.LON",
               "webvisu": "Webvisu",
               "total_access": 'ta gen3 port:2000',
               "vantage_infusion": "http.html:'InFusion Controller'",
               "sensoteq": "title:'sensoteq'",
               "sicon-8": "sicon-8",
               "automation_direct_hmi": "Server: EA-HTTP/1.0",
               "flotrac": "FloTrac",
               "innotech_bms": "http.title:'Innotech BMS'",
               "skylog": "http.title:skylog",
               "miele@home": "title:Miele@home",
               "alphacom": "http.title:Alphacom",
               "simplex_grinnell": "http.html:SimplexGrinnell title:login",
               "bosch_security": "http.html:'Bosch Security'",

               "other_hmi": "html:hmiBody",
               "fronius": "title:fronius",
               "webview": "http.favicon.hash:207964650",
               "Siemens Sm@rtClient": "title:'Siemens Sm@rtClient'",
               "WAGO": "title:'wago ethernet'",
               "sensatronics": "html:sensatronics",
               "extron": "Extron Electronics",
               "mikrotik_streetlighs": "mikrotik streetlight",
               "kesseltronics": "Kesseltronics",
               "unitronics": "title:'Unitronics PLC'",
               "atvise": "Server: atvise",
               "clearSCADA": "ClearSCADA",
               "youless": "title:YouLess",
               "DLILPC": "DLILPC",
               "intelliSlot": "title:IntelliSlot",
               "temperature_monitor": "title:'Temperature Monitor' !title:avtech",
               "CirCarLife": "CirCarLife -ASUSTeK",
               "web_scada": "title:'web scada'",
               "kaco": "kaco",
               "indect_parkway": "title:indect",
               "intuitive_Controller": "http.favicon.hash:1434282111",
               "intuitive_controller_2": "http.favicon.hash:-1011909571",
               "homeLYnk": "homeLYnk",
               "APC": "Location: home.htm Content-Length: 0 WebServer",
               "netio": "title:netio",
               "asi_controls": "title:'ASI Controls'",
               "myscada": "title:myscada",
               "iB-COM": "title:iB-COM",
               "building_operation_webstation": "title:'building operation'",
               "ftp_scada": "scada login",
               "apc_ftp": "APC FTP server",
               "network_management_card": "Network Management Card",
               "wemo_insight": "Belkin WeMo",
               "connect_ups": "title:ConnectUPS",
               "upshttpd": "Server: upshttpd",
               "poweragent": "PowerAgent",
               "CS121": "title:'CS121 SNMP/Web Adapter'",
               "ab_ethernet": "cspv4",

               "climatix": "Siemens Building Technologies Climatix",
               "bas_scada": "BAS SCADA Service",
               "watt_router": "SOLAR controls product server",
               "doors": '"HID VertX" port:4070',
               "saferoads": "Saferoads VMS",
               "xzeres": 'title:"XZERES Wind"',
               "doorbird": "html:DoorBird",

               "jeedom": 'title:"Jeedom"',
               "pwrctrl": '"NET-PwrCtrl"',
               "heatmiser_thermostat": 'title:"Heatmiser Wifi Thermostat"',
               "xpanel": "title:xpanel",
               "c4_max": "[1m[35mWelcome on console",
               "universal_devices": "ucos",
               "dasdec": "dasdec",
               "brightsign": 'title:"BrightSign&reg;"',
               "leica": "title:leica title:interface",
               "hughesnet": "html:hughesnet",
               "skyline": "'server: skyline'",
               "beward_door": "'DS06A(P) SIP Door Station'",
               "wallbox": "title:wallbox",
               "acadia": "acadia",
               "walchem": "html:walchem",
               "gnss": "'NTRIP' 'SOURCETABLE'",
               "traccar": "title:traccar",
               "trimble": 'html:"trimble Navigation"',
               "spacelynk": "title:spaceLYnk",
               }

coordinates_queries = {"videoiq": 'title:"VideoIQ Camera Login"',
                       "hikvision":'product:"Hikvision IP Camera"',
                       "webcam": "device:webcam",
                       "webcamxp": "webcamxp",
                       "vivotek": "vivotek",
                       "netwave": 'product:"Netwave IP camera http config"',
                       "techwin": "techwin",
                       "lutron": 'html:<h1>LUTRON</h1>',
                       "mobotix": "mobotix",
                       "iqinvision": "iqinvision",
                       "grandstream": 'ssl:"Grandstream" "Set-Cookie: TRACKID"',
                       "amcrest": 'html:"@WebVersion@" html:amcrest',
                       "contec": '"content/smarthome.php"',
                       'printer': "device:printer",
                       'mqtt': 'product:mqtt',
                       'rtsp': "port:'554'",
                       "ipcamera": "IPCamera_Logo",
                       "yawcam": "yawcam",
                       "blueiris": "http.favicon.hash:-520888198",
                       'ubnt': "UBNT Streaming Server",
                       "go1984": "go1984",
                       "dlink": "Server: Camera Web Server",
                       "avtech": "linux upnp avtech",
                       "adh": "ADH-web",
                       "axis": 'http.title:"axis" http.html:live',
                       "rdp": "has_screenshot:true port:3389",
                       "vnc": "has_screenthos:true port:5901",
                       "screenshot": "has_screenshot:true !port:3389 !port:3388 !port:5900",
                       "bbvs": "Server: BBVS",
                       "baudisch": "http.favicon.hash:746882768",
                       "loxone_intercom": "title:'Loxone Intercom Video'",

                       "idss": "Intelligent Digital Security System",
                       "webiopi": 'webiopi 200 ok',
                       "iobroker": "ioBroker.admin",
                       "comelit": "html:comelit",

                       "niagara": "port:1911,4911 product:Niagara",
                       'bacnet': '"Instance ID:" "Object Name:"',
                       'modbus': "Unit ID: 0",
                       'siemens': 'Original Siemens Equipment Basic Firmware:',
                       'dnp3': "port:20000 source address",
                       "ethernetip": '"Product name:" "Vendor ID:"',
                       "gestrip": 'port:18245,18246 product:"general electric"',
                       'hart': "port:5094 hart-ip",
                       'pcworx': "port:1962 PLC",
                       "mitsubishi": "port:5006,5007 product:mitsubishi",
                       "omron": "port:9600 response code",
                       "redlion": 'port:789 product:"Red Lion Controls"',
                       'codesys': "port:2455 operating system",
                       "iec": "port:2404 asdu address",
                       'proconos': "port:20547 PLC",

                       "plantvisor": "Server: CarelDataServer",
                       "iologik": "iologik",
                       "moxa": "Moxa",
                       "akcp": "Server: AKCP Embedded Web Server",
                       "spidercontrol": "powered by SpiderControl TM",
                       "tank": "port:10001 tank",
                       "iq3": "Server: IQ3",
                       "is2": "IS2 Web Server",
                       "vtscada": "Server: VTScada",
                       'zworld': "Z-World Rabbit",
                       "nordex": "html:nordex",

                       "axc": "PLC Type: AXC",
                       "modicon": "modicon",
                       "xp277": "HMI, XP277",
                       "vxworks": "vxworks",
                       "eig": "EIG Embedded Web Server",
                       "digi": "TransPort WR21",
                       "windweb": "server: WindWeb",
                       "moxahttp": "MoxaHttp",
                       "lantronix": "lantronix",
                       "entelitouch": "Server: DELTA enteliTOUCH",
                       "energyict_rtu": "EnergyICT RTU",
                       "crestron": "crestron",
                       "wince": 'Server: "Microsoft-WinCE"',
                       "ipc@chip": "IPC@CHIP",
                       "addup": "addUPI",
                       "anybus": '"anybus-s"',
                       "windriver": "WindRiver-WebServer",
                       "wago": "wago",
                       "niagara_audit": "niagara_audit",
                       "niagara_web_server": "Niagara Web Server",
                       "trendnet": "trendnet",
                       "stulz_klimatechnik": "Stulz GmbH Klimatechnik",
                       "somfy": "title:Somfy",
                       "scalance": "scalance",
                       "simatic": "simatic",
                       "simatic_s7": "Portal0000",
                       "schneider_electric": "Schneider Electric",
                       "power_measurement": "Power Measurement Ltd",
                       "power_logic": "title:PowerLogic",
                       "telemecanique_bxm": "TELEMECANIQUE BMX",
                       "schneider_web": "Schneider-WEB",
                       "fujitsu_serverview": "serverview",
                       "eiportal": "eiPortal",
                       "ilon": "i.LON",
                       "Webvisu": "Webvisu",
                       "total_access": 'ta gen3 port:2000',
                       "vantage_infusion": "http.html:'InFusion Controller'",
                       "sensoteq": "title:'sensoteq'",
                       "sicon-8": "sicon-8",
                       "automation_direct_hmi": "Server: EA-HTTP/1.0",
                       "flotrac": "FloTrac",
                       "innotech_bms": "http.title:'Innotech BMS'",
                       "skylog": "http.title:skylog",
                       "miele@home": "title:Miele@home",
                       "alphacom": "http.title:Alphacom",
                       "simplex_grinnell": "http.html:SimplexGrinnell title:login",
                       "bosch_security": "http.html:'Bosch Security'",

                       "fronius": "title:fronius",
                       "webview": "http.favicon.hash:207964650",
                       "siemens_Sm@rtClient": "title:'Siemens Sm@rtClient'",
                       "WAGO": "title:'wago ethernet'",
                       "sensatronics": "html:sensatronics",
                       "extron": "Extron Electronics",
                       "mikrotik_streetlighs": "mikrotik streetlight",
                       "kesseltronics": "Kesseltronics",
                       "unitronics": "title:'Unitronics PLC'",
                       "atvise": "Server: atvise",
                       "clearSCADA": "ClearSCADA",
                       "youless": "title:YouLess",
                       "DLILPC": "DLILPC",
                       "intelliSlot": "title:IntelliSlot",
                       "temperature_monitor": "title:'Temperature Monitor' !title:avtech",
                       "CirCarLife": "CirCarLife",
                       "web_scada": "title:'web scada'",
                       "kaco": "kaco",
                       "indect_parkway": "title:indect",
                       "intuitive_Controller": "http.favicon.hash:1434282111",
                       "intuitive_controller_2": "http.favicon.hash:-1011909571",
                       "homeLYnk": "homeLYnk",
                       "APC": "Location: home.htm Content-Length: 0 WebServer",
                       "netio": "title:netio",
                       "asi_controls": "title:'ASI Controls'",
                       "myscada": "title:myscada",
                       "iB-COM": "title:iB-COM",
                       "building_operation_webstation": "title:'building operation'",
                       "ftp_scada": "scada login",

                       "apc_ftp": "APC FTP server",
                       "network_management_card": "Network Management Card",
                       "wemo_insight": "Belkin WeMo",
                       "connect_ups": "title:ConnectUPS",
                       "upshttpd": "Server: upshttpd",
                       "poweragent": "PowerAgent",
                       "CS121": "title:'CS121 SNMP/Web Adapter'",
                       "ab_ethernet": "cspv4",

                       "climatix": "Siemens Building Technologies Climatix",
                       "bas_scada": "BAS SCADA Service",
                       "watt_router": "SOLAR controls product server",
                       "doors": '"HID VertX" port:4070',
                       "saferoads": "Saferoads VMS",
                       "xzeres": 'title:"XZERES Wind"',
                       "doorbird": "html:DoorBird",

                       "jeedom": 'title:"Jeedom"',
                       "pwrctrl": "NET-PwrCtrl",
                       "heatmiser_thermostat": 'title:"Heatmiser Wifi Thermostat"',
                       "xpanel": "title:xpanel",
                       "c4_max": "[1m[35mWelcome on console",
                       "universal_devices": "ucos",
                       "dasdec": "dasdec",
                       "brightsign": 'title:"BrightSign&reg;"',
                       "leica": "title:leica title:interface",
                       "hughesnet": "html:hughesnet",
                       "skyline": "server: skyline",
                       "beward_door": "DS06A(P) SIP Door Station",
                       "wallbox": "http.title:wallbox",
                       "acadia": "acadia",
                       "walchem": "html:walchem",
                       "GNSS": "NTRIP" "SOURCETABLE",
                       "traccar": "title:traccar",
                       "trimble": 'html:"trimble Navigation"',
                       "spacelynk": "title:spaceLYnk",
                       }

attackers_infra_queries = {"cobaltstrike": 'product:"Cobalt Strike Beacon"',
                           "msf": 'ssl:MetasploitSelfSignedCA',
                           # NOTE: this query uses smart/curly quotes (”) around "Covenant" and
                           # "Blazor". Shodan's query syntax only understands straight quotes ("...")
                           # for exact-phrase matching, so as written this query is not doing an exact
                           # phrase match the way the other quoted queries in this file do. Left as-is
                           # per the request to only fix if trivial to avoid changing match behavior
                           # for a query in active use without being able to verify results.
                           "covenant": 'ssl:”Covenant” http.component:”Blazor”',
                           "mythic": 'ssl:"Mythic" port:7443',
                           "bruteratel": "http.html_hash:-1957161625",
                           }

# Sentinel value used by the search UI/forms to mean "every family in this
# category", e.g. selecting it in the ICS multiselect expands to every key of
# ics_queries. Handled by expand_families()/build_family_selection() below.
ALL_FAMILIES = "__all__"

# Category name -> the dict of family-key -> Shodan query string it draws from.
# Coordinates searches are intentionally not part of this mapping: they remain
# a separate flow (see shodan_search) and are not combined with a country
# search in a single Search row.
_CATEGORY_QUERY_DICTS = {
    "healthcare": healthcare_queries,
    "ics": ics_queries,
    "infra": attackers_infra_queries,
}


def resolve_family(key, category_hint=None):
    """Look up a family key and return (query, category), or None if unknown.

    If category_hint is given ('healthcare' / 'ics' / 'infra'), only that
    category's dict is checked (this disambiguates keys that happen to exist
    in more than one dict). Otherwise every known category is checked.
    """
    if category_hint is not None:
        d = _CATEGORY_QUERY_DICTS.get(category_hint)
        if d and key in d:
            return d[key], category_hint
        return None

    for category, d in _CATEGORY_QUERY_DICTS.items():
        if key in d:
            return d[key], category
    return None


def expand_families(keys, category):
    """Expand any ALL_FAMILIES sentinel in `keys` into every key of that
    category's query dict. Other keys are passed through unchanged. Order is
    preserved and duplicates are not removed here (build_family_selection
    de-duplicates the final result).
    """
    d = _CATEGORY_QUERY_DICTS.get(category, {})
    expanded = []
    for k in keys or []:
        if k == ALL_FAMILIES:
            expanded.extend(d.keys())
        else:
            expanded.append(k)
    return expanded


def build_family_selection(ics=None, healthcare=None, infra=None):
    """Combine per-category family selections (each possibly containing the
    ALL_FAMILIES sentinel) into a single, de-duplicated, ordered list of
    (key, query, category) tuples ready to be searched.

    - Expands "__all__" into every key of its category.
    - Drops unknown keys.
    - De-duplicates so the same (category, query) is only searched once, even
      if it was selected more than once (directly and/or via "__all__").

    This is a pure function (no I/O, no Celery/Shodan) so it can be unit
    tested directly.
    """
    selection = []
    seen = set()
    for category, keys in (("ics", ics), ("healthcare", healthcare), ("infra", infra)):
        for key in expand_families(keys, category):
            resolved = resolve_family(key, category_hint=category)
            if resolved is None:
                continue
            query, resolved_category = resolved
            dedup_key = (resolved_category, query)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            selection.append((key, query, resolved_category))
    return selection


# --- Opt-in port-grouping optimization (query-credit saver) ---------------
#
# Curated allowlist of ICS families that are identified by a protocol-specific
# port. Every port below belongs to exactly one family in this map, so a
# returned Shodan match's `port` unambiguously identifies which family it
# belongs to. This lets several of these families be searched together as one
# combined `port:a,b,c,...` query instead of one `api.search` call per family,
# cutting query credits from N down to 1 for the families involved.
#
# This is deliberately a short, hand-picked subset of ics_queries: the ports
# here are specific enough to their protocol that dropping the per-family
# product/string sub-filter (e.g. "product:Niagara") adds little noise. Noisy
# shared ports used by other ICS families (e.g. tank=10001, total_access=2000)
# are intentionally left out, since collapsing those would over-include
# unrelated devices that merely share the port.
GROUPABLE_PORT_FAMILIES = {
    "niagara": [1911, 4911],
    "dnp3": [20000],
    "hart": [5094],
    "pcworx": [1962],
    "iec": [2404],
    "proconos": [20547],
    "omron": [9600],
    "redlion": [789],
    "mitsubishi": [5006, 5007],
    "gestrip": [18245, 18246],
    "doors": [4070],
}

# Reverse lookup: port -> family key, derived from GROUPABLE_PORT_FAMILIES.
# Safe because every port above belongs to exactly one family.
_PORT_TO_FAMILY = {
    port: family for family, ports in GROUPABLE_PORT_FAMILIES.items() for port in ports
}


def partition_groupable(selection):
    """Split a build_family_selection() result into (groupable, rest).

    `groupable` holds the (key, query, category) tuples whose category is
    "ics" and whose key is in GROUPABLE_PORT_FAMILIES (candidates for the
    combined port search). `rest` holds everything else (healthcare, infra,
    and any ICS family not in the curated allowlist), unchanged and in the
    same relative order as in `selection`.

    Pure function, no I/O, so it is unit-testable on its own.
    """
    groupable = []
    rest = []
    for key, query, category in selection:
        if category == "ics" and key in GROUPABLE_PORT_FAMILIES:
            groupable.append((key, query, category))
        else:
            rest.append((key, query, category))
    return groupable, rest


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
        print(e)


keys = get_keys()


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
    except:
        fail = 1
        print('fail1')

    if fail == 1:
        try:
            results = api.search("geo:" + lat + "," + lon + ",15 " + query)
        except Exception as e:
            print(e)

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
        print(e)


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
                print(e)
            c += 1

        for key, query, category in rest:
            try:
                result += c
                shodan_search_worker(country=country, fk=fk, query=query, search_type=key,
                                     category=category, all_results=all_results,
                                     max_pages=max_pages, query_cache=query_cache)
                progress_recorder.set_progress(c + 1, total=total)
            except Exception as e:
                print(e)
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
                except:
                    pass
    return result


def check_credits():
    keys_list = []
    try:
        SHODAN_API_KEY = keys['keys']['shodan']

        api = Shodan(SHODAN_API_KEY)
        a = api.info()
        keys_list.append(a['query_credits'])
    except Exception as e:
        print(e)

    try:
        be_key = keys['keys']['binaryedge']
        headers = {"X-Key": be_key}
        req = requests.get("https://api.binaryedge.io/v2/user/subscription", headers=headers)
        req_json = json.loads(req.content)
        keys_list.append(req_json['requests_left'])
    except Exception as e:
        print(e)

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
        vulns = ""

    if result['location']['city'] is not None:
        city = result['location']['city']

    hostnames = ""
    try:
        if 'hostnames' in result:
            hostnames = result['hostnames'][0]
    except Exception:
        pass

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
    print(query)

    cache_key = (query, country, coordinates)
    if query_cache is not None and cache_key in query_cache:
        print("Reusing cached results for duplicate query: " + query)
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
                print('Shodan search failed (attempt %d/%d) for query %r: %s' %
                     (attempt, SHODAN_MAX_ATTEMPTS, query, e))
                results = None
                if attempt < SHODAN_MAX_ATTEMPTS:
                    time.sleep(min(2 ** attempt, SHODAN_BACKOFF_CAP_SECONDS))

        if results is None:
            print("Giving up on query after %d attempts: %s" % (SHODAN_MAX_ATTEMPTS, query))
            break

        try:
            total = results['total']

            if total == 0:
                print("no results")
                break
        except Exception as e:
            print(e)
            break

        pages = math.ceil(total / 100) + 1
        # Note: don't fold max_pages into `pages` here — the `page > max_pages`
        # guard at the top of the loop already caps the number of pages fetched,
        # and min()'ing it in interacts badly with the +1 sentinel above.
        print("Pages: " + str(pages))

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
    print(a['location']['latitude'])
    print(a['location']['longitude'])
    for ports in host_arg.services:
        if ports.state == 'open':
            ports_list.append(ports.port)
        else:
            ports_list.append("None")

    ports_string = ', '.join(str(e) for e in ports_list)
    print(ports_string)
    device = Device(search=search, ip=host_arg.address, product="", org="",
                    data="", port=ports_string, type="NMAP", city="NMAP",
                    lat=a['location']['latitude'], lon=a['location']['longitude'],
                    country_code=a['country']['iso_code'], query="NMAP SCAN", category="NMAP",
                    vulns="", indicator="", hostnames=hostname, screenshot="")
    device.save()


def validate_nmap(file):
    NmapParser.parse_fromfile(os.getcwd() + file)


def validate_maxmind():
    maxminddb.open_database('GeoLite2-City.mmdb')


@shared_task(bind=True)
def nmap_scan(self, file, fk):
    progress_recorder = ProgressRecorder(self)
    result = 0
    print(os.getcwd() + file)
    search = Search.objects.get(id=fk)
    max_reader = maxminddb.open_database('GeoLite2-City.mmdb')
    nmap_report = NmapParser.parse_fromfile(os.getcwd() + file)
    total = len(nmap_report.hosts)
    for c, i in enumerate(nmap_report.hosts):
        result += c
        nmap_host_worker(host_arg=i, max_reader=max_reader, search=search)
        progress_recorder.set_progress(c + 1, total=total)
    return result


def paste_login(username, password, key):
    login_url = "https://pastebin.com/api/api_login.php"
    login_payload = {"api_dev_key": key, "api_user_name": username, "api_user_password": password}

    login = requests.post(login_url, data=login_payload)
    user_key = login.text
    return user_key


def retrieve_pastes(key, user_key):
    url = "http://pastebin.com/api/api_post.php"
    paste_dict = {}

    values_list = {'api_option': 'list',
                   'api_dev_key': key,
                   'api_user_key': user_key}

    data = urllib.parse.urlencode(values_list)
    data = data.encode('utf-8')  # data should be bytes
    req = urllib.request.Request(url, data)
    with urllib.request.urlopen(req) as response:
        the_page = response.read()

    key_v = ""
    title = ""

    root = et.fromstring("<root>" + str(the_page) + "</root>")
    for paste_root in root:
        for paste_element in paste_root:
            key = paste_element.tag.split("_", 1)[-1]
            if key == "key":
                key_v = paste_element.text
            if key == "title":
                title = paste_element.text

        paste_dict[title] = key_v
    return paste_dict


def delete_paste(key, user_key, paste_code):
    url = "http://pastebin.com/api/api_post.php"

    values_list = {'api_option': 'delete',
                   'api_dev_key': key,
                   'api_user_key': user_key,
                   "api_paste_key": paste_code}

    data = urllib.parse.urlencode(values_list)
    data = data.encode('utf-8')  # data should be bytes
    req = urllib.request.Request(url, data)
    urllib.request.urlopen(req)


def create_paste(key, user_key, filename, text):
    url = "http://pastebin.com/api/api_post.php"

    values = {'api_option': 'paste',
              'api_dev_key': key,
              'api_paste_code': text,
              'api_paste_private': '2',
              'api_paste_name': filename,
              'api_user_key': user_key}

    data = urllib.parse.urlencode(values)
    data = data.encode('utf-8')  # data should be bytes
    req = urllib.request.Request(url, data)
    with urllib.request.urlopen(req) as response:
        the_page = response.read()


@shared_task(bind=False)
def send_to_field_agent_task(id, notes):
    cve = ""
    indicator = ""

    af = Device.objects.get(id=id)
    ports = af.port
    try:
        af_details = ShodanScan.objects.get(device_id=id)
        ports = af_details.ports[1:][:-1]
        if af_details.vulns:
            cve = af_details.vulns[1:][:-1]
        if af.indicator:
            indicator = af.indicator[2:][:-2]
    except:
        print("Not scanned")
        pass

    user_key = paste_login(keys['keys']['pastebin_user'], keys['keys']['pastebin_password'],
                           keys['keys']['pastebin_dev_key'])

    pastes = retrieve_pastes(keys['keys']['pastebin_dev_key'], user_key=user_key)

    ip = af.ip
    lat = af.lat
    lon = af.lon
    org = af.org
    type = af.type

    notes = af.notes

    merge_string = "ꓘ;" + lat + ";" + lon + ";" + ip + ";" + ports + ";" + org + ";" + type + ";" + cve + ";" + indicator + ";" + notes

    print("\\xea\\x93\\x98amerka_" + af.ip)
    if "\\xea\\x93\\x98amerka_" + af.ip in pastes.keys():
        delete_paste(keys['keys']['pastebin_dev_key'], user_key, pastes["\\xea\\x93\\x98amerka_" + af.ip])
        create_paste(keys['keys']['pastebin_dev_key'], user_key, "ꓘamerka_" + af.ip, merge_string)
    else:
        create_paste(keys['keys']['pastebin_dev_key'], user_key, "ꓘamerka_" + af.ip, merge_string)


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
        print(total)
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
        print(results['ports'])

        return {'current': total, 'total': total, 'percent': 100}

    except Exception as e:
        print(e.args)


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


@shared_task(bind=False)
def scan(id):
    return_dict = {}
    device1 = Device.objects.get(id=id)
    ip = device1.ip
    port = device1.port
    type = device1.type

    if type in ics_scan.keys():
        nm = NmapProcess(ip, options="-p " + str(port) + " " + ics_scan[type])
        nm.run_background()

        while nm.is_running():
            print("Nmap Scan running: ETC: {0} DONE: {1}%".format(nm.etc,
                                                                  nm.progress))
            sleep(2)

        u = xmltodict.parse(nm.stdout)
        print(u['nmaprun'])

        try:
            for i in u['nmaprun']['host']['ports']['port']['script']:
                print(i)

                if i == "@output":
                    return_dict["ID"] = u['nmaprun']['host']['ports']['port']['script']["@id"]
                    return_dict["Output"] = u['nmaprun']['host']['ports']['port']['script']["@output"]

            device1.scan = return_dict
            device1.exploited_scanned = True
            device1.save()
            return return_dict


        except Exception as e:
            print(e)
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
            print("Nmap Scan running: ETC: {0} DONE: {1}%".format(nm.etc,
                                                                  nm.progress))
            sleep(2)

        u = xmltodict.parse(nm.stdout)

        try:
            return_dict["State"] = u['nmaprun']['host']['ports']['port']['state']['@state']
            return_dict["Reason"] = u['nmaprun']['host']['ports']['port']['state']['@reason']
            device1.scan = return_dict
            device1.exploited_scanned = True
            device1.save()
            return return_dict
        except:
            pass


@shared_task(bind=False)
def exploit(id):
    device1 = Device.objects.get(id=id)
    print(device1.type)
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

    req = requests.get(end)

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
        except:
            pass

        try:
            if req_json['WhoisRecord']['subRecords'][0]['customField1Name'] == "netRange":
                netrange = req_json['WhoisRecord']['subRecords'][0]['customField1Value']
            if req_json['WhoisRecord']['subRecords'][0]['customField2Name'] == "netRange":
                netrange = req_json['WhoisRecord']['subRecords'][0]['customField2Value']
        except:
            pass

        try:
            org = req_json['WhoisRecord']['subRecords'][0]['registrant']['organization']
            if 'city' in req_json['WhoisRecord']['subRecords'][0]['registrant']:
                city = req_json['WhoisRecord']['subRecords'][0]['registrant']['city']

            if 'email' in req_json['WhoisRecord']['subRecords'][0]['registrant']:
                email = req_json['WhoisRecord']['subRecords'][0]['registrant']['email']
        except:
            pass

        wh = Whois(device=device1, org=org,
                   street=street,
                   city=city,
                   admin_org=admin_org,
                   admin_email=admin_email,
                   admin_phone=admin_phone, netrange=netrange, name=name, email=email)

        wh.save()
