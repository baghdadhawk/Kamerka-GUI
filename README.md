# ꓘamerka GUI

## Internet of Things / Industrial Control Systems reconnaissance tool

<p align="center"><img src="https://www.offensiveosint.io/content/images/2020/07/OffensiveOsint-logo-RGB-2.png" alt="logo" width="200"/></p>

### Powered by Shodan — supported by BinaryEdge & WhoisXMLAPI

Kamerka GUI discovers Internet-facing ICS, medical and IoT devices, enriches
them with passive OSINT, and plots them on a map so an analyst can locate the
physical facility behind an exposed device and report it to the appropriate
CERT.

> This tool is for authorized security research, defensive reconnaissance and
> responsible disclosure. Active scanning and exploitation touch real
> third-party devices and are **disabled by default** — see
> [Active scanning & exploitation](#active-scanning--exploitation).

---

## What it does

1. **Search** for Internet-facing Industrial Control Systems, medical and IoT
   devices by country or by coordinates. Searches can target a single device
   family or a whole curated **category** of families in one run.
2. **Enrich** each device passively from Shodan, BinaryEdge and WhoisXMLAPI, or
   (opt-in) actively by scanning the target directly.
3. **Geolocate** — indicators parsed from device responses, combined with
   Google Maps and Street View, help pinpoint a device to a specific facility.
4. **Triage** — flag suspected false positives, score devices against a local
   honeypot heuristic, and record analyst notes per device.
5. **Report** critical-infrastructure exposure to your local CERT.

## Features

- Coverage of 100+ ICS / IoT device families, grouped into selectable categories
- Passive enrichment from Shodan, BinaryEdge and WhoisXMLAPI
- Local **honeypot scoring** heuristic to help surface deception hosts
- **Triage workflow**: per-device status, suspected-false-positive flag and notes
- **Export** filtered device sets
- Interactive Google Maps + Street View; indicators parsed from responses aid geolocation
- Gallery of every gathered screenshot; per-search statistics
- NMAP XML import as an input source
- Optional, opt-in active scanning and a small set of device-specific exploit PoCs

> The interface is self-hosted end to end (jQuery, Bootstrap and fonts are
> bundled locally); the only third-party runtime dependency in the browser is
> Google Maps.

---

## Requirements

- Python 3.10+
- [Redis](https://redis.io/) (Celery broker & result backend)
- A **paid Shodan** account (required)
- BinaryEdge, WhoisXMLAPI API keys (optional, for extra enrichment)
- A Google Maps API key (for the map / Street View views)

Python dependencies are pinned in [`requirements.txt`](requirements.txt) and
include Django 5.2 LTS, Celery 5.6, redis 8.1 and the Shodan client.

## Installation

```bash
git clone https://github.com/baghdadhawk/Kamerka-GUI/
cd Kamerka-GUI

python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt
```

### API keys

Copy the template and fill in your keys — `keys.json` is git-ignored and must
never be committed:

```bash
cp keys.json.example keys.json
$EDITOR keys.json
```

```json
{
  "keys": {
    "shodan": "SHODAN_KEY",
    "binaryedge": "BINARYEDGE_KEY",
    "google_maps": "GOOGLE_MAPS_KEY",
    "whoisxmlapi": "WHOISXMLAPI_KEY"
  }
}
```

By default keys are read from `keys.json` in the project root; set
`KAMERKA_KEYS_FILE=/path/to/keys.json` to load them from elsewhere.

### Configuration (environment variables)

The application is configured from the environment — nothing sensitive is
hardcoded.

| Variable | Default | Purpose |
| --- | --- | --- |
| `DJANGO_SECRET_KEY` | *(random per start)* | Stable secret key. If unset, a random key is generated at startup and sessions won't survive restarts. **Set this in production.** |
| `DJANGO_DEBUG` | `0` (off) | Set `1` for local development. When off, secure-cookie / nosniff / clickjacking hardening is enabled. |
| `DJANGO_ALLOWED_HOSTS` | `localhost,127.0.0.1` | Comma-separated allowed hosts. |
| `KAMERKA_KEYS_FILE` | `./keys.json` | Path to the API-keys file. |
| `KAMERKA_ENABLE_ACTIVE_SCAN` | `0` (off) | Opt in to active Nmap scanning of targets. |
| `KAMERKA_ENABLE_EXPLOITATION` | `0` (off) | Opt in to the device-specific exploit PoCs. |

### Database & first user

Authentication is required for **all** views, so create at least one user:

```bash
export DJANGO_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(50))')"
python manage.py migrate
python manage.py createsuperuser
```

## Running

Kamerka needs three processes: Redis, a Celery worker, and the Django server.

```bash
# 1) Redis (broker + result backend)
redis-server

# 2) Celery worker — default queue (searches, enrichment)
celery -A kamerka worker --loglevel=info

# 3) Django development server
python manage.py runserver
```

Then open <http://localhost:8000/> and log in.

### Active-operations worker (optional)

Active scanning and exploitation tasks are pinned to a dedicated `active`
Celery queue so they can be run by a separate worker on network-isolated
infrastructure. On Windows or when running the Nmap-based tasks, use the solo
pool:

```bash
celery -A kamerka worker -Q active --pool=solo --loglevel=info
```

Leave this worker unstarted (and the feature flags off) to run passive-only.

---

## Access control (RBAC)

Every mutating action is capability-gated. Assign a user to one of the
following groups via **Django admin → Users → Groups**; permissions are
cumulative. A superuser holds all capabilities implicitly.

| Group | Capabilities |
| --- | --- |
| **Viewer** | view data |
| **Analyst** | view + run searches / enrichment |
| **Active Scanner** | Analyst + active Nmap scan |
| **Exploit Operator** | Active Scanner + run exploit PoCs |
| **Administrator** | all of the above + administer |

In addition to the role, an active operation against a target is only allowed
if that target's IP is covered by a **scope authorization** (`ScanAuthorization`
in the admin), which is checked fail-closed. Every attempt — allowed, denied by
capability, denied by scope, or refused because the feature flag is off — is
written to the **audit log** (`AuditLog` in the admin).

## Active scanning & exploitation

These reach out to, and in some cases (e.g. the Hikvision PoC) mutate, real
third-party devices. They are gated by **three** independent controls, all of
which must be satisfied:

1. `KAMERKA_ENABLE_ACTIVE_SCAN` / `KAMERKA_ENABLE_EXPLOITATION` set in the
   environment, **and**
2. the user holds the `active_scan` / `exploit` capability, **and**
3. the target IP is within an authorized scope.

Only run these against systems you are explicitly authorized to test.

---

## Development

```bash
python manage.py test                 # full test suite
python manage.py check                # system checks
python manage.py makemigrations --check --dry-run
```

## Articles

- https://www.offensiveosint.io/hack-the-planet-with-amerka-gui-ultimate-internet-of-things-industrial-control-systems-reconnaissance-tool/
- https://www.offensiveosint.io/offensive-osint-s01e03-intelligence-gathering-on-critical-infrastructure-in-southeast-asia/
- https://www.zdnet.com/article/kamerka-osint-tool-shows-your-countrys-internet-connected-critical-infrastructure/
- https://us-cert.cisa.gov/ncas/alerts/aa20-205a

## Screens

| | |
| --- | --- |
| Search | ![](screens/search1.png) |
| Dashboard | ![](screens/dashboard.png) |
| Gallery | ![](screens/gallery.png) |
| Map | ![](screens/map.png) |
| Statistics | ![](screens/stats.png) |
