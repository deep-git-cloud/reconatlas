# reconatlas

Recon a domain, IP, email or username from one CLI, and track military satellites. Subdomain enumeration, DNS, RDAP, TLS, breach corpora, EXIF, 40+ username platforms and live orbital positions — all on free, keyless sources.

Every module queries **free, public, keyless** data sources, so there is no account to create, no API key to buy, and nothing to configure before the first run.

```bash
osint domain example.com
```

---

## Contents

- [Why keyless](#why-keyless)
- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Data sources](#data-sources)
- [Output formats](#output-formats)
- [Configuration](#configuration)
- [How the username checker decides](#how-the-username-checker-decides)
- [Military satellite tracking](#military-satellite-tracking)
- [Using reconatlas as a library](#using-reconatlas-as-a-library)
- [Project layout](#project-layout)
- [Tests](#tests)
- [Limitations and ethics](#limitations-and-ethics)
- [License](#license)

---

## Why keyless

Most OSINT tooling expects you to sign up for a paid API — Shodan, Censys, Hunter.io, VirusTotal. reconatlas deliberately avoids that. It talks to RDAP, DNS-over-HTTPS, Certificate Transparency logs, passive DNS, the public breach corpus and public profile APIs instead, all of which are reachable without credentials.

The practical consequences:

- **Nothing to sign up for.** Clone, install, run.
- **No per-query cost.** The only limits are the public APIs' own rate limits.
- **No key to leak.** There is no secret to rotate, and no key sitting in your shell history.
- **Honest failure.** When a source is down, the tool says so rather than quietly returning less.

---

## Install

Requires Python 3.10 or newer.

```bash
git clone https://github.com/deep-git-cloud/reconatlas.git
cd reconatlas
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

That installs the `osint` command (and a `reconatlas` alias). For a development install with the test dependencies:

```bash
pip install -e ".[dev]"
```

### Using it from anywhere

The command only lives inside the virtual environment by default. To make `osint` available in every shell, link the entry point into a directory that is already on your `PATH`:

```bash
ln -sf "$PWD/.venv/bin/osint" ~/.local/bin/osint
```

Use whichever `PATH` directory suits you — `~/.local/bin` is the usual choice, and it does not pollute any other Python environment. The link points at an absolute path, so keep the project folder where it is or re-create the link after moving it.

### Uninstall

```bash
rm ~/.local/bin/osint          # if you created the link
pip uninstall reconatlas       # from the virtual environment
```

---

## Quick start

```bash
# Everything we can find about a domain, in one report
osint domain wikipedia.org

# Just the DNS records
osint dns wikipedia.org

# Where is this IP, who owns it, what is open on it
osint ip 1.1.1.1

# Which mail servers handle this address, and is it protected
osint email someone@gmail.com

# Does this handle exist anywhere, and where
osint username torvalds --hits-only

# What is hiding in this photo
osint exif ./photo.jpg

# Search queries that leak things about a target
osint dorks example.com

# Save everything as machine-readable output
osint domain example.com --json report.json --csv findings.csv --html report.html
```

---

## Commands

| Command | What it does |
|---|---|
| `osint domain <domain>` | Full investigation: registration, DNS, subdomains, web, TLS, IP, archives, breaches |
| `osint dns <domain>` | A, AAAA, MX, NS, TXT, SOA, CNAME, CAA, SRV, DNSKEY and DS records |
| `osint subdomains <domain>` | Passive subdomain discovery from five sources, with optional resolution |
| `osint ip <address>` | Geolocation, ASN and netblock, reverse DNS, open ports, co-hosted domains |
| `osint web <url>` | Response headers, technology fingerprint, security headers, exposed files |
| `osint tls <host>` | Certificate subject, issuer, SANs, validity window, expiry warning |
| `osint email <address>` | MX, SPF, DMARC, DKIM, BIMI, disposable check, Gravatar profile |
| `osint username <name>` | Profile existence across 40+ platforms |
| `osint exif <file>` | EXIF, GPS, XMP from images; document properties from PDF and OOXML |
| `osint dorks <target>` | Search-engine queries for a target, ready to paste or launch |
| `osint breaches <domain>` | Every known breach affecting a domain, from the public corpus |
| `osint wayback <domain>` | Archived history, first and last snapshot, HTTP status spread |
| `osint satellite` | Detects military and classified satellites and shows where they are now |
| `osint report <target>` | Runs whichever modules apply to a domain, IP, email or username |
| `osint platforms` | Lists every username platform that is checked |

### Options shared by all commands

| Option | Effect |
|---|---|
| `--json PATH` | Write the full report as JSON |
| `--csv PATH` | Write every finding as a flat CSV row |
| `--jsonl PATH` | Write every finding as newline-delimited JSON |
| `--html PATH` | Write a self-contained HTML report |
| `--summary` | Print a compact per-module table instead of the full report |
| `--quiet` | Suppress console output (useful with `--json` in a pipeline) |
| `--no-cache` | Ignore the on-disk response cache |
| `--timeout SECONDS` | Per-request timeout (default 15) |
| `--rate-limit SECONDS` | Minimum gap between requests to the same host (default 0.7) |
| `--cache-ttl SECONDS` | How long cached responses stay valid (default 3600) |
| `--verbose` | Show progress information on stderr |

---

## Data sources

Everything below is public and works without credentials.

| Area | Sources |
|---|---|
| Registration | `rdap.org`, IANA RDAP bootstrap registry |
| DNS | Google DNS-over-HTTPS, local resolver as fallback |
| Subdomains | Cert Spotter, crt.sh, HackerTarget, subdomain.center, AlienVault OTX |
| IP data | ipwho.is, ipinfo.io, RIPEstat, Shodan InternetDB, local TCP probe |
| Web | Direct requests, `robots.txt`, `sitemap.xml`, `security.txt`, common exposed paths |
| TLS | Live TLS handshake against the host |
| Email | DNS MX/TXT lookups, Gravatar |
| Breaches | The public Have I Been Pwned breach corpus |
| Archives | Internet Archive CDX API |
| Usernames | Public profile pages and public JSON APIs (GitHub, GitLab, PyPI, Keybase, …) |
| Satellites | CelesTrak GP catalogue (TLE), SGP4 propagation, OpenStreetMap Nominatim for place names |

Public APIs have rate limits and occasionally go down. Every collector degrades gracefully: a source that fails is reported as an error on that module, the module is marked `partial`, and the remaining sources still contribute results.

---

## Output formats

**Console** — grouped panels, one per module, coloured by severity
(`+` good, `!` warning, `x` risk).

**JSON** — the complete report, including per-module summaries and errors:

```json
{
  "target": "example.com",
  "target_type": "domain",
  "started_at": "2026-03-14T09:21:44Z",
  "modules": {
    "dns": {
      "name": "dns",
      "status": "ok",
      "duration": 0.42,
      "summary": { "A": 2, "MX": 1 },
      "errors": [],
      "findings": [
        {
          "category": "dns",
          "key": "A (IPv4 address)",
          "value": "104.20.23.154",
          "source": "dns.google (DoH)",
          "severity": "info",
          "note": "",
          "meta": {}
        }
      ]
    }
  }
}
```

**CSV** — one row per finding, with `target`, `module`, `category`, `key`,
`value`, `source`, `severity`, `note` and `meta` columns.

**JSONL** — one JSON object per finding, for streaming into other tools.

**HTML** — a single self-contained page, no external assets.

---

## Configuration

Settings resolve in this order, later wins:

1. Built-in defaults
2. `~/.config/reconatlas/config.toml`
3. `RECONATLAS_*` environment variables
4. Command line flags

```toml
# ~/.config/reconatlas/config.toml
user_agent = "reconatlas/0.1 (+https://example.org; research)"
timeout = 20
rate_limit = 1.0
cache_ttl = 7200
```

```bash
export RECONATLAS_TIMEOUT=30
export RECONATLAS_NO_CACHE=1
```

Responses are cached under `~/.cache/reconatlas` so repeated runs are fast and the public APIs see less traffic. Failed responses expire after 60 seconds, so a recovered API is picked up immediately rather than after a full cache lifetime.

---

## How the username checker decides

Most platforms answer a request for a handle that does not exist with HTTP 200 and a generic landing page, so a status code alone proves nothing. reconatlas compares the target profile against a **control page** for a randomly generated handle that cannot exist:

- Different HTTP status than the control → the account exists
- The target page is substantially larger than the control → it exists
- The control page is larger, or the two match → it does not exist
- Anything else → reported as *inconclusive*

Platforms with a public JSON API (GitHub, GitLab, PyPI, Keybase, …) are checked directly and reported with high confidence. HTML-only platforms are reported with medium confidence and the reason is included in the note, so you can judge each result yourself.

---

## Military satellite tracking

`osint satellite` scans the public CelesTrak catalogue, flags the objects that are military or state-operated, and propagates each one with SGP4 to its current sub-satellite point.

```bash
osint satellite                        # full public catalogue, every match
osint satellite --group military       # only CelesTrak's curated military group
osint satellite --class recon --class sigint
osint satellite --match YAOGAN
```

Give it an observer position and it adds look angles, filters to what is actually above your horizon, and predicts the next passes:

```bash
osint satellite --place "London" --overhead
osint satellite --lat 51.5 --lon -0.1 --passes 3 --hours 12
osint satellite --place "London" --overhead --geojson sats.geojson
```

```text
military satellites  8 shown
catalog=15,923, matched=420, classes: comms=1,navigation=5,recon=1, observer=London, England

┏━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━┳━━━━━━┓
┃Class      ┃ Object               ┃ Sub-point        ┃       Alt ┃  El ┃ Orbit┃
┡━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━╇━━━━━━┩
│comms      │ TJS-13  #62188       │ 46.67°N   1.66°W │ 24,642 km │ 84° │ MEO  │
│recon      │ YAOGAN-9 01A  #36413 │ 51.86°N   2.07°W │  1,114 km │ 82° │ LEO  │
│navigation │ NAVSTAR 55 (USA 178) │ 54.75°N  10.15°W │ 20,515 km │ 81° │ MEO  │
└───────────┴──────────────────────┴──────────────────┴───────────┴─────┴──────┘
```

*(trimmed — positions change constantly.)*

### How detection works

Two public signals, nothing else:

1. **CelesTrak's curated military group.** Small and explicit, and the only place the catalogue itself labels an object military.
2. **Programme names.** A checked table of known programmes and designations — `KH-11`, `Lacrosse`/`Onyx`, `Mentor`/`Orion`, `SBIRS`, `DSP`, `AEHF`, `Milstar`, `WGS`, `MUOS`, `Yaogan`, `GLONASS`, `Persona`, `Bars-M`, `Lotos`, `Tundra`/`EKS`, `SAR-Lupe`, `Helios`, `CSO`, `IGS`, `Ofeq`, `RISAT`, `USA nnn`, `NROL-nn` and others.

Every result carries a confidence:

| Confidence | Meaning |
|---|---|
| `confirmed` | In the curated military group, or an unambiguous programme name |
| `likely` | Name matches a known programme pattern |
| `possible` | Weaker match, worth checking yourself |

Nothing is inferred from radio, imagery or behaviour. The tool does not *detect* a satellite in the signals sense — it classifies a public catalogue and computes where those objects are. "Military" is a judgement based on naming, so the confidence is always shown next to the result.

### Caveats

- Positions are only as good as the TLE epoch. A fresh TLE puts a LEO object within a few kilometres; a week-old one does not. The epoch and its age are in the JSON output.
- CelesTrak refreshes every two hours and refuses repeat downloads of the same group from one address. reconatlas caches the catalogue for six hours and reuses a stale copy rather than failing. If there is no cached copy, it says when the next refresh is allowed rather than just erroring. Use `--no-cache` to force a refresh once the window has passed.
- Pass predictions sample every 20 seconds, so rise and set times are accurate to about that. Peak elevation is refined further.
- GPS, GLONASS and BeiDou are reported as `navigation` because they are military-operated, but they are dual-use. Filter them out with `--class` if you only want reconnaissance and warning systems.
- This is public orbital data. It tells you where a catalogued object is, not what it is looking at.

---

## Using reconatlas as a library

```python
from reconatlas.config import build_config
from reconatlas.http import HttpClient
from reconatlas.modules.subdomains import collect_subdomains

cfg = build_config()
http = HttpClient(cfg)

findings, summary = collect_subdomains("example.com", http)
for finding in findings:
    print(finding.source, finding.key, finding.value)
```

Collectors can also be run through the `Collector` base class, which never raises:

```python
from reconatlas.modules.base import Collector, Context
from reconatlas.modules.dns import DnsResolver

class MyCollector(Collector):
    name = "my-collector"

    def collect(self, ctx: Context):
        ...
        return ctx

result = MyCollector().run(ctx)
print(result.status, len(result.findings), result.errors)
```

---

## Project layout

```
src/reconatlas/
  cli.py            Click commands
  config.py         Settings resolution
  http.py           Cached, rate-limited, retrying HTTP client
  models.py         Finding / ModuleResult / Report
  output.py         Console rendering and the JSON, CSV, JSONL and HTML writers
  modules/
    base.py         Collector base class and shared context
    dns.py          DNS-over-HTTPS resolver
    rdap.py         Domain registration
    subdomains.py   Passive subdomain discovery
    ipinfo.py       IP intelligence
    webprobe.py     Web server fingerprinting
    tlsinfo.py      TLS certificate inspection
    email.py        Email address analysis
    username.py     Username enumeration
    exif.py         File metadata extraction
    dorks.py        Search query generation
    breaches.py     Public breach corpus
    wayback.py      Internet Archive history
    satellite.py    Military satellite detection and SGP4 propagation
  util/             Network and text helpers
tests/              Offline test suite
```

---

## Tests

```bash
pytest
```

The suite runs entirely offline — no network calls — and covers the parsers, the model, the exporters and the CLI.

---

## Limitations and ethics

- Geolocation is derived from IP allocation records and is approximate. It
  is not the location of a device or a person.
- Password hashes are never collected and no password is ever tested.
  The breach module lists breaches that are already public knowledge.
- Username and subdomain results include false positives by nature. The
  confidence level and the reason are reported for every result so you
  can judge them.
- Satellite positions come from public orbital elements and are
  approximate. Military classification is a naming heuristic, not an
  identification; check the reported confidence before relying on it.
- Only use this against systems you own or have explicit written
  permission to investigate. Collection against third parties may breach
  the law in your jurisdiction, and it is unfair to the operators whose
  public APIs you are calling.
- The tool rate-limits itself and caches aggressively, but you are still
  the operator of the requests. Respect the terms of the services you
  query.

---

## License

MIT — see [LICENSE](LICENSE).
