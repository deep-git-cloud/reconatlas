# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-20

Initial release.

### Added

- **`domain`** — full investigation of a domain: RDAP registration, DNS
  records, passive subdomain discovery, web server fingerprinting, TLS
  certificate inspection, IP intelligence, archive history and breach
  corpus matching.
- **`dns`** — A, AAAA, MX, NS, TXT, SOA, CNAME, CAA, SRV, DNSKEY and DS
  records over DNS-over-HTTPS, with a local resolver fallback.
- **`subdomains`** — passive discovery from Cert Spotter, crt.sh,
  HackerTarget, subdomain.center and AlienVault OTX, with optional
  resolution of the results.
- **`ip`** — geolocation, ASN and netblock ownership, reverse DNS, open
  port probing and co-hosted domains.
- **`web`** — response headers, technology fingerprinting, security
  header audit and probing for publicly exposed files.
- **`tls`** — certificate subject, issuer, subject alternative names,
  validity window and expiry warnings.
- **`email`** — mail exchangers, SPF, DMARC, DKIM and BIMI policy
  analysis, disposable address detection and Gravatar profile lookup.
- **`username`** — profile existence checks across more than 40
  platforms, using public JSON APIs where available and differential
  page comparison otherwise.
- **`exif`** — EXIF, GPS and XMP extraction from images, plus document
  properties from PDF and OOXML files. Runs entirely offline.
- **`dorks`** — curated search-engine queries for a target, with an
  option to launch them in a browser.
- **`breaches`** — every known breach affecting a domain, from the
  public Have I Been Pwned breach corpus.
- **`wayback`** — archived history from the Internet Archive CDX API,
  including true first and most recent capture dates.
- **`report`** — runs whichever modules apply to a domain, IP address,
  email address or username and produces a single report.
- **Exporters** — JSON, CSV, newline-delimited JSON and self-contained
  HTML output.
- **Caching, rate limiting and retries** for every network request, with
  short-lived caching of failures so recovered APIs are picked up at once.
- **CLI commands** `osint` and `reconatlas`.

[Unreleased]: https://github.com/deep-git-cloud/reconatlas/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/deep-git-cloud/reconatlas/releases/tag/v0.1.0
