"""Command line interface for reconatlas."""

from __future__ import annotations

import atexit
import sys
import time
import webbrowser
from typing import Any, Callable, Sequence

import click

from . import __version__
from .config import Config, build_config
from .http import HttpClient
from .models import Finding, ModuleResult, Report
from .modules import base as base_mod
from .modules import (
    breaches as breaches_mod,
    dorks as dorks_mod,
    dns as dns_mod,
    email as email_mod,
    exif as exif_mod,
    ipinfo as ipinfo_mod,
    rdap as rdap_mod,
    satellite as satellite_mod,
    subdomains as subdomains_mod,
    tlsinfo as tlsinfo_mod,
    username as username_mod,
    wayback as wayback_mod,
    webprobe as webprobe_mod,
)
from .output import (
    ConsoleRenderer,
    export_csv,
    export_html,
    export_json,
    export_jsonl,
)
from .util.net import is_domain, is_email, is_ip, is_username, normalize_url

PASSIVE_NOTE = "Only use this against targets you are authorised to investigate."

#: HTTP sessions opened during this run, closed at exit.
_OPEN_CLIENTS: list[HttpClient] = []


# --------------------------------------------------------------------- options


def common_options(func):
    """Attach the options shared by every command."""
    func = click.option(
        "--json",
        "json_path",
        type=click.Path(dir_okay=False, path_type=str),
        help="Write the full report as JSON to this path.",
    )(func)
    func = click.option(
        "--csv",
        "csv_path",
        type=click.Path(dir_okay=False, path_type=str),
        help="Write every finding as CSV to this path.",
    )(func)
    func = click.option(
        "--jsonl",
        "jsonl_path",
        type=click.Path(dir_okay=False, path_type=str),
        help="Write every finding as newline-delimited JSON.",
    )(func)
    func = click.option(
        "--html",
        "html_path",
        type=click.Path(dir_okay=False, path_type=str),
        help="Write a self-contained HTML report.",
    )(func)
    func = click.option("--no-cache", is_flag=True, help="Bypass the on-disk response cache.")(func)
    func = click.option("--timeout", type=float, default=None, help="Per-request timeout in seconds.")(func)
    func = click.option("--rate-limit", type=float, default=None, help="Minimum seconds between requests.")(func)
    func = click.option("--cache-ttl", type=int, default=None, help="Cache lifetime in seconds.")(func)
    func = click.option("--verbose", "-v", is_flag=True, help="Show progress information.")(func)
    func = click.option("--summary", is_flag=True, help="Print a compact summary table only.")(func)
    func = click.option("--quiet", "-q", is_flag=True, help="Suppress console output entirely.")(func)
    return func


def make_config(**kwargs: Any) -> Config:
    cfg = build_config()
    cfg.with_overrides(
        no_cache=kwargs.get("no_cache"),
        timeout=kwargs.get("timeout"),
        rate_limit=kwargs.get("rate_limit"),
        cache_ttl=kwargs.get("cache_ttl"),
        verbose=kwargs.get("verbose"),
    )
    cfg.quiet = bool(kwargs.get("quiet"))
    return cfg


def make_context(cfg: Config, target: str, target_type: str) -> base_mod.Context:
    """Build a collector context, registering the client for cleanup."""
    http = HttpClient(cfg)
    _OPEN_CLIENTS.append(http)
    return base_mod.Context(config=cfg, http=http, target=target, target_type=target_type)


@atexit.register
def _close_clients() -> None:
    """Close every HTTP session this process opened."""
    for http in _OPEN_CLIENTS:
        http.close()
    _OPEN_CLIENTS.clear()


def emit(
    report: Report,
    opts: dict[str, Any],
    cfg: Config,
    renderer: Callable[[Report], None] | None = None,
) -> None:
    """Render the report and write any requested exports.

    ``renderer`` overrides the generic console output for commands that
    deserve a purpose-built table. Exports are unaffected.
    """
    if opts.get("json_path"):
        path = export_json(report, opts["json_path"])
        if not cfg.quiet:
            click.echo(f"[green]JSON report:[/green] {path}")
    if opts.get("csv_path"):
        path = export_csv(report, opts["csv_path"])
        if not cfg.quiet:
            click.echo(f"[green]CSV findings:[/green] {path}")
    if opts.get("jsonl_path"):
        path = export_jsonl(report, opts["jsonl_path"])
        if not cfg.quiet:
            click.echo(f"[green]JSONL findings:[/green] {path}")
    if opts.get("html_path"):
        path = export_html(report, opts["html_path"])
        if not cfg.quiet:
            click.echo(f"[green]HTML report:[/green] {path}")

    if cfg.quiet:
        return
    console = ConsoleRenderer()
    if opts.get("summary"):
        console.render_summary(report)
    elif renderer is not None:
        renderer(report)
    else:
        console.render(report)


def result_from(name: str, findings: Sequence[Finding], summary: dict[str, Any],
                errors: Sequence[str] = ()) -> ModuleResult:
    result = ModuleResult(name=name, findings=list(findings), summary=dict(summary), errors=list(errors))
    if errors and not findings:
        result.status = "error"
    elif errors:
        result.status = "partial"
    return result


def safe_collect(
    name: str,
    func: Callable[..., tuple[list[Finding], dict[str, Any]]],
    *args: Any,
    **kwargs: Any,
) -> ModuleResult:
    """Run one collector, timing it and turning any failure into an error.

    A single misbehaving data source must never abort the whole report.
    """
    started = time.monotonic()
    try:
        findings, summary = func(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001
        return ModuleResult(
            name=name,
            status="error",
            errors=[f"{type(exc).__name__}: {exc}"],
            duration=time.monotonic() - started,
        )
    result = result_from(name, findings, summary)

    # A collector that had some of its sources fail reports the detail in
    # the summary; surface it so a partial result is not mistaken for a
    # complete one.
    source_errors = summary.get("source_errors")
    if isinstance(source_errors, list) and source_errors:
        result.errors.extend(str(err) for err in source_errors)
        result.status = "partial" if findings else "error"

    # A collector that could not run at all reports it in the summary.
    summary_error = summary.get("error")
    if summary_error:
        result.errors.append(str(summary_error))
        result.status = "partial" if findings else "error"

    result.duration = time.monotonic() - started
    return result


# -------------------------------------------------------------------- commands


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    epilog=PASSIVE_NOTE,
)
@click.version_option(__version__, prog_name="osint")
def cli() -> None:
    """reconatlas - OSINT collection from free, public data sources.

    Every module queries keyless public APIs, so no account or API key is
    needed. Use it only against targets you have permission to investigate.
    """


@cli.command("domain")
@click.argument("domain")
@common_options
@click.option("--subdomain-sources", default="", help="Comma separated subdomain source names.")
@click.option("--no-resolve", is_flag=True, help="Do not resolve discovered subdomains.")
@click.option("--deep", is_flag=True, help="Probe more common paths on the web server.")
def domain_cmd(
    domain: str,
    json_path: str | None,
    csv_path: str | None,
    jsonl_path: str | None,
    html_path: str | None,
    no_cache: bool,
    timeout: float | None,
    rate_limit: float | None,
    cache_ttl: int | None,
    verbose: bool,
    summary: bool,
    quiet: bool,
    subdomain_sources: str,
    no_resolve: bool,
    deep: bool,
) -> None:
    """Run a full investigation against a domain."""
    domain = domain.strip().lower().rstrip(".")
    if not is_domain(domain):
        raise click.BadParameter(f"'{domain}' does not look like a domain name.")

    opts = dict(
        json_path=json_path, csv_path=csv_path, jsonl_path=jsonl_path, html_path=html_path,
        no_cache=no_cache, timeout=timeout, rate_limit=rate_limit, cache_ttl=cache_ttl,
        verbose=verbose, summary=summary, quiet=quiet,
    )
    cfg = make_config(**opts)
    ctx = make_context(cfg, domain, "domain")
    report = Report(target=domain, target_type="domain")

    sources = [s.strip() for s in subdomain_sources.split(",") if s.strip()] or None

    # --- registration
    report.add(safe_collect("registration", rdap_mod.collect_registration, domain, ctx.http))

    # --- DNS
    resolver = dns_mod.DnsResolver(ctx.http)

    def _dns_collector() -> tuple[list[Finding], dict[str, Any]]:
        records = resolver.records(domain)
        return dns_mod.dns_findings(domain, records), dns_mod.summarise(records)

    report.add(safe_collect("dns", _dns_collector))

    # --- subdomains
    report.add(
        safe_collect(
            "subdomains",
            subdomains_mod.collect_subdomains,
            domain,
            ctx.http,
            sources=sources,
            resolve=not no_resolve,
            max_resolve=cfg.max_subdomains,
        )
    )

    # --- web
    report.add(
        safe_collect("web", webprobe_mod.probe_site, f"https://{domain}", ctx.http, deep=deep)
    )

    # --- TLS
    report.add(safe_collect("tls", tlsinfo_mod.collect_tls, domain))

    # --- IP intelligence for the resolved addresses
    ips = [f.value for f in report.by_category("dns") if f.key.startswith("A (")]
    if ips:
        report.add(
            safe_collect("ip", ipinfo_mod.collect_ip, ips[0], ctx.http, probe_ports=True)
        )

    # --- archives
    report.add(safe_collect("wayback", wayback_mod.collect_wayback, domain, ctx.http))

    # --- breaches
    report.add(safe_collect("breaches", breaches_mod.collect_breaches, domain, ctx.http))

    emit(report, opts, cfg)


@cli.command("dns")
@click.argument("domain")
@common_options
def dns_cmd(domain: str, **kwargs: Any) -> None:
    """Show DNS records for a domain."""
    domain = domain.strip().lower().rstrip(".")
    if not is_domain(domain):
        raise click.BadParameter(f"'{domain}' does not look like a domain name.")

    cfg = make_config(**kwargs)
    ctx = make_context(cfg, domain, "domain")
    resolver = dns_mod.DnsResolver(ctx.http)

    def _dns_collector() -> tuple[list[Finding], dict[str, Any]]:
        records = resolver.records(domain)
        return dns_mod.dns_findings(domain, records), dns_mod.summarise(records)

    report = Report(target=domain, target_type="domain")
    report.add(safe_collect("dns", _dns_collector))
    emit(report, kwargs, cfg)


@cli.command("subdomains")
@click.argument("domain")
@common_options
@click.option("--source", "sources", multiple=True, help="Restrict to a source (repeatable).")
@click.option("--no-resolve", is_flag=True, help="Do not resolve discovered subdomains.")
def subdomains_cmd(domain: str, sources: tuple[str, ...], no_resolve: bool, **kwargs: Any) -> None:
    """Enumerate subdomains of a domain."""
    domain = domain.strip().lower().rstrip(".")
    cfg = make_config(**kwargs)
    ctx = make_context(cfg, domain, "domain")
    report = Report(target=domain, target_type="domain")
    report.add(safe_collect("subdomains", subdomains_mod.collect_subdomains, domain, ctx.http,
                             sources=list(sources) or None, resolve=not no_resolve,
                             max_resolve=cfg.max_subdomains))
    emit(report, kwargs, cfg)


@cli.command("ip")
@click.argument("address")
@common_options
@click.option("--no-port-scan", is_flag=True, help="Skip the local TCP port probe.")
def ip_cmd(address: str, no_port_scan: bool, **kwargs: Any) -> None:
    """Investigate an IP address: location, ASN, PTR, ports, co-hosts."""
    address = address.strip()
    if not is_ip(address):
        raise click.BadParameter(f"'{address}' is not a valid IP address.")

    cfg = make_config(**kwargs)
    ctx = make_context(cfg, address, "ip")
    report = Report(target=address, target_type="ip")
    report.add(safe_collect("ip", ipinfo_mod.collect_ip, address, ctx.http,
                             probe_ports=not no_port_scan))
    emit(report, kwargs, cfg)


@cli.command("web")
@click.argument("url")
@common_options
@click.option("--deep", is_flag=True, help="Probe more common paths on the web server.")
def web_cmd(url: str, deep: bool, **kwargs: Any) -> None:
    """Probe a web server: headers, technology, exposed files."""
    cfg = make_config(**kwargs)
    target = normalize_url(url)
    ctx = make_context(cfg, target, "url")
    report = Report(target=target, target_type="url")
    report.add(safe_collect("web", webprobe_mod.probe_site, target, ctx.http, deep=deep))
    emit(report, kwargs, cfg)


@cli.command("tls")
@click.argument("host")
@click.option("--port", default=443, type=int, help="TLS port to connect to.")
@common_options
def tls_cmd(host: str, port: int, **kwargs: Any) -> None:
    """Inspect the TLS certificate served by a host."""
    cfg = make_config(**kwargs)
    report = Report(target=host, target_type="host")
    report.add(safe_collect("tls", tlsinfo_mod.collect_tls, host, port))
    emit(report, kwargs, cfg)


@cli.command("email")
@click.argument("address")
@common_options
def email_cmd(address: str, **kwargs: Any) -> None:
    """Analyse an email address: mail routing, SPF/DMARC, Gravatar."""
    cfg = make_config(**kwargs)
    ctx = make_context(cfg, address, "email")
    report = Report(target=address, target_type="email")
    report.add(safe_collect("email", email_mod.collect_email, address, ctx.http))
    emit(report, kwargs, cfg)


@cli.command("username")
@click.argument("username")
@common_options
@click.option("--platform", "platforms", multiple=True, help="Only check these platforms.")
@click.option("--hits-only", is_flag=True, help="Only show platforms where the account exists.")
def username_cmd(
    username: str, platforms: tuple[str, ...], hits_only: bool, **kwargs: Any
) -> None:
    """Check a username across public platforms."""
    username = username.strip().lstrip("@")
    if not is_username(username):
        raise click.BadParameter(f"'{username}' is not a plausible username.")

    cfg = make_config(**kwargs)
    ctx = make_context(cfg, username, "username")

    selected = username_mod.PLATFORMS
    if platforms:
        wanted = {p.lower() for p in platforms}
        selected = tuple(p for p in username_mod.PLATFORMS if p.name.lower() in wanted)
        if not selected:
            raise click.BadParameter(
                f"Unknown platform. Available: {', '.join(username_mod.platform_names())}"
            )

    result = safe_collect("username", username_mod.check_username, username, ctx.http,
                           platforms=selected, concurrency=cfg.concurrency)
    if hits_only:
        result.findings = [f for f in result.findings if f.value.startswith("http")]
    report = Report(target=username, target_type="username")
    report.add(result)
    emit(report, kwargs, cfg)


@cli.command("exif")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=str))
@common_options
def exif_cmd(path: str, **kwargs: Any) -> None:
    """Extract metadata from an image, PDF or office document."""
    cfg = make_config(**kwargs)
    report = Report(target=path, target_type="file")
    report.add(safe_collect("metadata", exif_mod.collect_metadata, path))
    emit(report, kwargs, cfg)


@cli.command("dorks")
@click.argument("target")
@common_options
@click.option("--no-global", is_flag=True, help="Only produce site-scoped queries.")
@click.option("--open", "open_browser", is_flag=True, help="Open the queries in a browser.")
@click.option("--engine", default="google", help="Search engine to open (google, bing, duckduckgo...).")
def dorks_cmd(target: str, no_global: bool, open_browser: bool, engine: str, **kwargs: Any) -> None:
    """Generate search-engine dorks for a target."""
    cfg = make_config(**kwargs)
    result = safe_collect("dorks", dorks_mod.collect_dorks, target, global_scope=not no_global)
    report = Report(target=target, target_type="target")
    report.add(result)

    if open_browser:
        engine_url = dorks_mod.ENGINES.get(engine.lower())
        if not engine_url:
            raise click.BadParameter(
                f"Unknown engine '{engine}'. Available: {', '.join(dorks_mod.ENGINES)}"
            )
        for finding in result.findings[:8]:
            webbrowser.open(finding.meta.get("search_url", ""))
    emit(report, kwargs, cfg)


@cli.command("breaches")
@click.argument("domain")
@common_options
def breaches_cmd(domain: str, **kwargs: Any) -> None:
    """List known breaches affecting a domain."""
    domain = domain.strip().lower()
    cfg = make_config(**kwargs)
    ctx = make_context(cfg, domain, "domain")
    report = Report(target=domain, target_type="domain")
    report.add(safe_collect("breaches", breaches_mod.collect_breaches, domain, ctx.http))
    emit(report, kwargs, cfg)


@cli.command("wayback")
@click.argument("domain")
@common_options
@click.option("--limit", default=40, type=int, help="Number of snapshots to fetch.")
@click.option("--subdomains", is_flag=True, help="Include archived subdomains.")
def wayback_cmd(domain: str, limit: int, subdomains: bool, **kwargs: Any) -> None:
    """Show archived history for a domain."""
    domain = domain.strip().lower()
    cfg = make_config(**kwargs)
    ctx = make_context(cfg, domain, "domain")
    report = Report(target=domain, target_type="domain")
    report.add(safe_collect("wayback", wayback_mod.collect_wayback, domain, ctx.http,
                             limit=limit, subdomains=subdomains))
    emit(report, kwargs, cfg)


@cli.command("satellite")
@common_options
@click.option(
    "--group",
    type=click.Choice(["active", "military"]),
    default="active",
    show_default=True,
    help="Catalogue to scan: the full public active set, or CelesTrak's curated military group.",
)
@click.option(
    "--class",
    "classes",
    type=click.Choice(satellite_mod.CLASS_ORDER),
    multiple=True,
    help="Only these classes (repeatable).",
)
@click.option("--match", default="", help="Only objects whose name or NORAD id contains this text.")
@click.option("--lat", type=float, default=None, help="Observer latitude, decimal degrees.")
@click.option("--lon", type=float, default=None, help="Observer longitude, decimal degrees.")
@click.option("--place", default="", help="Observer place name, geocoded with OpenStreetMap.")
@click.option("--overhead", is_flag=True, help="Only objects currently above the horizon.")
@click.option("--min-elevation", type=float, default=0.0, help="Minimum elevation in degrees.")
@click.option("--passes", "passes_n", type=int, default=0, help="Also predict the next N passes.")
@click.option("--hours", type=float, default=24.0, show_default=True, help="Pass search window.")
@click.option("--limit", type=int, default=40, show_default=True, help="Maximum objects (0 = all).")
@click.option(
    "--tle-file",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Read TLEs from a local file instead of contacting CelesTrak (no download limit).",
)
@click.option(
    "--geojson",
    "geojson_path",
    type=click.Path(dir_okay=False, path_type=str),
    help="Write current sub-points as GeoJSON for a map.",
)
@click.option(
    "--watch",
    "watch_seconds",
    type=float,
    default=0.0,
    metavar="SECONDS",
    help="Redraw positions live every N seconds until Ctrl-C, reusing the cached catalogue.",
)
@click.option(
    "--viewer",
    is_flag=True,
    help="Open a live map in your browser, served locally (no external tiles or keys).",
)
@click.option(
    "--port",
    type=int,
    default=0,
    help="Port for --viewer (0 picks a free one).",
)
@click.option(
    "--no-browser",
    is_flag=True,
    help="With --viewer, print the URL instead of opening a browser.",
)
def satellite_cmd(
    group: str,
    classes: tuple[str, ...],
    match: str,
    lat: float | None,
    lon: float | None,
    place: str,
    overhead: bool,
    min_elevation: float,
    passes_n: int,
    hours: float,
    limit: int,
    tle_file: str | None,
    geojson_path: str | None,
    watch_seconds: float,
    viewer: bool,
    port: int,
    no_browser: bool,
    **kwargs: Any,
) -> None:
    """Detect military satellites and show where they are right now.

    Scans CelesTrak's public catalogue, flags objects that appear in its
    military group or whose name matches a known military programme, and
    propagates each one with SGP4 to its current sub-satellite point.

    Give an observer position to get look angles, filter to what is
    overhead, or predict the next passes.
    """
    if (overhead or passes_n > 0) and not place and (lat is None or lon is None):
        raise click.UsageError(
            "--overhead and --passes need an observer position: use --lat/--lon or --place."
        )
    if lat is not None and not -90.0 <= lat <= 90.0:
        raise click.BadParameter("--lat must be between -90 and 90.")
    if lon is not None and not -180.0 <= lon <= 180.0:
        raise click.BadParameter("--lon must be between -180 and 180.")

    cfg = make_config(**kwargs)
    http = HttpClient(cfg)
    _OPEN_CLIENTS.append(http)

    observer: satellite_mod.Observer | None = None
    if place:
        resolved = satellite_mod.geocode(http, place)
        if resolved is None:
            raise click.ClickException(f"could not find a place called '{place}'")
        observer = satellite_mod.Observer(
            lat=lat if lat is not None else resolved.lat,
            lon=lon if lon is not None else resolved.lon,
            label=resolved.label,
        )
    elif lat is not None and lon is not None:
        observer = satellite_mod.Observer(lat=lat, lon=lon)

    target = observer.label if observer is not None and observer.label else "military satellites"

    exports = geojson_path or any(
        kwargs.get(key) for key in ("json_path", "csv_path", "jsonl_path", "html_path")
    )

    if viewer:
        if watch_seconds > 0:
            raise click.UsageError("--viewer and --watch cannot be combined.")
        if exports:
            raise click.UsageError("--viewer cannot be combined with export options.")
        from . import viewer as viewer_mod

        catalogue = satellite_mod.load_catalogue(http, group=group, tle_file=tle_file)
        viewer_mod.serve(
            catalogue,
            port=port,
            observer=observer,
            classes=classes,
            match=match,
            overhead=overhead,
            min_elevation=min_elevation,
            open_browser=not no_browser,
        )
        return

    if watch_seconds > 0:
        if exports:
            raise click.UsageError("--watch cannot be combined with export options.")
        satellite_mod.watch(
            http,
            interval=watch_seconds,
            group=group,
            classes=classes,
            match=match,
            observer=observer,
            overhead=overhead,
            min_elevation=min_elevation,
            passes=passes_n,
            hours=hours,
            limit=limit,
            tle_file=tle_file,
        )
        return

    report = Report(target=target, target_type="satellite")
    report.add(
        safe_collect(
            "satellite",
            satellite_mod.collect_satellites,
            http,
            group=group,
            classes=classes,
            match=match,
            observer=observer,
            overhead=overhead,
            min_elevation=min_elevation,
            passes=passes_n,
            hours=hours,
            limit=limit,
            tle_file=tle_file,
        )
    )

    if geojson_path:
        import json as _json

        from pathlib import Path as _Path

        payload = satellite_mod.to_geojson(report.by_category("satellite"))
        path = _Path(geojson_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_json.dumps(payload, indent=2), encoding="utf-8")
        click.echo(f"GeoJSON: {path}")

    emit(report, kwargs, cfg, renderer=satellite_mod.render)


@cli.command("report")
@click.argument("target")
@common_options
@click.option("--no-resolve", is_flag=True, help="Do not resolve discovered subdomains.")
@click.option("--deep", is_flag=True, help="Probe more common paths on the web server.")
def report_cmd(target: str, no_resolve: bool, deep: bool, **kwargs: Any) -> None:
    """Run every applicable module against a target and produce one report.

    The target may be a domain, an IP address, an email address or a username.
    """
    cfg = make_config(**kwargs)
    target = target.strip()

    if is_ip(target):
        ctx = make_context(cfg, target, "ip")
        report = Report(target=target, target_type="ip")
        report.add(safe_collect("ip", ipinfo_mod.collect_ip, target, ctx.http, probe_ports=True))
    elif is_email(target):
        ctx = make_context(cfg, target, "email")
        report = Report(target=target, target_type="email")
        report.add(safe_collect("email", email_mod.collect_email, target, ctx.http))
    elif is_domain(target):
        domain = target.lower().rstrip(".")
        ctx = make_context(cfg, domain, "domain")
        report = Report(target=domain, target_type="domain")

        report.add(safe_collect("registration", rdap_mod.collect_registration, domain, ctx.http))

        resolver = dns_mod.DnsResolver(ctx.http)

        def _dns_collector() -> tuple[list[Finding], dict[str, Any]]:
            records = resolver.records(domain)
            return dns_mod.dns_findings(domain, records), dns_mod.summarise(records)

        report.add(safe_collect("dns", _dns_collector))

        report.add(
            safe_collect(
                "subdomains",
                subdomains_mod.collect_subdomains,
                domain,
                ctx.http,
                resolve=not no_resolve,
                max_resolve=cfg.max_subdomains,
            )
        )

        report.add(
            safe_collect("web", webprobe_mod.probe_site, f"https://{domain}", ctx.http, deep=deep)
        )
        report.add(safe_collect("tls", tlsinfo_mod.collect_tls, domain))
        report.add(safe_collect("wayback", wayback_mod.collect_wayback, domain, ctx.http))
        report.add(safe_collect("breaches", breaches_mod.collect_breaches, domain, ctx.http))
    elif is_username(target):
        username = target.lstrip("@")
        ctx = make_context(cfg, username, "username")
        report = Report(target=username, target_type="username")
        report.add(
            safe_collect(
                "username",
                username_mod.check_username,
                username,
                ctx.http,
                concurrency=cfg.concurrency,
            )
        )
    else:
        raise click.BadParameter(
            f"'{target}' is not recognised as a domain, IP, email address or username."
        )

    emit(report, kwargs, cfg)


@cli.command("platforms")
def platforms_cmd() -> None:
    """List every username platform the toolkit checks."""
    for platform in username_mod.PLATFORMS:
        method = "API" if platform.api else "HTML"
        click.echo(f"{platform.name:<18} {method:<5} {platform.url}")


def main() -> None:
    try:
        cli()
    except KeyboardInterrupt:
        click.echo("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()
