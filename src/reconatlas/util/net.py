"""Shared helpers for network-shaped values."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse, urlunparse

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{2,64}$")

#: Known disposable / throwaway email domains used by the email collector.
DISPOSABLE_DOMAINS = {
    "10minutemail.com", "10minutemail.net", "20minutemail.com", "33mail.com",
    "guerrillamail.com", "guerrillamail.net", "guerrillamail.org",
    "mailinator.com", "maildrop.cc", "mailnesia.com", "yopmail.com",
    "tempmail.com", "temp-mail.org", "throwawaymail.com", "trashmail.com",
    "getnada.com", "sharklasers.com", "grr.la", "dispostable.com",
    "fakeinbox.com", "mailcatch.com", "mytemp.email", "burnermail.io",
    "moakt.com", "mohmal.com", "emailondeck.com", "spamgourmet.com",
    "inboxbear.com", "tmpmail.org", "discard.email", "linshiyouxiang.net",
    "mail-temporaire.fr", "jetable.org", "nowmymail.com", "mail-temp.com",
    "minuteinbox.com", "dropmail.me", "cuvox.de", "e4ward.com",
}


def is_ip(value: str) -> bool:
    """True when *value* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


def is_domain(value: str) -> bool:
    """True when *value* looks like a registrable hostname."""
    return bool(DOMAIN_RE.match(value.strip().lower().rstrip(".")))


def is_email(value: str) -> bool:
    return bool(EMAIL_RE.match(value.strip()))


def is_username(value: str) -> bool:
    return bool(USERNAME_RE.match(value.strip()))


def registrable_domain(host: str) -> str:
    """Best-effort "registrable" part of a hostname.

    Handles the common two-label public suffixes (``co.uk``) as well as
    everything else with a naive last-two-labels rule.
    """
    host = host.strip().lower().rstrip(".")
    if is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    two_label_suffixes = {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "com.br", "com.cn", "com.mx", "co.in", "co.jp",
        "com.sg", "co.za", "com.tr", "com.tw", "com.hk", "com.ar",
    }
    if ".".join(labels[-2:]) in two_label_suffixes and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def host_of(url: str) -> str:
    """Extract the hostname from a URL (falls back to the raw input)."""
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    return (parsed.hostname or url).lower()


def normalize_url(url: str, scheme: str = "https") -> str:
    """Normalise a user-supplied URL into a canonical absolute form."""
    url = url.strip()
    if not url:
        return url
    if "://" not in url:
        url = f"{scheme}://{url}"
    parsed = urlparse(url)
    if not parsed.netloc:
        return url
    path = parsed.path or "/"
    return urlunparse(
        (parsed.scheme or scheme, parsed.netloc, path, parsed.params, parsed.query, "")
    )


def base_domain(url: str) -> str:
    """The host of *url* reduced to its registrable domain."""
    return registrable_domain(host_of(url))


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
    )
