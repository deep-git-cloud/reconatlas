"""Runtime configuration for reconatlas.

Configuration is resolved in this order (later wins):
  1. Built-in defaults
  2. Config file  (~/.config/reconatlas/config.toml)
  3. Environment variables (RECONATLAS_*)
  4. Command line flags
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_USER_AGENT = (
    "reconatlas/0.1 (+https://github.com/deep-git-cloud/reconatlas; public-data research)"
)

#: Hostnames that are contacted for a full "domain" investigation.
DEFAULT_DOMAIN_SOURCES = (
    "rdap",
    "dns",
    "subdomains",
    "web",
    "tls",
    "ip",
    "wayback",
    "breaches",
    "email",
)


@dataclass
class Config:
    """Global knobs shared by every module."""

    user_agent: str = DEFAULT_USER_AGENT
    timeout: float = 15.0
    connect_timeout: float = 6.0
    retries: int = 2
    #: Minimum seconds between two requests to the same host.
    rate_limit: float = 0.7
    #: Concurrent requests per host.
    concurrency: int = 6
    cache_dir: Path = field(default_factory=lambda: Path.home() / ".cache" / "reconatlas")
    cache_ttl: int = 3600
    no_cache: bool = False
    verbose: bool = False
    #: Cap on how many subdomains to actively resolve.
    max_subdomains: int = 60
    #: Set when the user asked for JSON/CSV output; suppresses rich rendering.
    quiet: bool = False

    def with_overrides(self, **kwargs: Any) -> "Config":
        for key, value in kwargs.items():
            if value is not None and hasattr(self, key):
                setattr(self, key, value)
        return self


def config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "reconatlas" / "config.toml"


def load_config_file(cfg: Config) -> Config:
    """Apply settings from the config file if one exists.

    TOML is parsed with the stdlib ``tomllib`` (Python 3.11+). Older
    interpreters simply skip the file rather than failing.
    """
    path = config_path()
    if not path.is_file():
        return cfg

    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
        return cfg

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return cfg

    for key, value in data.items():
        if key == "cache_dir" and isinstance(value, str):
            cfg.cache_dir = Path(value).expanduser()
        elif hasattr(cfg, key):
            setattr(cfg, key, value)
    return cfg


def apply_env(cfg: Config) -> Config:
    """Apply ``RECONATLAS_*`` environment variables."""
    env = os.environ.get
    if env("RECONATLAS_USER_AGENT"):
        cfg.user_agent = env("RECONATLAS_USER_AGENT")
    if env("RECONATLAS_TIMEOUT"):
        try:
            cfg.timeout = float(env("RECONATLAS_TIMEOUT"))
        except ValueError:
            pass
    if env("RECONATLAS_CACHE_TTL"):
        try:
            cfg.cache_ttl = int(env("RECONATLAS_CACHE_TTL"))
        except ValueError:
            pass
    if env("RECONATLAS_NO_CACHE"):
        cfg.no_cache = env("RECONATLAS_NO_CACHE").lower() in {"1", "true", "yes"}
    if env("RECONATLAS_RATE_LIMIT"):
        try:
            cfg.rate_limit = float(env("RECONATLAS_RATE_LIMIT"))
        except ValueError:
            pass
    return cfg


def build_config() -> Config:
    cfg = Config()
    cfg = load_config_file(cfg)
    cfg = apply_env(cfg)
    return cfg
