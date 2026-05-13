#!/usr/bin/env python3
"""
Claude Usage Monitor
====================

A macOS menu-bar app that shows your claude.ai plan usage in real time.
The status-bar title always shows the 5-hour percent; the user can pin
extra metrics (Weekly · all models, Claude Design) via the dropdown menu.

First run: opens a one-time pywebview login window. After you paste a
sessionKey, future launches go straight to the menu bar — no Dock icon,
no ⌘-Tab entry.

The app polls the same internal API claude.ai uses to render the
"Plan usage" widget, and refreshes every 10 seconds.

Storage
-------
~/.claude-usage-monitor/cookies.json   sessionKey + expiry (chmod 600)
~/.claude-usage-monitor/config.json    last-known org_uuid + endpoint

Author note
-----------
Claude.ai's usage endpoint is not public, so the script tries a small
list of likely endpoint shapes and remembers whichever one returned a
parseable response. If all of them fail, the UI shows a clear error
plus instructions for finding the right one via DevTools.
"""

from __future__ import annotations

import json
import keyring
import os
import re
import stat
import subprocess
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import requests
import webview

# curl_cffi mimics a real browser at the TLS layer, which lets us bypass
# Cloudflare's bot protection on claude.ai. Fall back to plain requests if
# it's not installed (the user may have an older requirements.txt).
try:
    from curl_cffi import requests as cffi_requests  # type: ignore
    _HTTP_BACKEND = "curl_cffi"
except Exception:  # pragma: no cover
    cffi_requests = None  # type: ignore
    _HTTP_BACKEND = "requests"

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------

APP_NAME = "Claude Usage Monitor"
APP_DIR = Path.home() / ".claude-usage-monitor"
APP_DIR.mkdir(parents=True, exist_ok=True)
COOKIES_PATH = APP_DIR / "cookies.json"
CONFIG_PATH = APP_DIR / "config.json"
LOG_PATH = APP_DIR / "debug.log"

LOGIN_HTML_PATH = Path(__file__).resolve().parent / "login.html"

CLAUDE_BASE = "https://claude.ai"

REFRESH_SECONDS = 10

# Endpoint shapes to try in order. The first one that returns parseable
# usage data wins and is cached in config.json. claude.ai's API isn't
# documented so we cast a wide net.
USAGE_ENDPOINTS = [
    # Most likely (org-scoped, usage-specific)
    "{base}/api/organizations/{org}/usage",
    "{base}/api/organizations/{org}/usage_v2",
    "{base}/api/organizations/{org}/usage_v3",
    "{base}/api/organizations/{org}/usage_summary",
    "{base}/api/organizations/{org}/usage_breakdown",
    "{base}/api/organizations/{org}/billable_usage",
    "{base}/api/organizations/{org}/billable_usage_breakdown",
    "{base}/api/organizations/{org}/plan_usage",
    "{base}/api/organizations/{org}/quota_usage",
    # Rate limits
    "{base}/api/organizations/{org}/rate_limits",
    "{base}/api/organizations/{org}/rate_limit_status",
    "{base}/api/organizations/{org}/rate_limit",
    # Billing-prefixed
    "{base}/api/organizations/{org}/billing/usage",
    "{base}/api/organizations/{org}/billing/usage_v2",
    "{base}/api/organizations/{org}/billing/quota",
    "{base}/api/organizations/{org}/billing",
    # Account / quota / org self
    "{base}/api/organizations/{org}/quota",
    "{base}/api/organizations/{org}/account",
    "{base}/api/organizations/{org}/account_status",
    "{base}/api/organizations/{org}/subscription",
    "{base}/api/organizations/{org}",
    # Bootstrap variants (may contain usage)
    "{base}/api/organizations/{org}/bootstrap",
    "{base}/api/bootstrap/{org}",
    "{base}/api/bootstrap/{org}/statsig",
    # Account-scoped (no org in path)
    "{base}/api/account_status",
    "{base}/api/account",
    "{base}/api/auth/current_account",
    "{base}/api/me",
    "{base}/api/me/usage",
    "{base}/api/me/quota",
    # Generic
    "{base}/api/usage",
    "{base}/api/usage_v2",
    "{base}/api/rate_limits",
]

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/127.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
    "Referer": f"{CLAUDE_BASE}/",
    "anthropic-client-platform": "web_claude_ai",
}


def _http_get(url: str, *, cookies: dict | None = None, headers: dict | None = None,
              timeout: int = 15, allow_redirects: bool = False):
    """
    GET helper that prefers curl_cffi (which impersonates a real browser
    so Cloudflare lets us through). Falls back to plain requests if curl_cffi
    isn't installed.
    """
    if cffi_requests is not None:
        return cffi_requests.get(
            url,
            cookies=cookies or {},
            headers=headers or DEFAULT_HEADERS,
            timeout=timeout,
            allow_redirects=allow_redirects,
            impersonate="chrome",
        )
    return requests.get(
        url,
        cookies=cookies or {},
        headers=headers or DEFAULT_HEADERS,
        timeout=timeout,
        allow_redirects=allow_redirects,
    )


# ---------------------------------------------------------------------------
# Utility logging
# ---------------------------------------------------------------------------

def log(msg: str, *, exc: bool = False) -> None:
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n"
    try:
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(line)
            if exc:
                f.write(traceback.format_exc())
    except Exception:
        pass
    print(line, end="", file=sys.stderr)


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------

_KEYRING_SERVICE = "Claude Usage Monitor"
_KEYRING_USER = "sessionKey"


def _secure_write(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass


def load_cookies() -> dict[str, str]:
    try:
        v = keyring.get_password(_KEYRING_SERVICE, _KEYRING_USER)
    except Exception:
        log("keyring read failed", exc=True)
        v = None
    if v:
        return {"sessionKey": v}

    # One-time migration: import the legacy plaintext cookies.json into
    # the Keychain, then delete the file.
    if COOKIES_PATH.exists():
        try:
            legacy = json.loads(COOKIES_PATH.read_text(encoding="utf-8"))
            key = legacy.get("sessionKey")
            if key:
                keyring.set_password(_KEYRING_SERVICE, _KEYRING_USER, key)
                COOKIES_PATH.unlink(missing_ok=True)
                log("migrated sessionKey from cookies.json to Keychain")
                return {"sessionKey": key}
        except Exception:
            log("cookies.json malformed during migration, ignoring", exc=True)
        # Whatever happened, drop the legacy file so we don't keep the token on disk.
        try:
            COOKIES_PATH.unlink(missing_ok=True)
        except Exception:
            pass
    return {}


def save_cookies(cookies: dict[str, str]) -> None:
    key = cookies.get("sessionKey", "")
    if not key:
        return
    try:
        keyring.set_password(_KEYRING_SERVICE, _KEYRING_USER, key)
    except Exception:
        log("keyring write failed", exc=True)


def clear_cookies() -> None:
    try:
        keyring.delete_password(_KEYRING_SERVICE, _KEYRING_USER)
    except keyring.errors.PasswordDeleteError:
        pass
    except Exception:
        log("keyring delete failed", exc=True)
    # Belt & suspenders: drop any stale legacy file too.
    try:
        COOKIES_PATH.unlink(missing_ok=True)
    except Exception:
        pass


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_config(cfg: dict) -> None:
    _secure_write(CONFIG_PATH, cfg)


# Which optional metrics the user has pinned to the menu-bar title (in
# addition to the always-shown 5-hour percent). Stored as a list of
# claude.ai internal keys, e.g. ["seven_day", "seven_day_omelette"].
def get_banner_extras() -> list[str]:
    val = load_config().get("banner_extras", [])
    return list(val) if isinstance(val, list) else []


def set_banner_extras(keys: list[str]) -> None:
    cfg = load_config()
    cfg["banner_extras"] = list(keys)
    save_config(cfg)


# Whether the optional floating window (in addition to the menu-bar item)
# should be open. Persisted so a user who relies on the floating window
# doesn't have to re-enable it every launch.
def get_show_floating() -> bool:
    return bool(load_config().get("show_floating", False))


def set_show_floating(v: bool) -> None:
    cfg = load_config()
    cfg["show_floating"] = bool(v)
    save_config(cfg)


# Floating-window theme: "system" (follow macOS), "light", or "dark".
THEME_VALUES = ("system", "light", "dark")


def get_theme() -> str:
    val = load_config().get("theme", "system")
    return val if val in THEME_VALUES else "system"


def set_theme(v: str) -> None:
    cfg = load_config()
    cfg["theme"] = v if v in THEME_VALUES else "system"
    save_config(cfg)


# ---------------------------------------------------------------------------
# Claude API client
# ---------------------------------------------------------------------------

@dataclass
class UsageRow:
    label: str
    percent: float           # 0..100
    resets_in: str           # "49m" / "4d" / ""
    key: str = ""            # claude.ai's internal key: "five_hour", "seven_day", "seven_day_omelette", ...
    raw: dict = field(default_factory=dict)


class ClaudeClient:
    """Talks to the internal claude.ai API using saved cookies."""

    def __init__(self) -> None:
        self._cookies: dict[str, str] = {}
        self._refresh_cookies()

    # -- cookies ----------------------------------------------------------

    def _refresh_cookies(self) -> None:
        self._cookies = dict(load_cookies())

    # -- low-level helpers ------------------------------------------------

    def _get(self, url: str):
        return _http_get(url, cookies=self._cookies)

    def get_org_uuid(self) -> Optional[str]:
        cfg = load_config()
        if cfg.get("org_uuid"):
            return cfg["org_uuid"]

        r = self._get(f"{CLAUDE_BASE}/api/organizations")
        if r.status_code in (401, 403):
            body_preview = ""
            try:
                body_preview = r.text[:300].lower()
            except Exception:
                pass
            if "<html" in body_preview or "cloudflare" in body_preview:
                raise RuntimeError("blocked by claude.ai's bot protection (Cloudflare)")
            raise PermissionError("not_logged_in")
        r.raise_for_status()
        orgs = r.json()
        if not isinstance(orgs, list) or not orgs:
            raise RuntimeError("no organizations returned")
        # Prefer the org whose capabilities indicate the user is a real member.
        chosen = orgs[0]
        for o in orgs:
            caps = o.get("capabilities") or []
            if "chat" in caps or "claude_pro" in " ".join(caps).lower():
                chosen = o
                break
        org_uuid = chosen.get("uuid") or chosen.get("id")
        if not org_uuid:
            raise RuntimeError("organization payload missing uuid")
        cfg["org_uuid"] = org_uuid
        save_config(cfg)
        return org_uuid

    # -- public API -------------------------------------------------------

    def _discover_endpoints_from_frontend(self, org: str) -> list[str]:
        """
        Scrape claude.ai's public Next.js JS bundles to find API path
        patterns. We grep for paths that mention usage/quota/rate/billing
        and substitute the org UUID. Cached in config.json under
        'discovered_endpoints'.
        """
        cfg = load_config()
        if cfg.get("discovered_endpoints"):
            return list(cfg["discovered_endpoints"])

        try:
            r = self._get(f"{CLAUDE_BASE}/")
            html = r.text if r.status_code == 200 else ""
        except Exception as e:
            log(f"discover: failed to fetch claude.ai/: {e}")
            return []

        # Extract Next.js script chunks.
        chunks = sorted(set(re.findall(r"/_next/static/[^\"'\s>]+\.js", html)))
        log(f"discover: found {len(chunks)} JS chunks on claude.ai/")

        # Three patterns to catch Next.js's many ways of writing API paths:
        # (a) plain quoted strings: "/api/organizations/abc/usage_v2"
        # (b) template literals:    `/api/organizations/${e}/usage_v2`
        # (c) string concat heads:  "/api/organizations/" + e + "/usage_v2"
        keywords = r"(?:usage|quota|rate[_-]?limit|billing|plan|account[_-]?status|consumption|capacity)"
        patterns = [
            re.compile(rf'"(/api/[^"]*?{keywords}[^"]*?)"', re.IGNORECASE),
            re.compile(rf'`(/api/[^`]*?{keywords}[^`]*?)`', re.IGNORECASE),
            # /api/organizations/ + segment + /<keyword>...
            re.compile(rf'"(/api/organizations/)"\s*[+,]\s*[\w.\[\]]+\s*[+,]\s*"(/[^"]*?{keywords}[^"]*)"', re.IGNORECASE),
            # /api/<tail>?org=...&...
            re.compile(rf'"(/api/{keywords}[^"]*)"', re.IGNORECASE),
        ]

        found: set[str] = set()
        # Limit to first ~40 chunks to keep this snappy.
        for path in chunks[:40]:
            url = f"{CLAUDE_BASE}{path}"
            try:
                cr = self._get(url)
                if cr.status_code != 200:
                    continue
                body = cr.text
            except Exception:
                continue

            raw_paths: list[str] = []
            for pat in patterns:
                for m in pat.findall(body):
                    # findall returns either a string (one group) or a tuple (multi-group).
                    if isinstance(m, tuple):
                        raw_paths.append("".join(m))
                    else:
                        raw_paths.append(m)

            for raw in raw_paths:
                # Substitute template literals like ${e} with the org UUID.
                cleaned = re.sub(r"\$\{[^}]+\}", org, raw)
                # If the path still has /<placeholder>/ between organizations and keyword
                # we may need to try inserting the org. Skip anything still templated.
                if "{" in cleaned or "${" in cleaned:
                    continue
                # If "/api/organizations//<rest>" appears (concat pattern lost the segment),
                # insert the org UUID.
                cleaned = cleaned.replace("/api/organizations//", f"/api/organizations/{org}/")
                if cleaned.startswith("/"):
                    full = f"{CLAUDE_BASE}{cleaned}"
                else:
                    full = cleaned
                # Sanity check: must be claude.ai and have an /api/ path.
                if "claude.ai/api/" not in full:
                    continue
                # Strip query strings - we'll add them only if they were on the canonical URL.
                full = full.split("?", 1)[0]
                found.add(full)

        urls = sorted(found)
        log(f"discover: scraped {len(urls)} candidate URLs from JS bundles: {urls[:10]}")
        cfg["discovered_endpoints"] = urls
        save_config(cfg)
        return urls

    def fetch_usage(self) -> list[UsageRow]:
        self._refresh_cookies()
        if "sessionKey" not in self._cookies:
            raise PermissionError("not_logged_in")

        org = self.get_org_uuid()
        cfg = load_config()
        endpoints_to_try: list[str] = []
        if cfg.get("usage_endpoint"):
            endpoints_to_try.append(cfg["usage_endpoint"])
        for tmpl in USAGE_ENDPOINTS:
            url = tmpl.format(base=CLAUDE_BASE, org=org)
            if url not in endpoints_to_try:
                endpoints_to_try.append(url)
        # Plus anything we previously scraped from the frontend bundles.
        for url in (cfg.get("discovered_endpoints") or []):
            if url not in endpoints_to_try:
                endpoints_to_try.append(url)

        # Track status codes per URL to surface a useful diagnostic.
        attempts: list[tuple[str, str]] = []   # (url, status_or_error)
        successes_without_rows: list[tuple[str, dict]] = []

        for url in endpoints_to_try:
            try:
                r = self._get(url)
                status = r.status_code
            except Exception as e:
                attempts.append((url, f"ERR {e.__class__.__name__}"))
                continue

            if status in (401, 403):
                # Could be auth or Cloudflare - check body
                try:
                    body_preview = r.text[:200].lower()
                except Exception:
                    body_preview = ""
                if "<html" in body_preview or "cloudflare" in body_preview:
                    attempts.append((url, f"{status} (CF block)"))
                    continue
                raise PermissionError("not_logged_in")

            attempts.append((url, str(status)))

            if status != 200:
                continue

            try:
                payload = r.json()
            except Exception:
                # 200 but body isn't JSON - skip
                continue

            rows = parse_usage(payload)
            if rows:
                cfg["usage_endpoint"] = url
                save_config(cfg)
                log(f"discovered usage endpoint: {url}")
                return rows

            # 200 with JSON but parser found nothing useful. Save the
            # payload's top-level keys to the log so the user (or me) can
            # see what claude.ai is returning.
            top_keys = list(payload.keys()) if isinstance(payload, dict) else f"list[{len(payload)}]"
            successes_without_rows.append((url, top_keys if isinstance(top_keys, list) else {"shape": top_keys}))
            log(f"200 from {url} but no usage rows. top-level keys: {top_keys}")
            try:
                snippet = json.dumps(payload)[:1200]
            except Exception:
                snippet = str(payload)[:1200]
            log(f"  snippet: {snippet}")

        # Last-ditch fallback: scrape claude.ai's frontend JS bundles
        # for API paths and try those. This only runs once per install
        # (results cached in config) and should reveal the real endpoint
        # even if our hard-coded list is wrong.
        if not cfg.get("discovered_endpoints"):
            log("hard-coded endpoints all failed; attempting JS bundle discovery")
            scraped = self._discover_endpoints_from_frontend(org)
            new_urls = [u for u in scraped if u not in endpoints_to_try]
            if new_urls:
                log(f"trying {len(new_urls)} URLs scraped from frontend")
                for url in new_urls:
                    try:
                        r = self._get(url)
                        status = r.status_code
                    except Exception as e:
                        attempts.append((url, f"ERR {e.__class__.__name__}"))
                        continue
                    attempts.append((url, str(status) + " (scraped)"))
                    if status != 200:
                        continue
                    try:
                        payload = r.json()
                    except Exception:
                        continue
                    rows = parse_usage(payload)
                    if rows:
                        cfg["usage_endpoint"] = url
                        save_config(cfg)
                        log(f"discovered usage endpoint via JS scrape: {url}")
                        return rows
                    top_keys = list(payload.keys()) if isinstance(payload, dict) else f"list[{len(payload)}]"
                    successes_without_rows.append((url, top_keys if isinstance(top_keys, list) else {"shape": top_keys}))
                    log(f"200 from {url} (scraped) but no usage rows. top-level keys: {top_keys}")
                    try:
                        snippet = json.dumps(payload)[:1500]
                    except Exception:
                        snippet = str(payload)[:1500]
                    log(f"  snippet: {snippet}")

        # Build a readable summary for the UI.
        summary_lines = [f"  {u} → {s}" for u, s in attempts]
        summary = "\n".join(summary_lines)
        if successes_without_rows:
            extras = "\n".join(
                f"  {u} returned 200 with keys: {k}" for u, k in successes_without_rows
            )
            summary += f"\n\n200s with unrecognised shape (see debug.log for raw body):\n{extras}"

        raise RuntimeError(
            "Could not auto-discover the usage endpoint. "
            "Use the menu → 'Set endpoint manually' and paste the URL "
            "from your browser's DevTools (Network tab on claude.ai, look for a fetch "
            "containing 'usage', 'quota' or 'rate_limit').\n\n"
            f"Tried:\n{summary}"
        )


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

_RESET_DURATION_RE = re.compile(
    r"P?T?(?:(?P<days>\d+)D)?(?:(?P<hours>\d+)H)?(?:(?P<mins>\d+)M)?",
    re.IGNORECASE,
)


def _humanize_reset(seconds: Optional[float]) -> str:
    if seconds is None or seconds <= 0:
        return ""
    seconds = int(seconds)
    if seconds < 60 * 60:
        return f"{max(1, seconds // 60)}m"
    if seconds < 60 * 60 * 24:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def _coerce_percent(used: Any, limit: Any, percent: Any) -> Optional[float]:
    try:
        if percent is not None:
            p = float(percent)
            return p * 100 if p <= 1 else p
        if used is not None and limit not in (None, 0):
            return float(used) / float(limit) * 100
    except (TypeError, ValueError):
        return None
    return None


# Friendly labels for claude.ai's internal limit keys. Anything not in
# this map falls back to a Title Cased version of the key.
LIMIT_LABELS = {
    "five_hour": "5-hour limit",
    "seven_day": "Weekly · all models",
    "seven_day_opus": "Weekly · Opus",
    "seven_day_sonnet": "Weekly · Sonnet",
    "seven_day_haiku": "Weekly · Haiku",
    "seven_day_oauth_apps": "Weekly · API apps",
    "seven_day_cowork": "Weekly · Cowork",
    "seven_day_omelette": "Weekly · Claude Design",
    "iguana_necktie": "Iguana necktie",
    "omelette_promotional": "Design promo",
    "extra_usage": "Extra usage",
}


def _extract_limit_metric(value: Any) -> tuple[Optional[float], str]:
    """
    Given the value side of one entry in claude.ai's /usage response
    (which can be a number, a dict, or a list), return (percent_0_to_100,
    resets_in_string). Returns (None, "") if no usage signal can be found.
    """
    if value is None:
        return None, ""

    # Bare number — assume utilization in 0..1 or 0..100
    if isinstance(value, (int, float)):
        v = float(value)
        return (v * 100 if v <= 1.0 else v, "")

    if isinstance(value, list):
        # Pick the largest utilization across the list (most useful signal).
        best_pct: Optional[float] = None
        best_resets = ""
        for item in value:
            p, r = _extract_limit_metric(item)
            if p is None:
                continue
            if best_pct is None or p > best_pct:
                best_pct = p
                best_resets = r
        return best_pct, best_resets

    if not isinstance(value, dict):
        return None, ""

    # Look for a utilization-like field across many naming conventions.
    pct: Optional[float] = None
    for k in (
        "utilization", "percent", "percentage", "percent_used",
        "ratio", "used_ratio", "usage_ratio", "fraction",
    ):
        if k in value and value[k] is not None:
            try:
                v = float(value[k])
                pct = v * 100 if v <= 1.0 else v
                break
            except (TypeError, ValueError):
                pass

    # Fall back to used / limit math.
    if pct is None:
        used = (value.get("used") or value.get("usage")
                or value.get("current") or value.get("current_usage")
                or value.get("consumed") or value.get("count"))
        limit = (value.get("limit") or value.get("max")
                 or value.get("quota") or value.get("cap")
                 or value.get("total") or value.get("max_count"))
        try:
            if used is not None and limit not in (None, 0):
                pct = float(used) / float(limit) * 100
        except (TypeError, ValueError, ZeroDivisionError):
            pass

    if pct is None:
        return None, ""

    # Find the reset time.
    seconds_left: Optional[float] = None
    for k in ("resets_in_seconds", "seconds_until_reset", "reset_in_seconds"):
        if k in value and value[k] is not None:
            try:
                seconds_left = float(value[k])
                break
            except (TypeError, ValueError):
                pass

    if seconds_left is None:
        for k in ("resets_at", "reset_at", "resets_at_utc", "reset_time", "expires_at", "ends_at"):
            ts = value.get(k)
            if ts is None:
                continue
            try:
                from datetime import datetime, timezone
                if isinstance(ts, (int, float)):
                    dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
                else:
                    dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                seconds_left = (dt - datetime.now(timezone.utc)).total_seconds()
                break
            except Exception:
                continue

    return max(0.0, min(100.0, pct)), _humanize_reset(seconds_left)


def _parse_keyed_shape(payload: dict) -> list[UsageRow]:
    """
    claude.ai's /api/organizations/{org}/usage returns
        {"five_hour": {...}, "seven_day": {...}, "seven_day_opus": {...}, ...}
    Each value carries utilization + reset info. This parser handles that
    shape directly. Returns [] if no recognised key is present.
    """
    if not isinstance(payload, dict):
        return []
    if not any(k in payload for k in LIMIT_LABELS):
        return []

    rows: list[UsageRow] = []
    for key, value in payload.items():
        pct, resets_in = _extract_limit_metric(value)
        if pct is None:
            continue
        # Skip noise: zeros, and entries that are just promotional flags.
        if pct < 0.5 and key not in ("five_hour", "seven_day", "seven_day_omelette"):
            continue
        label = LIMIT_LABELS.get(key, key.replace("_", " ").title())
        rows.append(UsageRow(label=label, percent=pct, resets_in=resets_in, key=key, raw={"key": key}))

    def _rank(row: UsageRow) -> tuple:
        l = row.label.lower()
        if "5-hour" in l: return (0,)
        if "all models" in l: return (1,)
        if "claude design" in l: return (2, row.label)
        if "weekly" in l: return (3, row.label)
        return (4, row.label)
    rows.sort(key=_rank)
    return rows[:6]


def parse_usage(payload: Any) -> list[UsageRow]:
    """
    Pull rows out of whichever shape claude.ai returned. We try the
    canonical /api/organizations/{org}/usage shape first, then fall back
    to a recursive walker for unknown shapes.
    """
    # Shape A: keys-as-labels (claude.ai's actual /usage response).
    if isinstance(payload, dict):
        keyed = _parse_keyed_shape(payload)
        if keyed:
            return keyed

    # Shape B: recursive walker for nested payloads.
    rows: list[UsageRow] = []

    def _walk(obj: Any, path: str = "") -> None:
        if isinstance(obj, dict):
            label = obj.get("display_name") or obj.get("name") or obj.get("label")
            used = obj.get("used") or obj.get("usage") or obj.get("current")
            limit = obj.get("limit") or obj.get("quota") or obj.get("max")
            percent = obj.get("percent") or obj.get("percentage") or obj.get("ratio")
            resets_at = (
                obj.get("resets_at")
                or obj.get("reset_at")
                or obj.get("resets_at_utc")
                or obj.get("reset_time")
            )
            resets_in_seconds = obj.get("resets_in_seconds") or obj.get("seconds_until_reset")

            p = _coerce_percent(used, limit, percent)
            if label and p is not None:
                if resets_in_seconds is None and resets_at:
                    try:
                        from datetime import datetime, timezone
                        if isinstance(resets_at, (int, float)):
                            ts = datetime.fromtimestamp(float(resets_at), tz=timezone.utc)
                        else:
                            s = str(resets_at).replace("Z", "+00:00")
                            ts = datetime.fromisoformat(s)
                        resets_in_seconds = (ts - datetime.now(timezone.utc)).total_seconds()
                    except Exception:
                        resets_in_seconds = None
                rows.append(UsageRow(
                    label=str(label),
                    percent=max(0.0, min(100.0, p)),
                    resets_in=_humanize_reset(resets_in_seconds),
                    raw={"path": path},
                ))
            for k, v in obj.items():
                _walk(v, f"{path}.{k}" if path else k)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                _walk(item, f"{path}[{i}]")

    _walk(payload)

    # De-dup by label, preferring the entry deepest in the tree (more specific).
    seen: dict[str, UsageRow] = {}
    for r in rows:
        seen[r.label] = r
    deduped = list(seen.values())

    # Heuristic ordering: 5-hour first, weekly all models second, others after.
    def _rank(row: UsageRow) -> int:
        l = row.label.lower()
        if "5" in l and ("hour" in l or "hr" in l):
            return 0
        if "week" in l and "all" in l:
            return 1
        if "week" in l:
            return 2
        return 3

    deduped.sort(key=_rank)
    return deduped[:6]


# ---------------------------------------------------------------------------
# Login flow (paste-based, since Google OAuth is blocked in WKWebView)
# ---------------------------------------------------------------------------

def _verify_session_key(session_key: str) -> tuple[bool, str]:
    """
    Best-effort verification. We try to hit /api/organizations, but Cloudflare
    will sometimes block automated requests even with curl_cffi - so a hard
    failure here doesn't necessarily mean the key is bad. We surface a useful
    message either way.

    Returns (looks_good, message). looks_good=True even on inconclusive results
    when the key has the right shape - the main app's polling loop will tell
    us for sure.
    """
    if not session_key.startswith("sk-ant-"):
        return False, "Doesn't look like a sessionKey - the value should start with 'sk-ant-'."

    try:
        r = _http_get(
            f"{CLAUDE_BASE}/api/organizations",
            cookies={"sessionKey": session_key},
        )
    except Exception as e:
        log(f"verify: network error: {e}", exc=True)
        return True, f"Saved (could not reach claude.ai to verify: {e})."

    body_preview = ""
    try:
        body_preview = r.text[:600]
    except Exception:
        pass
    log(f"verify: status={r.status_code} backend={_HTTP_BACKEND} body_head={body_preview[:200]!r}")

    if r.status_code == 200:
        try:
            data = r.json()
            if isinstance(data, list):
                return True, ""
        except Exception:
            pass
        return True, ""

    # Distinguish a real auth failure (JSON error) from a Cloudflare block (HTML).
    looks_html = "<html" in body_preview.lower() or "<!doctype" in body_preview.lower() \
        or "cloudflare" in body_preview.lower()

    if r.status_code in (401, 403) and not looks_html:
        return False, "Claude rejected this sessionKey - double-check you copied the full value."

    # Inconclusive (Cloudflare, 5xx, redirect, etc.) - save anyway, let the
    # main app surface the real error if there is one.
    return True, f"Saved. Verification was inconclusive (HTTP {r.status_code}); the main window will show usage if it works."


class LoginBridge:
    """JS bridge methods for the login window."""

    def __init__(self) -> None:
        self.captured = threading.Event()
        self.cancelled = threading.Event()
        self.window: Optional[webview.Window] = None

    def open_claude_in_browser(self) -> dict:
        """Open https://claude.ai in the user's default browser."""
        try:
            subprocess.Popen(["open", CLAUDE_BASE])
            return {"status": "ok"}
        except Exception as e:
            log(f"failed to open browser: {e}", exc=True)
            return {"status": "error", "message": str(e)}

    def auto_detect_session_key(self) -> dict:
        """Try to read the sessionKey directly from any installed browser the
        user is already signed in to claude.ai with. Saves it on success.
        Returns a structured response so the UI can show actionable guidance.
        """
        try:
            import browser_cookie3 as bc3
        except ImportError as e:
            return {"status": "error", "message": f"browser-cookie3 not installed: {e}"}

        def _arc_loader(domain_name: str = ""):
            """Arc isn't natively supported by browser-cookie3, but it's
            Chromium-based with its own profile dir + 'Arc Safe Storage'
            keychain entry. Drive ChromiumBased manually.
            """
            return bc3.ChromiumBased(
                browser="arc",
                cookie_file=None,
                domain_name=domain_name,
                key_file=None,
                linux_cookies=[],
                windows_cookies=[],
                osx_cookies=[
                    os.path.expanduser(
                        "~/Library/Application Support/Arc/User Data/Default/Cookies"
                    ),
                    os.path.expanduser(
                        "~/Library/Application Support/Arc/User Data/Default/Network/Cookies"
                    ),
                ],
                windows_keys=[],
                os_crypt_name="arc",
                osx_key_service="Arc Safe Storage",
                osx_key_user="Arc",
            ).load()

        candidates = [
            ("Arc",     _arc_loader),
            ("Chrome",  bc3.chrome),
            ("Brave",   bc3.brave),
            ("Edge",    bc3.edge),
            ("Firefox", bc3.firefox),
            ("Safari",  bc3.safari),
        ]

        expired: list[str] = []             # cookie found but rejected by claude.ai
        permission_blocked: list[str] = []  # macOS denied access to cookie file
        no_cookie: list[str] = []           # browser readable but no claude.ai cookie
        unavailable: list[str] = []         # browser not installed / no profile

        for name, fn in candidates:
            try:
                jar = fn(domain_name="claude.ai")
            except Exception as e:
                emsg = str(e).lower()
                if "operation not permitted" in emsg or "permission denied" in emsg:
                    permission_blocked.append(name)
                else:
                    unavailable.append(name)
                log(f"auto-detect: {name} failed: {e}")
                continue

            session_cookie = None
            for c in jar:
                if c.name == "sessionKey" and c.value:
                    session_cookie = c
                    break

            if session_cookie is None:
                no_cookie.append(name)
                continue

            ok, vmsg = _verify_session_key(session_cookie.value)
            if ok:
                save_cookies({"sessionKey": session_cookie.value})
                log(f"auto-detect: matched in {name} (verify: {vmsg!r})")
                self.captured.set()
                return {"status": "ok", "browser": name, "message": vmsg}
            log(f"auto-detect: {name} cookie rejected ({vmsg!r})")
            expired.append(name)

        return {
            "status": "not_found",
            "expired": expired,
            "permission_blocked": permission_blocked,
            "no_cookie": no_cookie,
            "unavailable": unavailable,
        }

    def open_fda_settings(self) -> dict:
        """Open System Settings → Privacy & Security → Full Disk Access."""
        try:
            subprocess.Popen([
                "open",
                "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles",
            ])
            return {"status": "ok"}
        except Exception as e:
            log(f"failed to open FDA settings: {e}", exc=True)
            return {"status": "error", "message": str(e)}

    def submit_session_key(self, key: str) -> dict:
        """Validate the sessionKey by calling /api/organizations, then save it."""
        key = (key or "").strip().strip('"').strip("'")
        if not key:
            return {"status": "error", "message": "Empty key."}
        ok, msg = _verify_session_key(key)
        if not ok:
            return {"status": "error", "message": msg}
        save_cookies({"sessionKey": key})
        log(f"sessionKey saved (verify message: {msg!r})")
        self.captured.set()
        return {"status": "ok", "message": msg}

    def finish_login(self) -> None:
        """Close the login window after a successful save."""
        try:
            if self.window:
                self.window.destroy()
        except Exception:
            pass

    def cancel_login(self) -> None:
        self.cancelled.set()
        try:
            if self.window:
                self.window.destroy()
        except Exception:
            pass


def run_login_window() -> bool:
    """Open the paste-based login window. Returns True if a session was captured."""
    bridge = LoginBridge()
    bridge.window = webview.create_window(
        "Connect to Claude",
        url=str(LOGIN_HTML_PATH.as_uri()),
        js_api=bridge,
        width=560,
        height=560,
        resizable=False,
        on_top=True,
        background_color="#0F0F10",
    )
    webview.start(debug=False)
    return bridge.captured.is_set()


# ---------------------------------------------------------------------------
# Menu-bar (NSStatusItem) UI
# ---------------------------------------------------------------------------
#
# We use AppKit directly via PyObjC. The status bar shows a short title
# (always the 5-hour percent, plus optional Weekly / Claude Design pinned
# by the user). Clicking opens an NSMenu with one custom-view row per
# usage metric (label + percent + native NSProgressIndicator bar) and
# checkbox menu items for the banner-extras toggles.

from AppKit import (  # type: ignore
    NSApplication,
    NSStatusBar,
    NSVariableStatusItemLength,
    NSMenu,
    NSMenuItem,
    NSView,
    NSTextField,
    NSFont,
    NSFontWeightRegular,
    NSColor,
    NSAlert,
    NSAlertFirstButtonReturn,
    NSApplicationActivationPolicyAccessory,
    NSControlStateValueOn,
    NSControlStateValueOff,
    NSTextAlignmentRight,
    NSTextAlignmentCenter,
    NSWindow,
    NSWindowStyleMaskBorderless,
    NSBackingStoreBuffered,
    NSFloatingWindowLevel,
    NSScreen,
    NSButton,
    NSAppearance,
    NSBezierPath,
    NSGradient,
)
from Foundation import NSObject, NSMakeRect  # type: ignore
import objc  # type: ignore

# How extras are displayed in the status-bar title.
BANNER_EXTRA_SHORT_LABELS = {
    "seven_day": "W",
    "seven_day_omelette": "CD",
}

# Which extras the menu offers (key, human label).
BANNER_EXTRA_OPTIONS = [
    ("seven_day", "Weekly · all models"),
    ("seven_day_omelette", "Claude Design"),
]

ROW_VIEW_WIDTH = 280
ROW_VIEW_HEIGHT = 38

# Bar colors mirror the original CSS thresholds:
#   < 50%   → blue gradient   (#1F6FB2 → #3DA9FC)
#   < 85%   → orange gradient (#C9651C → #FF8A4C)
#   ≥ 85%   → magenta gradient (#B6195F → #E11D74)
def _bar_gradient_for(percent: float) -> "NSGradient":
    def c(r, g, b):
        return NSColor.colorWithCalibratedRed_green_blue_alpha_(r / 255, g / 255, b / 255, 1.0)
    if percent < 50:
        start, end = c(0x1F, 0x6F, 0xB2), c(0x3D, 0xA9, 0xFC)
    elif percent < 85:
        start, end = c(0xC9, 0x65, 0x1C), c(0xFF, 0x8A, 0x4C)
    else:
        start, end = c(0xB6, 0x19, 0x5F), c(0xE1, 0x1D, 0x74)
    return NSGradient.alloc().initWithStartingColor_endingColor_(start, end)


class BarView(NSView):
    """Rounded fill bar with a percent-based gradient (replaces NSProgressIndicator)."""

    def initWithFrame_percent_(self, frame, percent):
        self = objc.super(BarView, self).initWithFrame_(frame)
        if self is None:
            return None
        self._percent = max(0.0, min(100.0, float(percent)))
        return self

    def drawRect_(self, dirty):
        bounds = self.bounds()
        radius = bounds.size.height / 2.0

        # Background pill — adapts to the view's effective appearance so the
        # floating window in light mode doesn't get a near-black pill.
        is_dark = True
        try:
            appearance = self.effectiveAppearance()
            matched = appearance.bestMatchFromAppearancesWithNames_(
                ["NSAppearanceNameAqua", "NSAppearanceNameDarkAqua"]
            )
            is_dark = (matched == "NSAppearanceNameDarkAqua")
        except Exception:
            pass
        if is_dark:
            NSColor.colorWithCalibratedWhite_alpha_(0.18, 1.0).setFill()
        else:
            NSColor.colorWithCalibratedWhite_alpha_(0.88, 1.0).setFill()
        NSBezierPath.bezierPathWithRoundedRect_xRadius_yRadius_(
            bounds, radius, radius
        ).fill()

        if self._percent <= 0:
            return

        # Foreground gradient pill
        fill_w = bounds.size.width * (self._percent / 100.0)
        fill_rect = NSMakeRect(bounds.origin.x, bounds.origin.y, fill_w, bounds.size.height)
        path = NSBezierPath.bezierPathWithRoundedRect_xRadius_yRadius_(
            fill_rect, radius, radius
        )
        _bar_gradient_for(self._percent).drawInBezierPath_angle_(path, 0.0)


def _make_row_view(label: str, percent: float, resets_in: str, width: int = ROW_VIEW_WIDTH) -> NSView:
    """Custom NSView used as an NSMenuItem's view (or as a row in the floating
    window): label on the left, percent + resets on the right, colored fill
    bar below. `width` lets callers reuse the same row at different widths."""
    view = NSView.alloc().initWithFrame_(NSMakeRect(0, 0, width, ROW_VIEW_HEIGHT))

    # Label (left)
    label_field = NSTextField.alloc().initWithFrame_(NSMakeRect(14, 19, width - 168, 16))
    label_field.setStringValue_(label)
    label_field.setBezeled_(False)
    label_field.setDrawsBackground_(False)
    label_field.setEditable_(False)
    label_field.setSelectable_(False)
    label_field.setFont_(NSFont.systemFontOfSize_(12))
    label_field.setTextColor_(NSColor.labelColor())
    view.addSubview_(label_field)

    # Percent + resets (right-aligned to the right edge)
    pct_text = f"{int(round(percent))}%"
    if resets_in:
        pct_text = f"{pct_text}  ·  resets {resets_in}"
    meta_field = NSTextField.alloc().initWithFrame_(NSMakeRect(width - 154, 19, 140, 16))
    meta_field.setStringValue_(pct_text)
    meta_field.setBezeled_(False)
    meta_field.setDrawsBackground_(False)
    meta_field.setEditable_(False)
    meta_field.setSelectable_(False)
    meta_field.setAlignment_(NSTextAlignmentRight)
    meta_field.setFont_(NSFont.monospacedDigitSystemFontOfSize_weight_(11, NSFontWeightRegular))
    meta_field.setTextColor_(NSColor.secondaryLabelColor())
    view.addSubview_(meta_field)

    # Colored fill bar (full width minus padding)
    bar = BarView.alloc().initWithFrame_percent_(
        NSMakeRect(14, 8, width - 28, 6), percent
    )
    view.addSubview_(bar)

    return view


# ---------------------------------------------------------------------------
# Optional always-on-top floating window (built in pure Cocoa so it shares
# the menu-bar app's NSApplication event loop).
# ---------------------------------------------------------------------------

FLOATING_WIDTH = 300
FLOATING_HEADER_H = 28
FLOATING_ROW_H = 44
FLOATING_PADDING = 8


class FloatingWindow(NSObject):
    """A small frameless always-on-top NSWindow that mirrors the dropdown rows."""

    def initWithToggleCallback_(self, callback):
        self = objc.super(FloatingWindow, self).init()
        if self is None:
            return None
        self._callback = callback  # called when user clicks the × close button

        # Position: top-left of the main screen, ~60px in from the corner.
        screen_rect = NSScreen.mainScreen().visibleFrame()
        initial_h = FLOATING_HEADER_H + FLOATING_ROW_H * 3 + FLOATING_PADDING
        x = screen_rect.origin.x + 60
        y = screen_rect.origin.y + screen_rect.size.height - initial_h - 60

        self.window = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            NSMakeRect(x, y, FLOATING_WIDTH, initial_h),
            NSWindowStyleMaskBorderless,
            NSBackingStoreBuffered,
            False,
        )
        self.window.setLevel_(NSFloatingWindowLevel)
        self.window.setMovableByWindowBackground_(True)
        self.window.setOpaque_(False)
        self.window.setBackgroundColor_(NSColor.clearColor())
        self.window.setHasShadow_(True)
        # macOS hides borderless windows when the app deactivates by default;
        # we explicitly want it visible across spaces.
        self.window.setHidesOnDeactivate_(False)
        self.window.setCollectionBehavior_(1 << 0)  # NSWindowCollectionBehaviorCanJoinAllSpaces

        # Content: a layer-backed NSView with rounded corners. Background
        # color is set by applyTheme_() based on the user's preference.
        content = NSView.alloc().initWithFrame_(
            NSMakeRect(0, 0, FLOATING_WIDTH, initial_h)
        )
        content.setWantsLayer_(True)
        content.layer().setCornerRadius_(10.0)
        self.window.setContentView_(content)
        self._content = content

        # Header label "Plan usage" (left) + close button "×" (right).
        self._header_label = NSTextField.alloc().initWithFrame_(
            NSMakeRect(14, initial_h - 22, 200, 16)
        )
        self._header_label.setStringValue_("Plan usage")
        self._header_label.setBezeled_(False)
        self._header_label.setDrawsBackground_(False)
        self._header_label.setEditable_(False)
        self._header_label.setSelectable_(False)
        self._header_label.setFont_(NSFont.systemFontOfSize_(11))
        self._header_label.setTextColor_(NSColor.secondaryLabelColor())
        content.addSubview_(self._header_label)

        self._close_btn = NSButton.alloc().initWithFrame_(
            NSMakeRect(FLOATING_WIDTH - 26, initial_h - 24, 18, 18)
        )
        self._close_btn.setTitle_("✕")
        self._close_btn.setBordered_(False)
        self._close_btn.setFont_(NSFont.systemFontOfSize_(11))
        self._close_btn.setAlignment_(NSTextAlignmentCenter)
        self._close_btn.setTarget_(self)
        self._close_btn.setAction_(b"closeClicked:")
        content.addSubview_(self._close_btn)

        # Container that holds the row views (rebuilt on each payload).
        self._rows_container = NSView.alloc().initWithFrame_(
            NSMakeRect(0, FLOATING_PADDING, FLOATING_WIDTH, initial_h - FLOATING_HEADER_H - FLOATING_PADDING)
        )
        content.addSubview_(self._rows_container)

        self.applyTheme_(get_theme())

        return self

    @objc.python_method
    def applyTheme_(self, theme: str):
        """Apply 'system' / 'light' / 'dark' to the floating window's
        appearance and content background. Called on init and when the
        user changes the menu setting."""
        if theme == "light":
            self.window.setAppearance_(
                NSAppearance.appearanceNamed_("NSAppearanceNameAqua")
            )
        elif theme == "dark":
            self.window.setAppearance_(
                NSAppearance.appearanceNamed_("NSAppearanceNameDarkAqua")
            )
        else:
            # Inherit system appearance.
            self.window.setAppearance_(None)

        # Resolve effective appearance to pick a matching content fill.
        is_dark = True
        try:
            eff = self.window.effectiveAppearance()
            matched = eff.bestMatchFromAppearancesWithNames_(
                ["NSAppearanceNameAqua", "NSAppearanceNameDarkAqua"]
            )
            is_dark = (matched == "NSAppearanceNameDarkAqua")
        except Exception:
            pass
        if is_dark:
            bg = NSColor.colorWithCalibratedWhite_alpha_(0.06, 0.96)
        else:
            bg = NSColor.colorWithCalibratedWhite_alpha_(0.97, 0.96)
        self._content.layer().setBackgroundColor_(bg.CGColor())
        # Force the bar views to repaint with the new effective appearance.
        for sub in list(self._rows_container.subviews()):
            sub.setNeedsDisplay_(True)
            for inner in list(sub.subviews()):
                inner.setNeedsDisplay_(True)

    @objc.python_method
    def show(self):
        self.window.orderFrontRegardless()

    @objc.python_method
    def close(self):
        self.window.orderOut_(None)

    def closeClicked_(self, sender):
        # Tell MenuBarApp the user dismissed the window so it can flip the
        # menu checkbox + persisted preference.
        try:
            if self._callback is not None:
                self._callback()
        except Exception:
            log("floating-window callback failed", exc=True)

    def applyPayload_(self, payload):
        """Rebuild the stacked rows for the latest payload."""
        # Drop existing row views.
        for sub in list(self._rows_container.subviews()):
            sub.removeFromSuperview()

        status = (payload or {}).get("status")
        if status == "ok":
            rows = payload.get("rows") or []
        else:
            rows = []

        if not rows:
            msg = "No data."
            if status == "login_required":
                msg = "Session expired — sign out & relaunch."
            elif status == "error":
                msg = (payload.get("message") or "Error fetching usage")[:120]
            elif status is None:
                msg = "Loading…"
            self._setSingleMessage(msg)
            return

        # Lay out rows top-to-bottom inside the container (Cocoa is
        # bottom-origin, so build from the bottom up but display in the
        # natural reading order by reversing).
        rows_to_render = rows[: 6]
        new_h = FLOATING_HEADER_H + FLOATING_ROW_H * len(rows_to_render) + FLOATING_PADDING
        self._resizeWindow(new_h)

        container_h = new_h - FLOATING_HEADER_H - FLOATING_PADDING
        for i, r in enumerate(rows_to_render):
            row_view = _make_row_view(
                str(r.get("label", "")),
                float(r.get("percent", 0.0)),
                str(r.get("resets_in", "")),
                width=FLOATING_WIDTH,
            )
            y = container_h - (i + 1) * FLOATING_ROW_H
            row_view.setFrame_(NSMakeRect(0, y, FLOATING_WIDTH, FLOATING_ROW_H))
            self._rows_container.addSubview_(row_view)

    @objc.python_method
    def _setSingleMessage(self, text):
        self._resizeWindow(FLOATING_HEADER_H + FLOATING_ROW_H + FLOATING_PADDING)
        msg = NSTextField.alloc().initWithFrame_(
            NSMakeRect(14, 8, FLOATING_WIDTH - 28, FLOATING_ROW_H - 12)
        )
        msg.setStringValue_(text)
        msg.setBezeled_(False)
        msg.setDrawsBackground_(False)
        msg.setEditable_(False)
        msg.setSelectable_(False)
        msg.setFont_(NSFont.systemFontOfSize_(11))
        msg.setTextColor_(NSColor.secondaryLabelColor())
        self._rows_container.addSubview_(msg)

    @objc.python_method
    def _resizeWindow(self, new_h):
        # Anchor the window to its current top edge so it grows downward.
        frame = self.window.frame()
        old_h = frame.size.height
        new_y = frame.origin.y + (old_h - new_h)
        self.window.setFrame_display_(
            NSMakeRect(frame.origin.x, new_y, FLOATING_WIDTH, new_h), True
        )
        # Re-place header + close button at the new top edge.
        self._header_label.setFrame_(NSMakeRect(14, new_h - 22, 200, 16))
        self._close_btn.setFrame_(NSMakeRect(FLOATING_WIDTH - 26, new_h - 24, 18, 18))
        self._rows_container.setFrame_(
            NSMakeRect(0, FLOATING_PADDING, FLOATING_WIDTH, new_h - FLOATING_HEADER_H - FLOATING_PADDING)
        )
        # Match the rounded background to the new size.
        self._content.setFrame_(NSMakeRect(0, 0, FLOATING_WIDTH, new_h))


class MenuBarApp(NSObject):
    """Owns the NSStatusItem + NSMenu and renders incoming payloads."""

    # PyObjC initializer convention: classmethod alloc + custom init.
    def initWithClient_(self, client):
        self = objc.super(MenuBarApp, self).init()
        if self is None:
            return None
        self.client = client
        self.last_payload = None  # cached so toggles don't trigger a fetch
        self.floating_window = None
        self.status_item = NSStatusBar.systemStatusBar().statusItemWithLength_(
            NSVariableStatusItemLength
        )
        self.status_item.button().setTitle_("Claude …")
        self.status_item.button().setFont_(
            NSFont.monospacedDigitSystemFontOfSize_weight_(13, NSFontWeightRegular)
        )
        self.menu = NSMenu.alloc().init()
        self.menu.setAutoenablesItems_(False)
        self.status_item.setMenu_(self.menu)
        self._renderLoading()
        # Restore the floating window if the user had it open last session.
        if get_show_floating():
            self._openFloatingWindow()
        return self

    # -- payload entry points (called from any thread) -------------------

    def applyPayload_(self, payload):
        """Main-thread entry point. payload is the dict from get_usage_payload."""
        self.last_payload = payload
        self._renderPayload(payload)
        if self.floating_window is not None:
            self.floating_window.applyPayload_(payload)

    # -- rendering -------------------------------------------------------

    @objc.python_method
    def _renderLoading(self):
        self.status_item.button().setTitle_("Claude …")
        self.menu.removeAllItems()
        header = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_("Loading…", None, "")
        header.setEnabled_(False)
        self.menu.addItem_(header)
        self._appendStaticItems()

    @objc.python_method
    def _renderPayload(self, payload):
        status = (payload or {}).get("status")
        if status == "login_required":
            self.status_item.button().setTitle_("Claude !")
            self.menu.removeAllItems()
            self._addDisabledHeader("Session expired — sign out & relaunch")
            self._appendStaticItems()
            return
        if status == "error":
            self.status_item.button().setTitle_("Claude ⚠︎")
            self.menu.removeAllItems()
            self._addDisabledHeader("Error fetching usage")
            msg = (payload.get("message") or "")[:240]
            if msg:
                detail = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(msg, None, "")
                detail.setEnabled_(False)
                self.menu.addItem_(detail)
            self._appendStaticItems()
            return
        if status != "ok":
            self.status_item.button().setTitle_("Claude ?")
            self.menu.removeAllItems()
            self._addDisabledHeader(f"Unknown status: {status}")
            self._appendStaticItems()
            return

        rows = payload.get("rows") or []
        rows_by_key = {r.get("key", ""): r for r in rows if r.get("key")}

        # --- status-bar title ---
        five = rows_by_key.get("five_hour")
        parts = []
        if five is not None:
            parts.append(f"Claude {int(round(float(five['percent'])))}%")
        else:
            parts.append("Claude —")
        for k in get_banner_extras():
            row = rows_by_key.get(k)
            if not row:
                continue
            short = BANNER_EXTRA_SHORT_LABELS.get(k, k)
            parts.append(f"{short} {int(round(float(row['percent'])))}%")
        self.status_item.button().setTitle_(" · ".join(parts))

        # --- menu ---
        self.menu.removeAllItems()
        self._addDisabledHeader("Plan usage")
        if not rows:
            empty = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                "No usage data returned.", None, ""
            )
            empty.setEnabled_(False)
            self.menu.addItem_(empty)
        else:
            for r in rows:
                row_item = NSMenuItem.alloc().init()
                row_item.setView_(
                    _make_row_view(
                        str(r.get("label", "")),
                        float(r.get("percent", 0.0)),
                        str(r.get("resets_in", "")),
                    )
                )
                self.menu.addItem_(row_item)
        self._appendStaticItems()

    @objc.python_method
    def _addDisabledHeader(self, text):
        item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(text, None, "")
        item.setEnabled_(False)
        self.menu.addItem_(item)

    def _appendStaticItems(self):
        """Separator + 'Show in banner' toggles + actions + Quit. Always last."""
        self.menu.addItem_(NSMenuItem.separatorItem())

        # "Show in banner" header + toggles
        show_header = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_("Show in banner", None, "")
        show_header.setEnabled_(False)
        self.menu.addItem_(show_header)
        extras = set(get_banner_extras())
        for key, label in BANNER_EXTRA_OPTIONS:
            item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                f"  {label}", b"toggleBannerExtra:", ""
            )
            item.setTarget_(self)
            item.setRepresentedObject_(key)
            item.setState_(NSControlStateValueOn if key in extras else NSControlStateValueOff)
            self.menu.addItem_(item)

        self.menu.addItem_(NSMenuItem.separatorItem())

        # Floating window toggle (a checkbox menu item, persisted to config).
        floating_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
            "Show floating window", b"toggleFloatingWindow:", ""
        )
        floating_item.setTarget_(self)
        floating_item.setState_(
            NSControlStateValueOn if self.floating_window is not None else NSControlStateValueOff
        )
        self.menu.addItem_(floating_item)

        # Theme submenu (System / Light / Dark) for the floating window.
        theme_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
            "Floating window theme", None, ""
        )
        theme_submenu = NSMenu.alloc().init()
        theme_submenu.setAutoenablesItems_(False)
        current_theme = get_theme()
        for key, label in (("system", "System"), ("light", "Light"), ("dark", "Dark")):
            sub = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                label, b"setTheme:", ""
            )
            sub.setTarget_(self)
            sub.setRepresentedObject_(key)
            sub.setState_(NSControlStateValueOn if key == current_theme else NSControlStateValueOff)
            theme_submenu.addItem_(sub)
        theme_item.setSubmenu_(theme_submenu)
        self.menu.addItem_(theme_item)

        self.menu.addItem_(NSMenuItem.separatorItem())

        endpoint = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
            "Set endpoint…", b"setEndpoint:", ""
        )
        endpoint.setTarget_(self)
        self.menu.addItem_(endpoint)

        sign_out = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
            "Sign out", b"signOut:", ""
        )
        sign_out.setTarget_(self)
        self.menu.addItem_(sign_out)

        self.menu.addItem_(NSMenuItem.separatorItem())

        quit_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
            f"Quit {APP_NAME}", b"quit:", "q"
        )
        quit_item.setTarget_(self)
        self.menu.addItem_(quit_item)

    # -- menu actions ----------------------------------------------------

    def toggleBannerExtra_(self, sender):
        key = sender.representedObject()
        if not key:
            return
        extras = get_banner_extras()
        if key in extras:
            extras.remove(key)
        else:
            extras.append(key)
        set_banner_extras(extras)
        # Re-render the title from cache; no need to refetch.
        if self.last_payload is not None:
            self._renderPayload(self.last_payload)

    def toggleFloatingWindow_(self, sender):
        if self.floating_window is None:
            self._openFloatingWindow()
            set_show_floating(True)
        else:
            self.floating_window.close()
            self.floating_window = None
            set_show_floating(False)
        # Re-render so the checkbox state in the menu refreshes.
        if self.last_payload is not None:
            self._renderPayload(self.last_payload)

    @objc.python_method
    def _openFloatingWindow(self):
        self.floating_window = FloatingWindow.alloc().initWithToggleCallback_(
            self._floatingClosedFromButton
        )
        self.floating_window.show()
        if self.last_payload is not None:
            self.floating_window.applyPayload_(self.last_payload)

    @objc.python_method
    def _floatingClosedFromButton(self):
        # User clicked the × on the floating window itself.
        if self.floating_window is not None:
            self.floating_window.close()
            self.floating_window = None
        set_show_floating(False)
        if self.last_payload is not None:
            self._renderPayload(self.last_payload)

    def setTheme_(self, sender):
        key = sender.representedObject()
        if key not in THEME_VALUES:
            return
        set_theme(key)
        if self.floating_window is not None:
            self.floating_window.applyTheme_(key)
        if self.last_payload is not None:
            self._renderPayload(self.last_payload)

    @objc.python_method
    def _fetchAndApply(self):
        payload = _build_payload(self.client)
        self.performSelectorOnMainThread_withObject_waitUntilDone_(
            b"applyPayload:", payload, False
        )

    def setEndpoint_(self, sender):
        current = load_config().get("usage_endpoint", "")
        alert = NSAlert.alloc().init()
        alert.setMessageText_("Set usage endpoint")
        alert.setInformativeText_(
            "Paste the usage URL from claude.ai DevTools (Network tab → fetch "
            "containing 'usage', 'quota' or 'rate'). Leave empty to clear."
        )
        alert.addButtonWithTitle_("Save")
        alert.addButtonWithTitle_("Cancel")
        field = NSTextField.alloc().initWithFrame_(NSMakeRect(0, 0, 360, 24))
        field.setStringValue_(current)
        alert.setAccessoryView_(field)
        response = alert.runModal()
        if response != NSAlertFirstButtonReturn:
            return
        url = str(field.stringValue() or "").strip()
        cfg = load_config()
        if url:
            if not url.startswith("http"):
                err = NSAlert.alloc().init()
                err.setMessageText_("URL must start with http(s)://")
                err.runModal()
                return
            cfg["usage_endpoint"] = url
            save_config(cfg)
            log(f"manual endpoint set: {url}")
        else:
            cfg.pop("usage_endpoint", None)
            save_config(cfg)
            log("manual endpoint cleared")
        threading.Thread(target=self._fetchAndApply, daemon=True).start()

    def signOut_(self, sender):
        clear_cookies()
        cfg = load_config()
        cfg.pop("org_uuid", None)
        cfg.pop("usage_endpoint", None)
        save_config(cfg)
        log("signed out via menu; relaunching")
        # Relaunch the process so the login window flow runs from scratch.
        os.execv(sys.executable, [sys.executable, *sys.argv])

    def quit_(self, sender):
        os._exit(0)


def _build_payload(client: "ClaudeClient") -> dict:
    """Pull rows from the Claude client and shape them for the menu-bar UI."""
    try:
        rows = client.fetch_usage()
        return {
            "status": "ok",
            "fetched_at": int(time.time()),
            "rows": [
                {
                    "label": r.label,
                    "percent": r.percent,
                    "resets_in": r.resets_in,
                    "key": r.key,
                }
                for r in rows
            ],
        }
    except PermissionError:
        return {"status": "login_required"}
    except Exception as e:
        log(f"fetch_usage failed: {e}", exc=True)
        return {"status": "error", "message": str(e)}


# ---------------------------------------------------------------------------
# App orchestration
# ---------------------------------------------------------------------------

class App:
    def __init__(self) -> None:
        self.client = ClaudeClient()
        self.menu_app: Optional[MenuBarApp] = None
        self._stop = threading.Event()

    def _poll_loop(self) -> None:
        # Brief delay so the menu bar item is on screen before the first push.
        time.sleep(1.0)
        while not self._stop.is_set():
            try:
                payload = _build_payload(self.client)
                if self.menu_app is not None:
                    self.menu_app.performSelectorOnMainThread_withObject_waitUntilDone_(
                        b"applyPayload:", payload, False
                    )
            except Exception:
                log("poll loop iteration crashed", exc=True)
            self._stop.wait(REFRESH_SECONDS)

    def run(self) -> None:
        # 1. If we don't have cookies yet, run the paste-based login window first.
        if "sessionKey" not in load_cookies():
            log("no sessionKey on disk, opening paste-based login window")
            captured = run_login_window()
            if not captured:
                log("login cancelled or window closed without a session; exiting")
                sys.exit(1)
            self.client = ClaudeClient()  # reload cookies into session

        # 2. Boot a Cocoa app with a status-bar item and no Dock icon.
        ns_app = NSApplication.sharedApplication()
        ns_app.setActivationPolicy_(NSApplicationActivationPolicyAccessory)
        self.menu_app = MenuBarApp.alloc().initWithClient_(self.client)

        threading.Thread(target=self._poll_loop, daemon=True).start()
        ns_app.run()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    log(f"--- {APP_NAME} starting (pid={os.getpid()}) ---")
    try:
        App().run()
    except SystemExit:
        raise
    except Exception:
        log("fatal", exc=True)
        raise


if __name__ == "__main__":
    main()
