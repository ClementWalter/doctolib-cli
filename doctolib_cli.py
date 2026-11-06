#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "click==8.3.3",
#     "requests==2.34.2",
#     "pycryptodome==3.23.0",
# ]
#
# [tool.uv]
# exclude-newer = "2026-10-27T00:00:00Z"
# ///
"""doctolib-cli — read a Doctolib patient account and search practitioners' open slots.

Doctolib has no public API (its Partner API is for medical software vendors only).
This CLI talks to the JSON API the patient website itself uses:

- public reads (search, practitioner profile, open slots) need no login;
- account reads (patients, appointments, documents) reuse the session of a
  signed-in Chromium browser (Chrome, Arc, Brave, Edge, Dia), whose cookie store
  is decrypted with the macOS keychain key.

Read-only: it never books or cancels. Downloading a document marks it as read
on Doctolib, as opening it on the website does.
"""

from __future__ import annotations

import hashlib
import hmac
import json as jsonlib
import logging
import mimetypes
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unicodedata
from datetime import date, timedelta
from pathlib import Path
from urllib.parse import urlparse

import click
import requests

log = logging.getLogger("doctolib")

HOSTS = {"fr": "https://www.doctolib.fr", "de": "https://www.doctolib.de", "it": "https://www.doctolib.it"}
# Doctolib's bot shield (DataDome) answers 403 to non-browser User-Agents, so the
# tool cannot name itself here; Nominatim, which asks for a named client, gets NOMINATIM_UA.
BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
NOMINATIM_UA = "doctolib-cli (+https://github.com/ClementWalter/doctolib-cli)"
TIMEOUT = 30
MAX_RETRIES = 3
MAX_PAGES = 100
# availabilities.json answers about two weeks per call and 400s below limit=2.
WINDOW_DAYS = 15
CACHE_DIR = Path.home() / ".cache" / "doctolib-cli"
SESSION_COOKIE = "_doctolib_session"

# (label, browser root under $HOME, keychain service holding the cookie key)
BROWSERS = [
    ("chrome", "Library/Application Support/Google/Chrome", "Chrome Safe Storage"),
    ("arc", "Library/Application Support/Arc/User Data", "Arc Safe Storage"),
    ("brave", "Library/Application Support/BraveSoftware/Brave-Browser", "Brave Safe Storage"),
    ("edge", "Library/Application Support/Microsoft Edge", "Microsoft Edge Safe Storage"),
    ("dia", "Library/Application Support/Dia/User Data", "Dia Safe Storage"),
]


def login_hint(country: str) -> str:
    return (f"Sign in at {HOSTS[country]} in Chrome (or Arc, Brave, Edge, Dia), then retry. "
            "If macOS asks to let `security` use the browser's \"Safe Storage\" key, click Always Allow.")


def env_value(name: str) -> str:
    """An env var, treating an unfilled extension setting (`${user_config.x}`) as unset."""
    value = os.environ.get(name, "").strip()
    return "" if value.startswith("${") else value


def default_out() -> Path:
    """$DOCTOLIB_DOWNLOAD_DIR (the extension's Download folder setting), else ~/Downloads/doctolib."""
    value = env_value("DOCTOLIB_DOWNLOAD_DIR")
    return Path(value).expanduser() if value else Path.home() / "Downloads" / "doctolib"


# --------------------------------------------------------------------------- #
# Browser session (Chromium cookie store, macOS keychain)
# --------------------------------------------------------------------------- #
def keychain_key(service: str) -> bytes | None:
    """AES key Chromium derives on macOS: PBKDF2-SHA1(keychain secret, 'saltysalt', 1003)."""
    try:
        proc = subprocess.run(["security", "find-generic-password", "-w", "-s", service],
                              capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    return hashlib.pbkdf2_hmac("sha1", proc.stdout.strip().encode(), b"saltysalt", 1003, 16)


def decrypt_cookie(encrypted: bytes, key: bytes, domain_hashed: bool) -> str | None:
    """Decrypt a Chromium `v10` AES-128-CBC cookie; DB version >= 24 prefixes sha256(host)."""
    from Crypto.Cipher import AES

    if encrypted[:3] not in (b"v10", b"v11") or len(encrypted) < 19:
        return None
    try:
        plain = AES.new(key, AES.MODE_CBC, iv=b" " * 16).decrypt(encrypted[3:])
        plain = plain[: -plain[-1]]
        return (plain[32:] if domain_hashed else plain).decode()
    except (ValueError, IndexError, UnicodeDecodeError):
        return None


def read_store(store: Path, host: str) -> tuple[list[tuple[str, bytes, str]], int, bool]:
    """(rows of (name, encrypted, plain value), session last access, domain_hashed) for `host`.

    Reads a copy: the live database is locked while the browser runs.
    """
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td) / "Cookies"
        try:
            shutil.copy2(store, tmp)
            con = sqlite3.connect(f"file:{tmp}?immutable=1", uri=True)
            rows = con.execute("SELECT name, encrypted_value, value, last_access_utc FROM cookies "
                               "WHERE host_key = ? OR host_key = ?", (host, "." + host.removeprefix("www."))).fetchall()
            meta = dict(con.execute("SELECT key, value FROM meta").fetchall())
            con.close()
        except (OSError, sqlite3.Error):
            return [], 0, False
    session = [r for r in rows if r[0] == SESSION_COOKIE]
    last = max((r[3] for r in session), default=0)
    return [(n, bytes(e), v) for n, e, v, _ in rows], last, int(meta.get("version", 0) or 0) >= 24


def browser_sessions(country: str, home: Path | None = None):
    """Yield (source, cookie header) per browser profile holding a Doctolib session, most recent first."""
    home = home or Path.home()
    host = urlparse(HOSTS[country]).netloc
    found = []
    for label, root, service in BROWSERS:
        base = home / root
        if not base.is_dir():
            continue
        for store in sorted(base.glob("*/Cookies")):
            rows, last, hashed = read_store(store, host)
            if last:
                found.append((last, f"{label}:{store.parent.name}", rows, service, hashed))
    keys: dict[str, bytes | None] = {}
    for _, source, rows, service, hashed in sorted(found, key=lambda f: -f[0]):
        # Only stores holding the session reach this point, so a signed-out
        # browser never triggers a keychain prompt.
        if service not in keys:
            keys[service] = keychain_key(service)
        key = keys[service]
        if not key:
            log.warning("%s: no access to the %r keychain item", source, service)
            continue
        jar = {}
        for name, enc, plain in rows:
            value = plain or decrypt_cookie(enc, key, hashed)
            if value:
                jar[name] = value
        if SESSION_COOKIE in jar:
            yield source, "; ".join(f"{k}={v}" for k, v in sorted(jar.items()))


# --------------------------------------------------------------------------- #
# HTTP client
# --------------------------------------------------------------------------- #
class Doctolib:
    """Client over the patient website's JSON API, anonymous or with a browser session."""

    def __init__(self, country: str = "fr", session: requests.Session | None = None):
        self.country = country
        self.base = HOSTS[country]
        self.s = session or requests.Session()
        self.s.headers.update({"User-Agent": BROWSER_UA, "Accept": "application/json",
                               "Accept-Language": f"{country}-{country.upper()},{country};q=0.9",
                               "Referer": self.base + "/"})
        self.source = "anonymous"
        self._cookie: str | None = None

    def _send(self, method: str, url: str, **kw) -> requests.Response:
        """One request with bounded retries on 429/5xx, honoring Retry-After."""
        for attempt in range(MAX_RETRIES + 1):
            r = self.s.request(method, url, timeout=TIMEOUT, allow_redirects=False, **kw)
            if r.status_code != 429 and r.status_code < 500 or attempt == MAX_RETRIES:
                return r
            wait = r.headers.get("Retry-After", "")
            delay = float(wait) if wait.isdigit() else 2 ** attempt
            log.warning("%s %s → %s, retrying in %.0fs", method, url, r.status_code, delay)
            time.sleep(delay)
        return r

    def request(self, method: str, path: str, auth: bool = False, **kw) -> requests.Response:
        headers = kw.pop("headers", {})
        if auth:
            headers["Cookie"] = self.cookie()
        r = self._send(method, self.base + path, headers=headers, **kw)
        if auth and r.status_code in (301, 302, 401):
            raise click.ClickException(f"{r.status_code} — the Doctolib session from {self.source} is "
                                       f"signed out or expired. {login_hint(self.country)}")
        if r.status_code == 403:
            raise click.ClickException("403 — Doctolib's bot shield refused the request; open the site "
                                       "once in the browser, then retry in a minute.")
        if r.status_code == 404 and path.startswith("/v2/account/documents/"):
            raise click.ClickException(f"404 — no document {path.rsplit('/', 1)[-1]} on this account; "
                                       "list ids with `doctolib documents`.")
        if r.status_code not in (200, 206):
            raise click.ClickException(f"{r.status_code} — {method} {path} failed: {r.text[:200]}")
        return r

    def get(self, path: str, params: dict | None = None, auth: bool = False):
        return self.request("GET", path, auth=auth, params=params).json()

    def cookie(self) -> str:
        """The account's Cookie header: $DOCTOLIB_COOKIE, else the freshest browser session."""
        if self._cookie is None:
            env = env_value("DOCTOLIB_COOKIE")
            if env:
                self.source, self._cookie = "env", env
            else:
                found = next(browser_sessions(self.country), None)
                if not found:
                    raise click.ClickException(f"No Doctolib session in any local browser. {login_hint(self.country)}")
                self.source, self._cookie = found
        return self._cookie


# --------------------------------------------------------------------------- #
# Public reads: search, profile, slots
# --------------------------------------------------------------------------- #
def geocode(city: str, country: str) -> dict:
    """Doctolib `place` for a city: its bounding box is what scopes the search.

    Without a viewport the search silently returns nationwide results.
    Cached on disk: a city's bounding box does not change.
    """
    cache = CACHE_DIR / "places.json"
    key = f"{country}:{city.strip().lower()}"
    try:
        known = jsonlib.loads(cache.read_text())
    except (OSError, ValueError):
        known = {}
    if key not in known:
        r = requests.get("https://nominatim.openstreetmap.org/search", timeout=TIMEOUT,
                         params={"q": city, "countrycodes": country, "format": "json", "limit": 1},
                         headers={"User-Agent": NOMINATIM_UA})
        r.raise_for_status()
        hits = r.json()
        if not hits:
            raise click.BadParameter(f"OpenStreetMap does not know {city!r}; try a city name, e.g. --city Lyon.")
        g = hits[0]
        south, north, west, east = (float(x) for x in g["boundingbox"])
        known[key] = {
            "name": city.strip().title(), "slug": slugify(city), "country": country, "type": "locality",
            "viewport": {"northeast": {"lat": north, "lng": east}, "southwest": {"lat": south, "lng": west}},
            "gpsPoint": {"lat": float(g["lat"]), "lng": float(g["lon"])},
        }
        try:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            cache.write_text(jsonlib.dumps(known, indent=1, sort_keys=True))
        except OSError:
            pass
    return known[key]


def slugify(text: str) -> str:
    ascii_text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "-", ascii_text.lower()).strip("-")


def normalize_provider(h: dict, base: str) -> dict:
    """A search hit, with the three ids availabilities.json needs."""
    motive = h.get("matchedVisitMotive") or {}
    booking = h.get("onlineBooking") or {}
    loc = h.get("location") or {}
    link = (h.get("link") or "").split("?")[0]
    spec = h.get("speciality")
    return {
        "name": " ".join(" ".join(p.split()) for p in (h.get("firstName"), h.get("name")) if p and p.strip()),
        "slug": link.rstrip("/").split("/")[-1] if link else None,
        "url": base + link if link else None,
        "speciality": spec.get("name") if isinstance(spec, dict) else spec,
        "address": loc.get("address"),
        "zipcode": loc.get("zipcode"),
        "city": loc.get("city"),
        "practice_id": (h.get("references") or {}).get("practiceId"),
        "bookable_online": "onlineBooking" in (h.get("services") or []),
        "telehealth": booking.get("telehealth"),
        "motive_id": motive.get("visitMotiveId"),
        "motive": (motive.get("name") or "").strip() or None,
        "agenda_ids": booking.get("agendaIds") or motive.get("agendaIds") or [],
        "new_patients": motive.get("allowNewPatients"),
    }


def search(client: Doctolib, keyword: str, place: dict, page: int = 0, telehealth=None, sector=None) -> dict:
    filters: dict = {}
    if telehealth is not None:
        filters["telehealth"] = telehealth
    if sector:
        filters["insuranceSector"] = sector
    r = client.request("POST", "/patient-health-search/api/v1/hcp/search", params={"page": page},
                       json={"keyword": keyword, "location": {"place": place}, "filters": filters})
    body = r.json()
    return {"total": body.get("total"),
            "providers": [normalize_provider(h, client.base) for h in body.get("healthcareProviders", [])]}


def profile_slug(value: str) -> str:
    """Accept a slug or any doctolib URL to a practitioner's page."""
    path = urlparse(value).path if "://" in value or value.startswith("www.") else value
    return path.rstrip("/").split("/")[-1].split("?")[0]


def normalize_profile(data: dict) -> dict:
    """info.json → profile, places and motives, each motive with the practices and agendas offering it."""
    agendas = [a for a in data.get("agendas", []) if not a.get("booking_temporary_disabled")]
    places = {pid: p for p in data.get("places", []) for pid in p.get("practice_ids", [])}
    motives = []
    for m in data.get("visit_motives", []):
        offers: dict[int, list[int]] = {}
        for a in agendas:
            for pid, ids in (a.get("visit_motive_ids_by_practice_id") or {}).items():
                if m["id"] in ids:
                    offers.setdefault(int(pid), []).append(a["id"])
        motives.append({"id": m["id"], "name": (m.get("name") or "").strip(), "telehealth": m.get("telehealth"),
                        "new_patients_restricted": bool(m.get("new_patient_restrictions")),
                        "practices": {pid: sorted(ids) for pid, ids in sorted(offers.items())}})
    prof = data.get("profile") or {}
    spec = prof.get("speciality")
    return {
        "id": prof.get("id"),
        "name": prof.get("name_with_title"),
        "speciality": prof.get("subtitle") or (spec.get("name") if isinstance(spec, dict) else spec),
        "places": [{"practice_id": pid, "name": p.get("name"), "address": p.get("address"),
                    "zipcode": p.get("zipcode"), "city": p.get("city"), "phone": p.get("landline_number")}
                   for pid, p in sorted(places.items())],
        "motives": [m for m in motives if m["practices"]],
    }


def pick_motives(motives: list[dict], wanted: str) -> list[dict]:
    """Motives by id or case-insensitive name fragment.

    A name shared by several practices (one motive id each) selects all of them;
    distinct names are ambiguous and listed.
    """
    if wanted.isdigit():
        hits = [m for m in motives if m["id"] == int(wanted)]
    else:
        hits = [m for m in motives if wanted.lower() in (m["name"] or "").lower()]
        exact = [m for m in hits if (m["name"] or "").lower() == wanted.lower()]
        hits = exact or hits
    if hits and len({(m["name"] or "").lower() for m in hits}) == 1:
        return hits
    listing = "; ".join(f"{m['id']} {m['name']}" for m in (hits or motives)[:15])
    raise click.BadParameter(f"{'Ambiguous' if hits else 'Unknown'} motive {wanted!r}. Pass an id or a full name: {listing}")


def availabilities(client: Doctolib, motive_id: int, agenda_ids: list[int], practice_id: int,
                   start: date, days: int) -> dict:
    """Slots over `days` days, walked in ≤15-day windows; keeps Doctolib's `reason` when empty."""
    slots: list[str] = []
    reason = next_slot = None
    cursor, remaining = start, days
    while remaining > 0:
        chunk = min(remaining, WINDOW_DAYS)
        body = client.get("/availabilities.json", {
            "start_date": cursor.isoformat(), "visit_motive_ids": motive_id,
            "agenda_ids": "-".join(str(a) for a in agenda_ids), "practice_ids": practice_id,
            "limit": max(2, chunk)})
        for day in body.get("availabilities", []):
            slots.extend(s if isinstance(s, str) else s.get("start_date", "") for s in day.get("slots", []))
        reason = reason or body.get("reason")
        next_slot = next_slot or body.get("next_slot")
        cursor += timedelta(days=chunk)
        remaining -= chunk
    slots = sorted({s for s in slots if s and s[:10] < (start + timedelta(days=days)).isoformat()})
    return {"practice_id": practice_id, "slots": slots, "next_slot": None if slots else next_slot,
            "reason": None if slots else reason}


# --------------------------------------------------------------------------- #
# Account reads: patients, appointments, documents
# --------------------------------------------------------------------------- #
def full_name(p: dict) -> str:
    return " ".join(" ".join(x.split()) for x in (p.get("first_name"), p.get("last_name")) if x and x.strip())


def normalize_patient(p: dict) -> dict:
    return {"id": p["id"], "name": full_name(p), "kind": p.get("kind"), "birthdate": p.get("birthdate"),
            "email": p.get("email"), "phone": p.get("phone_number"),
            "city": p.get("city"), "zipcode": p.get("zipcode")}


def normalize_appointment(a: dict) -> dict:
    prof = a.get("profile") or {}
    spec = prof.get("speciality")
    status = ("canceled" if a.get("canceled") else "no_show" if a.get("no_show")
              else "past" if a.get("past") else "confirmed" if a.get("confirmed") else "pending")
    return {
        "id": a.get("id"),
        "start": a.get("start_date"),
        "end": a.get("end_date"),
        "status": status,
        "practitioner": prof.get("name_with_title"),
        "speciality": spec.get("name") if isinstance(spec, dict) else spec,
        "motive": (a.get("visit_motive") or {}).get("name"),
        "patient": full_name(a.get("patient") or {}),
        "practice_id": (a.get("practice") or {}).get("id"),
        "profile_url": prof.get("link"),
    }


def fetch_appointments(client: Doctolib, past: bool) -> list[dict]:
    """Upcoming (one page) or the whole past history (cursor pagination, capped)."""
    if not past:
        data = client.get("/account/appointments.json", {"page": 0}, auth=True).get("data") or {}
        return [normalize_appointment(a) for a in data.get("confirmed", []) + data.get("pending", [])]
    out, params = [], {"page": 1, "past": "true"}
    for _ in range(MAX_PAGES):
        data = client.get("/account/appointments.json", params, auth=True).get("data") or {}
        out += [normalize_appointment(a) for a in data.get("done", [])]
        if not data.get("has_next_page"):
            return out
        if data.get("next_cursor"):
            params["cursor"] = data["next_cursor"]
        else:
            params["page"] += 1
    raise click.ClickException(f"Past appointments exceed {MAX_PAGES} pages; refusing a partial list.")


def normalize_document(d: dict) -> dict:
    return {
        "id": d.get("id"),
        "created_at": d.get("created_at"),
        "kind": d.get("kind"),
        "title": d.get("title"),
        "patient": full_name(d.get("master_patient") or {}),
        "patient_id": (d.get("master_patient") or {}).get("id"),
        "creator": d.get("creator_label"),
        "content_type": d.get("content_type"),
        "viewed": d.get("viewed_at") is not None,
        "path": urlparse(d.get("url") or d.get("download_path") or "").path,
    }


def fetch_documents(client: Doctolib) -> list[dict]:
    """Every page of the account's documents, newest first."""
    out, seen = [], set()
    for page in range(1, MAX_PAGES + 1):
        body = client.get("/account/documents.json", {"page": page}, auth=True)
        for d in body.get("documents", []):
            if d.get("id") not in seen:
                seen.add(d.get("id"))
                out.append(normalize_document(d))
        if body.get("last_page", True):
            return sorted(out, key=lambda d: (d["created_at"] or "", d["id"]), reverse=True)
    raise click.ClickException(f"Documents exceed {MAX_PAGES} pages; refusing a partial list.")


def filter_by(rows: list[dict], patient=None, kind=None, since=None, unread=False) -> list[dict]:
    """Client-side filters: the list endpoints take none of them."""
    def keep(r):
        if patient and patient.lower() not in (r.get("patient") or "").lower():
            return False
        if kind and r.get("kind") != kind:
            return False
        if since and ((r.get("created_at") or r.get("start") or "")[:10] < since):
            return False
        return not (unread and r.get("viewed"))
    return [r for r in rows if keep(r)]


def document_filename(doc: dict, content_type: str | None) -> str:
    """`<date>_<kind>_<creator>_<id>.<ext>`, safe on macOS and Drive."""
    ext = mimetypes.guess_extension((content_type or doc.get("content_type") or "").split(";")[0].strip()) or ""
    parts = [(doc.get("created_at") or "")[:10], doc.get("kind") or "document", slugify(doc.get("creator") or ""), doc["id"]]
    return "_".join(str(p) for p in parts if p) + (".jpg" if ext == ".jpe" else ext)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
JSON_OPT = click.option("--json", "as_json", is_flag=True, help="Output normalized JSON.")
RAW_OPT = click.option("--raw", is_flag=True, help="Output Doctolib's answer untouched (debugging).")
LIMIT_OPT = click.option("--limit", type=int, default=None, help="Show at most N rows.")


def emit(data, as_json: bool, render) -> None:
    if as_json:
        click.echo(jsonlib.dumps(data, indent=2, ensure_ascii=False))
    else:
        render(data)


def short_time(iso: str | None) -> str:
    """'2026-11-08T09:30:00.000+01:00' → '2026-11-08 09:30+01:00' (local time, zone kept)."""
    if not iso:
        return ""
    m = re.match(r"(\d{4}-\d\d-\d\d)T(\d\d:\d\d)(?::\d\d(?:\.\d+)?)?(Z|[+-]\d\d:\d\d)?", iso)
    return f"{m.group(1)} {m.group(2)}{m.group(3) or ''}" if m else iso


@click.group(context_settings={"help_option_names": ["-h", "--help"]},
             epilog="\b\nExamples:\n  doctolib search dentiste --city Paris\n  doctolib slots carla-bodenreider-fb6ba726-70f1-4579-bf3a-e80d5df947c9 --motive urgence\n  doctolib appointments --past")
@click.option("--country", type=click.Choice(sorted(HOSTS)), default=lambda: env_value("DOCTOLIB_COUNTRY") or "fr",
              show_default="fr", help="Which Doctolib site ($DOCTOLIB_COUNTRY).")
@click.option("--debug", is_flag=True, help="Log HTTP details to stderr.")
@click.pass_context
def cli(ctx, country, debug):
    """Read a Doctolib account and search practitioners' open slots."""
    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO, format="%(message)s", stream=sys.stderr)
    ctx.obj = Doctolib(country)


@cli.command(epilog="\b\nExamples:\n  doctolib connect\n  doctolib connect --json")
@JSON_OPT
@click.pass_obj
def connect(client: Doctolib, as_json):
    """Check that a signed-in browser holds a live Doctolib session."""
    patients = client.get("/account/master_patients.json", auth=True)
    main = next((p for p in patients if p.get("kind") == "main"), patients[0] if patients else {})
    data = {"connected": True, "source": client.source, "account": full_name(main), "patients": len(patients)}
    emit(data, as_json, lambda d: click.echo(f"connected\t{d['account']}\t{d['patients']} patients\t{d['source']}"))


@cli.command(epilog="\b\nExamples:\n  doctolib patients\n  doctolib patients --json")
@JSON_OPT
@RAW_OPT
@click.pass_obj
def patients(client: Doctolib, as_json, raw):
    """The account holder and relatives this account can book for."""
    body = client.get("/account/master_patients.json", auth=True)
    if raw:
        return emit(body, True, None)
    rows = sorted((normalize_patient(p) for p in body), key=lambda p: (p["kind"] != "main", p["name"]))
    emit(rows, as_json, lambda rs: [click.echo(f"{r['id']}\t{r['kind']}\t{r['birthdate']}\t{r['name']}") for r in rs])


@cli.command(epilog="\b\nExamples:\n  doctolib appointments\n  doctolib appointments --past --since 2025-01-01\n  doctolib appointments --past --patient Alice --json")
@click.option("--past", is_flag=True, help="Past appointments (whole history) instead of upcoming ones.")
@click.option("--patient", help="Keep appointments whose patient name contains this text.")
@click.option("--since", metavar="YYYY-MM-DD", help="On or after this date.")
@JSON_OPT
@LIMIT_OPT
@click.pass_obj
def appointments(client: Doctolib, past, patient, since, as_json, limit):
    """Upcoming appointments, or the past ones with --past (newest first)."""
    rows = filter_by(fetch_appointments(client, past), patient=patient, since=since)
    rows = sorted(rows, key=lambda a: (a["start"] or "", a["id"] or ""), reverse=past)[:limit]
    emit(rows, as_json, lambda rs: [click.echo(
        f"{short_time(r['start'])}\t{r['status']}\t{r['patient']}\t{r['practitioner']}\t{r['speciality'] or ''}"
        f"\t{r['motive'] or ''}\t{r['id']}") for r in rs])


@cli.command(epilog="\b\nExamples:\n  doctolib documents --limit 20\n  doctolib documents --unread\n  doctolib documents --patient Alice --kind medicine_prescription --json")
@click.option("--patient", help="Keep documents whose patient name contains this text.")
@click.option("--kind", help="Exact kind, e.g. medicine_prescription, invoice, medical_certificate.")
@click.option("--since", metavar="YYYY-MM-DD", help="Created on or after this date.")
@click.option("--unread", is_flag=True, help="Only documents never opened.")
@JSON_OPT
@LIMIT_OPT
@click.pass_obj
def documents(client: Doctolib, patient, kind, since, unread, as_json, limit):
    """Documents shared by practitioners or uploaded to the account (newest first)."""
    rows = filter_by(fetch_documents(client), patient=patient, kind=kind, since=since, unread=unread)[:limit]
    emit(rows, as_json, lambda rs: [click.echo(
        f"{(r['created_at'] or '')[:10]}\t{r['kind']}\t{r['patient']}\t{r['creator'] or ''}"
        f"\t{'read' if r['viewed'] else 'UNREAD'}\t{r['id']}") for r in rs])


@cli.command(epilog="\b\nExamples:\n  doctolib download 00000000-0000-0000-0000-000000000000\n  doctolib download ID1 ID2 --target-dir ~/Santé\n  doctolib download ID -o ordonnance.pdf --json")
@click.argument("ids", nargs=-1, required=True)
@click.option("--target-dir", type=click.Path(file_okay=False, path_type=Path), default=default_out,
              show_default="~/Downloads/doctolib")
@click.option("-o", "--output", type=click.Path(dir_okay=False, path_type=Path), help="Exact file path (one id only).")
@JSON_OPT
@click.pass_obj
def download(client: Doctolib, ids, target_dir, output, as_json):
    """Save documents by id (from `documents`); marks them as read on Doctolib."""
    if output and len(ids) != 1:
        raise click.BadParameter("-o takes exactly one id, e.g. `doctolib download ID -o ordonnance.pdf`.")
    out = []
    for doc_id in ids:
        if not re.fullmatch(r"[A-Za-z0-9-]+", doc_id):
            raise click.BadParameter(f"{doc_id!r} is not a document id; list them with `doctolib documents`.")
        meta = normalize_document(client.get(f"/v2/account/documents/{doc_id}", auth=True))
        r = client.request("GET", f"/v2/account/documents/{doc_id}", auth=True, headers={"Accept": "*/*"})
        ctype = r.headers.get("content-type", "")
        if "json" in ctype or "html" in ctype:
            raise click.ClickException(f"Document {doc_id}: Doctolib returned {ctype}, not a file.")
        dest = output or target_dir / document_filename(meta, ctype)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(r.content)
        out.append({"id": doc_id, "path": str(dest.resolve()), "bytes": len(r.content)})
    emit(out, as_json, lambda rs: [click.echo(f"{r['id']}\t{r['path']}") for r in rs])


@cli.command("search", epilog="\b\nExamples:\n  doctolib search dentiste --city Paris\n  doctolib search 'médecin généraliste' --city Lyon --telehealth --json\n  doctolib search ophtalmologue --city Bordeaux --page 1")
@click.argument("keyword")
@click.option("--city", required=True, help="City (or district) to search in, geocoded with OpenStreetMap.")
@click.option("--page", type=int, default=0, show_default=True, help="Result page (20 per page).")
@click.option("--telehealth/--no-telehealth", default=None, help="Only video, or only in-person, consultations.")
@click.option("--sector", type=click.Choice(["public", "private"]), help="Insurance sector (DE).")
@JSON_OPT
@RAW_OPT
@LIMIT_OPT
@click.pass_obj
def search_cmd(client: Doctolib, keyword, city, page, telehealth, sector, as_json, raw, limit):
    """Practitioners matching a specialty or name in a city (no login)."""
    place = geocode(city, client.country)
    if raw:
        r = client.request("POST", "/patient-health-search/api/v1/hcp/search", params={"page": page},
                           json={"keyword": keyword, "location": {"place": place}, "filters": {}})
        return emit(r.json(), True, None)
    res = search(client, keyword, place, page, telehealth, sector)
    res["providers"] = res["providers"][:limit]
    emit(res, as_json, lambda d: [log.info("%s results; page %d", d["total"], page)] + [click.echo(
        f"{p['name']}\t{p['speciality'] or ''}\t{p['zipcode'] or ''} {p['city'] or ''}\t{p['motive'] or ''}"
        f"\t{p['slug']}") for p in d["providers"]])



@cli.command(epilog="\b\nExamples:\n  doctolib profile carla-bodenreider-fb6ba726-70f1-4579-bf3a-e80d5df947c9\n  doctolib profile https://www.doctolib.fr/dentiste/paris/carla-bodenreider-fb6ba726-70f1-4579-bf3a-e80d5df947c9 --json")
@click.argument("practitioner")
@JSON_OPT
@RAW_OPT
@click.pass_obj
def profile(client: Doctolib, practitioner, as_json, raw):
    """A practitioner's places and the visit motives bookable online (no login)."""
    slug = profile_slug(practitioner)
    body = client.get("/online_booking/api/slot_selection_funnel/v1/info.json",
                      {"profile_slug": slug, "locale": client.country})
    if raw:
        return emit(body, True, None)
    p = normalize_profile(body.get("data") or {})

    def render(d):
        click.echo(f"{d['name']}\t{d['speciality']}")
        for pl in d["places"]:
            click.echo(f"place\t{pl['practice_id']}\t{pl['name'] or ''}\t{pl['address']}, {pl['zipcode']} {pl['city']}\t{pl['phone'] or ''}")
        for m in d["motives"]:
            flags = ("video " if m["telehealth"] else "") + ("existing-patients-only" if m["new_patients_restricted"] else "")
            click.echo(f"motive\t{m['id']}\t{m['name']}\t{','.join(map(str, m['practices']))}\t{flags.strip()}")
    emit(p, as_json, render)


@cli.command(epilog="\b\nExamples:\n  doctolib slots carla-bodenreider-fb6ba726-70f1-4579-bf3a-e80d5df947c9 --motive urgence\n  doctolib slots carla-bodenreider-fb6ba726-70f1-4579-bf3a-e80d5df947c9 --motive 6089080 --days 30 --json")
@click.argument("practitioner")
@click.option("--motive", required=True, help="Visit motive id or name fragment (see `doctolib profile`).")
@click.option("--days", type=click.IntRange(1, 180), default=14, show_default=True, help="Days to look ahead.")
@click.option("--start", metavar="YYYY-MM-DD", help="First day (default today).")
@click.option("--practice", type=int, help="Only this practice id (see `doctolib profile`).")
@JSON_OPT
@LIMIT_OPT
@click.pass_obj
def slots(client: Doctolib, practitioner, motive, days, start, practice, as_json, limit):
    """Open slots of one practitioner for one visit motive (no login)."""
    body = client.get("/online_booking/api/slot_selection_funnel/v1/info.json",
                      {"profile_slug": profile_slug(practitioner), "locale": client.country})
    chosen = pick_motives(normalize_profile(body.get("data") or {})["motives"], motive)
    first = date.fromisoformat(start) if start else date.today()
    pairs = [(m, pid, ids) for m in chosen for pid, ids in m["practices"].items() if practice in (None, pid)]
    if not pairs:
        offered = sorted({pid for m in chosen for pid in m["practices"]})
        raise click.BadParameter(f"Motive {motive!r} is not offered at practice {practice}; it is at {offered}.")
    res = [availabilities(client, m["id"], ids, pid, first, days) | {"motive_id": m["id"], "motive": m["name"]}
           for m, pid, ids in pairs]
    for r in res:
        r["slots"] = r["slots"][:limit]

    def render(rows):
        for r in rows:
            if not r["slots"]:
                click.echo(f"{r['practice_id']}\tno slot in {days} days\tnext {short_time(r['next_slot']) or '-'}\t{r['reason'] or ''}")
            for s in r["slots"]:
                click.echo(f"{short_time(s)}\t{r['practice_id']}")
    emit(res, as_json, render)


@cli.command(epilog="\b\nExamples:\n  doctolib earliest dentiste --city Paris\n  doctolib earliest dermatologue --city Lyon --days 60 --pages 2 --json")
@click.argument("keyword")
@click.option("--city", required=True, help="City to search in.")
@click.option("--days", type=click.IntRange(1, 180), default=14, show_default=True, help="Days to look ahead.")
@click.option("--pages", type=click.IntRange(1, 5), default=1, show_default=True, help="Search pages to scan (20 each).")
@click.option("--telehealth/--no-telehealth", default=None, help="Only video, or only in-person, consultations.")
@JSON_OPT
@LIMIT_OPT
@click.pass_obj
def earliest(client: Doctolib, keyword, city, days, pages, telehealth, as_json, limit):
    """Search, then rank practitioners by their first open slot (no login)."""
    place = geocode(city, client.country)
    providers = [p for page in range(pages) for p in search(client, keyword, place, page, telehealth)["providers"]]
    rows = []
    for p in providers:
        if not (p["motive_id"] and p["agenda_ids"] and p["practice_id"]):
            continue
        av = availabilities(client, p["motive_id"], p["agenda_ids"], p["practice_id"], date.today(), days)
        if av["slots"]:
            rows.append({k: p[k] for k in ("name", "speciality", "address", "zipcode", "city", "motive", "motive_id",
                                           "practice_id", "slug", "url")}
                        | {"first_slot": av["slots"][0], "slots_in_window": len(av["slots"])})
    rows = sorted(rows, key=lambda r: (r["first_slot"], r["name"]))[:limit]
    log.info("%d of %d practitioners have a slot within %d days", len(rows), len(providers), days)
    emit(rows, as_json, lambda rs: [click.echo(
        f"{short_time(r['first_slot'])}\t{r['name']}\t{r['zipcode'] or ''} {r['city'] or ''}\t{r['motive']}"
        f"\t{r['slots_in_window']} slots\t{r['slug']}") for r in rs])


if __name__ == "__main__":
    cli()
