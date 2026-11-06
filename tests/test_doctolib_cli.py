#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "click==8.3.3",
#     "requests==2.34.2",
#     "pycryptodome==3.23.0",
#     "pytest==9.1.1",
# ]
#
# [tool.uv]
# exclude-newer = "2026-10-27T00:00:00Z"
# ///
"""Offline tests for doctolib-cli: cookie decryption, normalization, pagination, CLI output.

HTTP goes through a stub requests session answering recorded (anonymized) payload shapes.
"""

import hashlib
import importlib.machinery
import importlib.util
import json
import sqlite3
import sys
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

import click
import pytest
import requests
from click.testing import CliRunner
from Crypto.Cipher import AES

KEY = hashlib.pbkdf2_hmac("sha1", b"synthetic-secret", b"saltysalt", 1003, 16)


@pytest.fixture(scope="module")
def m():
    path = Path(__file__).resolve().parents[1] / "doctolib_cli.py"
    loader = importlib.machinery.SourceFileLoader("doctolib_cli", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def encrypt(value: str, host: str | None) -> bytes:
    """A Chromium v10 cookie; `host` set means DB version >= 24 (sha256(host) prefix)."""
    plain = (hashlib.sha256(host.encode()).digest() if host else b"") + value.encode()
    pad = 16 - len(plain) % 16
    return b"v10" + AES.new(KEY, AES.MODE_CBC, iv=b" " * 16).encrypt(plain + bytes([pad]) * pad)


def cookie_store(path: Path, rows: list[tuple[str, str, bytes, int]], version: int = 24) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE meta (key TEXT, value TEXT)")
    con.execute("INSERT INTO meta VALUES ('version', ?)", (str(version),))
    con.execute("CREATE TABLE cookies (host_key TEXT, name TEXT, encrypted_value BLOB, value TEXT, last_access_utc INT)")
    con.executemany("INSERT INTO cookies VALUES (?, ?, ?, '', ?)", rows)
    con.commit()
    con.close()
    return path


# --------------------------------------------------------------------------- #
# Stub HTTP
# --------------------------------------------------------------------------- #
class StubSession:
    """Answers by path; records every call as (method, path, params)."""

    def __init__(self, routes: dict):
        self.routes = routes
        self.headers: dict = {}
        self.calls: list = []

    def request(self, method, url, params=None, headers=None, json=None, **kw):
        path = urlparse(url).path
        self.calls.append((method, path, dict(params or {})))
        answer = self.routes[path]
        status, body, ctype = answer(params or {}) if callable(answer) else answer
        r = requests.Response()
        r.status_code = status
        r.headers["content-type"] = ctype
        r._content = body if isinstance(body, bytes) else json_dumps(body)
        return r


def json_dumps(obj) -> bytes:
    return json.dumps(obj).encode()


def ok(body, ctype="application/json"):
    return (200, body, ctype)


@pytest.fixture
def search_hit():
    return {
        "firstName": " Ada ", "name": "EXAMPLE  ", "link": "/dentiste/paris/ada-example?pid=practice-1",
        "location": {"address": "1 Rue Exemple", "city": "Paris", "zipcode": "75000"},
        "references": {"practiceId": 1}, "services": ["profile", "onlineBooking"],
        "speciality": {"name": "Dentist", "slug": "dentiste"},
        "matchedVisitMotive": {"visitMotiveId": 11, "name": "Urgence ", "agendaIds": [99], "allowNewPatients": True},
        "onlineBooking": {"agendaIds": [101, 102], "telehealth": False},
    }


@pytest.fixture
def info():
    return {"data": {
        "profile": {"id": 5, "name_with_title": "Ada EXAMPLE", "subtitle": "Chirurgien-dentiste"},
        "visit_motives": [
            {"id": 11, "name": "Urgence dentaire", "telehealth": False, "new_patient_restrictions": []},
            {"id": 12, "name": "Urgence dentaire", "telehealth": False, "new_patient_restrictions": []},
            {"id": 13, "name": "Première consultation", "telehealth": False, "new_patient_restrictions": ["x"]},
            {"id": 14, "name": "Hidden", "telehealth": False, "new_patient_restrictions": []},
        ],
        "agendas": [
            {"id": 101, "booking_temporary_disabled": False, "visit_motive_ids_by_practice_id": {"1": [11, 13]}},
            {"id": 102, "booking_temporary_disabled": False, "visit_motive_ids_by_practice_id": {"2": [12]}},
            {"id": 103, "booking_temporary_disabled": True, "visit_motive_ids_by_practice_id": {"1": [14]}},
        ],
        "places": [
            {"practice_ids": [1], "name": "Cabinet A", "address": "1 Rue Exemple", "zipcode": "75000", "city": "Paris"},
            {"practice_ids": [2], "name": "Cabinet B", "address": "2 Rue Exemple", "zipcode": "93000", "city": "Pantin"},
        ],
    }}


@pytest.fixture
def appointment():
    return {
        "id": "00000000-0000-0000-0000-000000000001", "start_date": "2026-01-02T09:30:00.000+01:00",
        "end_date": "2026-01-02T09:45:00.000+01:00", "confirmed": True, "canceled": False, "no_show": False,
        "past": True, "profile": {"name_with_title": "Dr Ada EXAMPLE", "speciality": "Dentiste", "link": "/x/ada"},
        "visit_motive": {"id": 11, "name": "Urgence"}, "practice": {"id": 1},
        "patient": {"first_name": "Bob", "last_name": "Example"},
    }


@pytest.fixture
def document():
    return {
        "id": "00000000-0000-0000-0000-00000000000d", "kind": "medicine_prescription", "title": None,
        "master_patient": {"id": 1, "first_name": "Bob", "last_name": "Example"},
        "created_at": "2026-02-03T10:00:00.000+01:00", "viewed_at": None, "content_type": "application/pdf",
        "creator_label": "Dr Ada Example", "url": "/v2/account/documents/00000000-0000-0000-0000-00000000000d",
    }


def client_with(m, routes, cookie="_doctolib_session=synthetic"):
    c = m.Doctolib("fr", session=StubSession(routes))
    c._cookie, c.source = cookie, "stub"
    return c


# --------------------------------------------------------------------------- #
# Browser session
# --------------------------------------------------------------------------- #
def test_decrypt_cookie_strips_domain_hash(m):
    assert m.decrypt_cookie(encrypt("abc", "www.doctolib.fr"), KEY, True) == "abc"


def test_decrypt_cookie_without_domain_hash(m):
    assert m.decrypt_cookie(encrypt("abc", None), KEY, False) == "abc"


def test_decrypt_cookie_rejects_unencrypted(m):
    assert m.decrypt_cookie(b"plain", KEY, True) is None


@pytest.fixture
def home(tmp_path):
    cookie_store(tmp_path / "Library/Application Support/Dia/User Data/Default/Cookies", [
        ("www.doctolib.fr", "_doctolib_session", encrypt("old", "www.doctolib.fr"), 100)])
    cookie_store(tmp_path / "Library/Application Support/Google/Chrome/Default/Cookies", [
        ("www.doctolib.fr", "_doctolib_session", encrypt("new", "www.doctolib.fr"), 200),
        ("www.doctolib.fr", "ssid", encrypt("s", "www.doctolib.fr"), 200)])
    cookie_store(tmp_path / "Library/Application Support/Arc/User Data/Default/Cookies", [
        ("www.example.com", "_doctolib_session", encrypt("other", "www.example.com"), 300)])
    return tmp_path


def test_browser_sessions_prefers_most_recent_session(m, monkeypatch, home):
    monkeypatch.setattr(m, "keychain_key", lambda service: KEY)
    assert next(m.browser_sessions("fr", home)) == ("chrome:Default", "_doctolib_session=new; ssid=s")


def test_browser_sessions_ignores_other_sites(m, monkeypatch, home):
    monkeypatch.setattr(m, "keychain_key", lambda service: KEY)
    assert [s for s, _ in m.browser_sessions("fr", home)] == ["chrome:Default", "dia:Default"]


def test_browser_sessions_asks_keychain_only_for_stores_with_a_session(m, monkeypatch, home):
    asked = []
    monkeypatch.setattr(m, "keychain_key", lambda service: asked.append(service) or KEY)
    list(m.browser_sessions("fr", home))
    assert asked == ["Chrome Safe Storage", "Dia Safe Storage"]


def test_cookie_prefers_env(m, monkeypatch):
    monkeypatch.setenv("DOCTOLIB_COOKIE", "_doctolib_session=env")
    assert m.Doctolib("fr").cookie() == "_doctolib_session=env"


def test_cookie_ignores_unfilled_extension_setting(m, monkeypatch):
    monkeypatch.setenv("DOCTOLIB_COOKIE", "${user_config.cookie}")
    monkeypatch.setattr(m, "browser_sessions", lambda country: iter(()))
    with pytest.raises(click.ClickException, match="No Doctolib session"):
        m.Doctolib("fr").cookie()


@pytest.mark.parametrize(("value", "expected"), [
    ("", Path.home() / "Downloads" / "doctolib"),
    ("${user_config.download_dir}", Path.home() / "Downloads" / "doctolib"),
    ("/tmp/docs", Path("/tmp/docs")),
])
def test_default_out(m, monkeypatch, value, expected):
    monkeypatch.setenv("DOCTOLIB_DOWNLOAD_DIR", value)
    assert m.default_out() == expected


# --------------------------------------------------------------------------- #
# HTTP errors
# --------------------------------------------------------------------------- #
def test_expired_session_names_the_fix(m):
    c = client_with(m, {"/account/master_patients.json": (401, {}, "application/json")})
    with pytest.raises(click.ClickException, match="Sign in at https://www.doctolib.fr"):
        c.get("/account/master_patients.json", auth=True)


def test_bot_shield_403_is_explained(m):
    c = client_with(m, {"/availabilities.json": (403, b"<html>", "text/html")})
    with pytest.raises(click.ClickException, match="bot shield"):
        c.get("/availabilities.json")


def test_search_206_is_success(m, search_hit):
    c = client_with(m, {"/patient-health-search/api/v1/hcp/search": (206, {"total": 1, "healthcareProviders": [search_hit]}, "application/json")})
    assert m.search(c, "dentiste", {"name": "Paris"})["total"] == 1


# --------------------------------------------------------------------------- #
# Public reads
# --------------------------------------------------------------------------- #
def test_provider_prefers_online_booking_agendas(m, search_hit):
    assert m.normalize_provider(search_hit, "https://www.doctolib.fr")["agenda_ids"] == [101, 102]


def test_provider_name_collapses_spaces(m, search_hit):
    assert m.normalize_provider(search_hit, "https://www.doctolib.fr")["name"] == "Ada EXAMPLE"


def test_provider_slug_drops_query(m, search_hit):
    assert m.normalize_provider(search_hit, "https://www.doctolib.fr")["slug"] == "ada-example"


def test_provider_motive_is_stripped(m, search_hit):
    assert m.normalize_provider(search_hit, "https://www.doctolib.fr")["motive"] == "Urgence"


@pytest.mark.parametrize("value", [
    "ada-example",
    "https://www.doctolib.fr/dentiste/paris/ada-example",
    "https://www.doctolib.fr/dentiste/paris/ada-example?pid=practice-1",
    "/dentiste/paris/ada-example/",
])
def test_profile_slug(m, value):
    assert m.profile_slug(value) == "ada-example"


def test_profile_maps_motive_to_practices_and_agendas(m, info):
    motives = {x["id"]: x for x in m.normalize_profile(info["data"])["motives"]}
    assert motives[11]["practices"] == {1: [101]}


def test_profile_drops_motives_only_on_disabled_agendas(m, info):
    assert 14 not in {x["id"] for x in m.normalize_profile(info["data"])["motives"]}


def test_profile_flags_existing_patient_motives(m, info):
    motives = {x["id"]: x for x in m.normalize_profile(info["data"])["motives"]}
    assert motives[13]["new_patients_restricted"] is True


@pytest.mark.parametrize(("wanted", "ids"), [
    ("13", [13]),
    ("urgence", [11, 12]),
    ("Urgence dentaire", [11, 12]),
    ("première", [13]),
])
def test_pick_motives(m, info, wanted, ids):
    motives = m.normalize_profile(info["data"])["motives"]
    assert [x["id"] for x in m.pick_motives(motives, wanted)] == ids


@pytest.mark.parametrize(("wanted", "error"), [("u", "Ambiguous"), ("radio", "Unknown"), ("999", "Unknown")])
def test_pick_motives_errors_list_candidates(m, info, wanted, error):
    motives = m.normalize_profile(info["data"])["motives"]
    with pytest.raises(click.BadParameter, match=error):
        m.pick_motives(motives, wanted)


@pytest.fixture
def window_client(m):
    def answer(params):
        start = params["start_date"]
        slots = {"2026-01-01": ["2026-01-03T09:00:00.000+01:00"],
                 "2026-01-16": ["2026-01-17T10:00:00.000+01:00", "2026-01-30T10:00:00.000+01:00"]}[start]
        return ok({"availabilities": [{"date": start, "slots": slots}], "total": len(slots)})
    return client_with(m, {"/availabilities.json": answer})


def test_availabilities_walks_15_day_windows(m, window_client):
    m.availabilities(window_client, 11, [101], 1, date(2026, 1, 1), 20)
    assert [c[2]["limit"] for c in window_client.s.calls] == [15, 5]


def test_availabilities_drops_slots_past_the_horizon(m, window_client):
    res = m.availabilities(window_client, 11, [101], 1, date(2026, 1, 1), 20)
    assert res["slots"] == ["2026-01-03T09:00:00.000+01:00", "2026-01-17T10:00:00.000+01:00"]


def test_availabilities_joins_agendas_with_hyphens(m, window_client):
    m.availabilities(window_client, 11, [101, 102], 1, date(2026, 1, 1), 2)
    assert window_client.s.calls[0][2]["agenda_ids"] == "101-102"


def test_availabilities_keeps_not_opened_reason(m):
    c = client_with(m, {"/availabilities.json": ok({"availabilities": [], "total": 0, "reason": "not_opened_availability"})})
    assert m.availabilities(c, 11, [101], 1, date(2027, 6, 1), 3)["reason"] == "not_opened_availability"


# --------------------------------------------------------------------------- #
# Account reads
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(("flags", "status"), [
    ({}, "past"),
    ({"canceled": True}, "canceled"),
    ({"no_show": True}, "no_show"),
    ({"past": False}, "confirmed"),
    ({"past": False, "confirmed": False}, "pending"),
])
def test_appointment_status(m, appointment, flags, status):
    assert m.normalize_appointment(appointment | flags)["status"] == status


def test_appointment_patient_name(m, appointment):
    assert m.normalize_appointment(appointment)["patient"] == "Bob Example"


@pytest.fixture
def past_client(m, appointment):
    pages = {None: {"done": [appointment], "has_next_page": True, "next_cursor": "c2"},
             "c2": {"done": [appointment | {"id": "2"}], "has_next_page": False, "next_cursor": None}}
    return client_with(m, {"/account/appointments.json": lambda p: ok({"data": pages[p.get("cursor")]})})


def test_past_appointments_follow_cursor(m, past_client):
    assert [a["id"] for a in m.fetch_appointments(past_client, past=True)][-1] == "2"


def test_past_appointments_request_past_flag(m, past_client):
    m.fetch_appointments(past_client, past=True)
    assert past_client.s.calls[0][2] == {"page": 1, "past": "true"}


def test_past_appointments_cap_fails_loudly(m, monkeypatch, appointment):
    monkeypatch.setattr(m, "MAX_PAGES", 2)
    c = client_with(m, {"/account/appointments.json": ok({"data": {"done": [appointment], "has_next_page": True}})})
    with pytest.raises(click.ClickException, match="exceed 2 pages"):
        m.fetch_appointments(c, past=True)


def test_documents_paginate_and_dedupe(m, document):
    pages = {1: {"documents": [document], "last_page": False, "current_page": 1},
             2: {"documents": [document, document | {"id": "e"}], "last_page": True, "current_page": 2}}
    c = client_with(m, {"/account/documents.json": lambda p: ok(pages[p["page"]])})
    assert len(m.fetch_documents(c)) == 2


def test_document_path_is_relative(m, document):
    assert m.normalize_document(document)["path"] == "/v2/account/documents/00000000-0000-0000-0000-00000000000d"


@pytest.mark.parametrize(("kwargs", "kept"), [
    ({"patient": "bob"}, 1),
    ({"patient": "alice"}, 0),
    ({"kind": "invoice"}, 0),
    ({"since": "2026-02-03"}, 1),
    ({"since": "2026-02-04"}, 0),
    ({"unread": True}, 1),
])
def test_filter_by(m, document, kwargs, kept):
    assert len(m.filter_by([m.normalize_document(document)], **kwargs)) == kept


def test_document_filename(m, document):
    assert m.document_filename(m.normalize_document(document), "application/pdf") == \
        "2026-02-03_medicine_prescription_dr-ada-example_00000000-0000-0000-0000-00000000000d.pdf"


@pytest.mark.parametrize(("iso", "short"), [
    ("2026-11-08T09:30:00.000+01:00", "2026-11-08 09:30+01:00"),
    ("2026-11-08T09:30:00Z", "2026-11-08 09:30Z"),
    (None, ""),
])
def test_short_time(m, iso, short):
    assert m.short_time(iso) == short


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
@pytest.fixture
def run(m, monkeypatch, search_hit, info, appointment, document):
    patient = {"id": 1, "first_name": "Bob", "last_name": "Example", "kind": "main", "birthdate": "2000-01-01"}
    routes = {
        "/account/master_patients.json": ok([patient]),
        "/account/appointments.json": ok({"data": {"confirmed": [appointment | {"past": False}], "done": [appointment],
                                                   "has_next_page": False}}),
        "/account/documents.json": ok({"documents": [document], "last_page": True}),
        "/patient-health-search/api/v1/hcp/search": (206, {"total": 1, "healthcareProviders": [search_hit]}, "application/json"),
        "/online_booking/api/slot_selection_funnel/v1/info.json": ok(info),
        "/availabilities.json": ok({"availabilities": [{"date": "2026-01-01", "slots": ["2099-01-01T09:00:00.000+01:00"]}]}),
    }
    stub = client_with(m, routes)
    monkeypatch.setattr(m, "Doctolib", lambda country: stub)
    monkeypatch.setattr(m, "geocode", lambda city, country: {"name": city})
    monkeypatch.setattr(m, "availabilities", lambda *a: {"practice_id": 1, "slots": ["2099-01-01T09:00:00.000+01:00"],
                                                          "next_slot": None, "reason": None})
    return lambda *args: CliRunner().invoke(m.cli, list(args))


@pytest.mark.parametrize("args", [
    ["connect", "--json"],
    ["patients", "--json"],
    ["appointments", "--json"],
    ["appointments", "--past", "--json"],
    ["documents", "--json"],
    ["search", "dentiste", "--city", "Paris", "--json"],
    ["profile", "ada-example", "--json"],
    ["slots", "ada-example", "--motive", "urgence", "--json"],
    ["earliest", "dentiste", "--city", "Paris", "--json"],
])
def test_json_output_parses(run, args):
    result = run(*args)
    assert isinstance(json.loads(result.output), (list, dict))


def test_download_rejects_path_like_ids(run):
    assert "is not a document id" in run("download", "../etc").output


def test_download_writes_the_file(m, monkeypatch, tmp_path, document):
    stub = client_with(m, {"/v2/account/documents/00000000-0000-0000-0000-00000000000d":
                           lambda p: ok(document) if not p else ok(b"%PDF-1.7", "application/pdf")})
    real_request = stub.request

    def request(method, path, auth=False, **kw):
        # The file and its metadata share one URL; the Accept header picks the answer.
        if kw.get("headers", {}).get("Accept") == "*/*":
            kw["params"] = {"file": 1}
        return real_request(method, path, auth=auth, **kw)
    monkeypatch.setattr(stub, "request", request)
    monkeypatch.setattr(m, "Doctolib", lambda country: stub)
    CliRunner().invoke(m.cli, ["download", document["id"], "--target-dir", str(tmp_path)])
    assert [p.read_bytes() for p in tmp_path.iterdir()] == [b"%PDF-1.7"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q", "-p", "no:cacheprovider"]))
