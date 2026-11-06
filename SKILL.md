---
name: doctolib-cli
description: Read a Doctolib patient account and search practitioners' open slots from the terminal with the `doctolib` command — the account's patients (holder and relatives), upcoming and past appointments, documents shared by practitioners (prescriptions, invoices, certificates, referrals) and their download; plus, with no login, practitioner search in a city, a practitioner's places and visit motives, open slots for a motive, and a ranking of practitioners by earliest slot. Read-only, never books or cancels; borrows the signed-in browser's session. Works on doctolib.fr, .de and .it. Use when the user asks about their Doctolib appointments, wants a prescription or invoice from Doctolib, or wants to find a doctor/dentist/specialist with an early slot. Triggers - "doctolib", "mes rendez-vous doctolib", "trouve un dentiste dispo", "premier créneau", "ordonnance doctolib", "facture doctolib", "quand est mon prochain rdv".
---

# doctolib-cli

Read-only access to Doctolib through the JSON API its patient website uses.

## How to invoke

`doctolib` is on `$PATH` via `uv run claudine/scripts/link_clis.py`, which links
`bin/doctolib` into `~/.local/bin`. If it is missing, run
`<skill-dir>/bin/doctolib` directly: it is a PEP 723 script and `uv` resolves
its pinned dependencies.

## Authentication

`search`, `profile`, `slots` and `earliest` need none.

The account commands (`connect`, `patients`, `appointments`, `documents`,
`download`) reuse the Doctolib session of a signed-in Chromium browser (Chrome,
Arc, Brave, Edge, Dia): its cookie store is decrypted with the browser's
"Safe Storage" key from the macOS keychain. Nothing is stored.

- Start with `doctolib connect --json`: it names the account holder and the
  browser profile the session came from.
- On `No Doctolib session` or `401`, ask the user to sign in at
  https://www.doctolib.fr in their browser, then retry once. Do not loop.
- macOS may ask to let `security` read the browser's Safe Storage key; a denied
  prompt looks exactly like being signed out.
- `DOCTOLIB_COOKIE` (a full Cookie header) overrides the browser lookup.
- `--country de|it` (or `DOCTOLIB_COUNTRY`) switches site; the session must be
  for that site.

## Output conventions

- Default: one line per record, tab-separated, the id or slug the next command
  takes at the end.
- `--json`: normalized records on stdout, nothing else. `--raw` (on `patients`,
  `search`, `profile`) prints Doctolib's answer untouched.
- Logs and counts go to stderr (`--debug` for HTTP details).
- Times are the practice's local time with the offset written out
  (`2026-11-08 09:30+01:00`), because that is when the patient must show up.

## Commands

```bash
# Read, no login
doctolib search dentiste --city Paris                    # 20 per page, slug last
doctolib search 'médecin généraliste' --city Lyon --telehealth --json
doctolib profile <slug-or-url>                           # places + bookable motives (ids)
doctolib slots <slug-or-url> --motive urgence            # name fragment or motive id
doctolib slots <slug-or-url> --motive 6089080 --days 30 --practice 299047 --json
doctolib earliest dentiste --city Paris --days 14         # ranked by first open slot
doctolib earliest dermatologue --city Lyon --days 60 --pages 2

# Read, account (browser session)
doctolib connect --json
doctolib patients                                       # holder ("main") and relatives
doctolib appointments                                   # upcoming
doctolib appointments --past --since 2025-01-01         # history, newest first
doctolib appointments --past --patient Alice --json
doctolib documents --limit 20                           # newest first
doctolib documents --unread
doctolib documents --patient Alice --kind medicine_prescription --json

# Local write (download; marks the document as read on Doctolib)
doctolib download <doc-id> [<doc-id> …] --target-dir ~/Downloads/doctolib
doctolib download <doc-id> -o ordonnance.pdf --json     # [{"id", "path", "bytes"}]
```

## Recipes

- **Next appointment:** `doctolib appointments --limit 1`.
- **Find a dentist with an early slot nearby:**
  `doctolib earliest dentiste --city 'Paris 18' --days 14`, then
  `doctolib slots <slug> --motive <motive>` for the full list. Booking is done by
  the user on the practitioner's page (`url` in `--json`).
- **Latest prescription as PDF:**
  `doctolib documents --kind medicine_prescription --limit 1 --json`, then
  `doctolib download <id>`.
- **All invoices of a year:**
  `doctolib documents --kind invoice --since 2025-01-01 --json | jq -r '.[] | select(.created_at < "2026") | .id' | xargs doctolib download --target-dir DIR`.
- **When did we last see a given doctor:**
  `doctolib appointments --past --json > appts.json`, then filter with `jq`.

## Gotchas

- Read-only by design. Booking is a four-step server-side funnel with a CSRF
  token that rotates per request; cancelling needs the same token. Neither works
  with a cookie replay, so the CLI does not try.
- `download` marks the document as read on Doctolib (measured: `viewed_at` set
  after one download), like opening it on the website. `documents --unread`
  is therefore only meaningful before downloading.
- Search needs a city: `--city` is geocoded with OpenStreetMap (Nominatim,
  cached in `~/.cache/doctolib-cli/places.json`) into the bounding box Doctolib
  filters on. Without a box Doctolib silently returns nationwide results.
- Search answers HTTP 206 on success (paged results).
- `availabilities.json` covers about two weeks per call; `slots` walks
  15-day windows. A practice that has not opened its calendar that far answers
  `reason: not_opened_availability`, shown instead of slots; that is not
  "fully booked".
- The same motive name (e.g. "Urgence dentaire") has one id per practice;
  `--motive <name>` queries all of them, `--practice` narrows to one.
- Motives flagged `existing-patients-only` in `profile` show slots that a new
  patient cannot book.
- Measured (2026-11, doctolib.fr): `earliest` over 20 practitioners and 7 days
  takes about 5 s; an account with 22 past appointments and 16 documents lists
  each in under 2 s.
- Doctolib's bot shield (DataDome) lets JSON calls through with a browser
  User-Agent and answers 403 to others; the HTML pages are blocked much harder.
  Do not scrape pages.
