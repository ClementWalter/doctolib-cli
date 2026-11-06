# doctolib-cli

**Visibility: public.**

Also a Claude Desktop extension: download `doctolib-cli.mcpb` from the
[latest release](https://github.com/ClementWalter/doctolib-cli/releases/latest)
or from <https://clementwalter.github.io/claude-extensions/#doctolib>.

Read your [Doctolib](https://www.doctolib.fr) patient account from the terminal
(patients, upcoming and past appointments, documents and their download), and
search practitioners' open slots without logging in: search in a city, a
practitioner's visit motives, open slots, and a ranking by earliest slot.

Doctolib has no public API (its Partner API is for medical software vendors).
This tool uses the JSON API behind the patient website. Account commands reuse
the session of your signed-in browser and never store it. It is read-only: it
never books or cancels an appointment.

## Install

Requires macOS, Python 3.11+, `uv`, and for the account commands a Chromium
browser (Chrome, Arc, Brave, Edge or Dia) signed in to https://www.doctolib.fr.

```console
uv run claudine/scripts/link_clis.py   # links bin/doctolib into ~/.local/bin
doctolib connect
```

`bin/doctolib` is a symlink to `doctolib_cli.py`, a PEP 723 script with pinned
dependencies.

## Usage

```console
doctolib earliest dentiste --city Paris
doctolib slots <practitioner-slug> --motive urgence
doctolib appointments
doctolib documents --unread
doctolib download <document-id>
```

See `SKILL.md` for every command, recipe and known trap.

## Tests

```console
uv run --script tests/test_doctolib_cli.py
```

The tests are offline and use synthetic data.

## Privacy Policy

See https://clementwalter.github.io/claude-extensions/privacy/. The tool talks
only to doctolib.fr (or .de, .it) and to nominatim.openstreetmap.org (the city
name of a search), and writes only the files you ask it to download and a cache
of geocoded city names.
