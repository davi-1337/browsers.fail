# browsers.fail

an index of browser vulnerabilities.

two sections:

- **firefox** — public security bugs from [bugzilla.mozilla.org](https://bugzilla.mozilla.org/), with `sec-critical`, `sec-high`, `sec-moderate` or `sec-low`.
- **webkit** — security-relevant commits from [WebKit/WebKit](https://github.com/WebKit/WebKit). WebKit has no public security bug tracker, so the indexer reads commit messages and keeps the ones that look like vulnerability fixes.

the search is full text and has filters for type, component, severity, cve, date, status and bounty. everything is public data, no login.

## run

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# first load, can take a few minutes
.venv/bin/python scrape_firefox.py
.venv/bin/python scrape_webkit.py

.venv/bin/python app.py
```

the webkit pass can take longer because github rate-limits the public commit search. use `--pages` and `--sleep` if you want to tune it.

open <http://127.0.0.1:5000>.

the scripts use sqlite in `data/browsers.db`. run them again to update; items are upserted by source id.

## search syntax

```text
use-after-free
type:use-after-free
type:oob
component:DOM
component:"DOM: Security"
severity:critical
reward:yes
reward:pending
reward:no
reward:any
reward>0
cve:CVE-2026-8955
browser:webkit
year:2024
after:2020 before:2025
status:fixed
sort:old
sort:severity
```

free text is matched with sqlite fts5. filters can be combined:

```text
browser:firefox type:xss severity:critical
```

## how the webkit side works

WebKit fixes often land as normal commits, with a bug link, a review and no public security label. the indexer searches the WebKit repository for messages containing terms like:

- use-after-free, uaf, freed memory
- out-of-bounds, buffer overflow, oob
- type confusion, integer overflow, uninitialized memory
- xss, info leak, same-origin bypass, sandbox escape
- spoofing, code execution, race condition, path traversal
- cve, security fix, vulnerability

each commit is classified into one main type, and the component is taken from the changed `Source/...` paths in the commit message. commits that only touch `LayoutTests` or `Tools` are ignored.

if you change the classifier later, you can clean the existing database without hitting github again:

```bash
.venv/bin/python scrape_webkit.py --reclassify
```

that reads the stored commit messages, updates the types and removes commits that no longer match. it is a best effort, not a cve database. a commit can match a pattern without being a shipped vulnerability, and a real fix can use wording that the indexer does not catch.

## reward

Mozilla does not publish a dollar amount for each bug. the site indexes the `sec-bounty` flag from bugzilla:

- `awarded` — flag is `+`
- `nominated` — flag is `?`
- `denied` — flag is `-`

`reward:yes` and `reward>0` mean awarded. `reward:any` means any of the three. WebKit commits have no reward data.

## files

```text
app.py             flask app, search parser and routes
db.py              sqlite schema and helpers
scrape_firefox.py  bugzilla indexer
scrape_webkit.py   github commit indexer
templates/         jinja pages
static/            css and small js
data/              generated sqlite database
```

## notes

- this is not affiliated with Mozilla, Apple or the WebKit project.
- the firefox side only sees bugs that are public without logging in.
- the webkit side uses github's public commit search. keep the pause between requests (`--sleep`) if you run it often.
- the app uses flask's development server. for a public deployment, put it behind gunicorn or another wsgi server.
