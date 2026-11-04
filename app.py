import math
import os
import re
import shlex
from urllib.parse import urlparse

from flask import Flask, abort, redirect, render_template, request, url_for
from markupsafe import Markup, escape

import db

app = Flask(__name__)
db.init()

PER_PAGE = 30

TYPE_ALIASES = {
    "uaf": "use-after-free",
    "use-after-free": "use-after-free",
    "use after free": "use-after-free",
    "oob": "out-of-bounds",
    "out-of-bounds": "out-of-bounds",
    "out of bounds": "out-of-bounds",
    "buffer overflow": "out-of-bounds",
    "buffer-overflow": "out-of-bounds",
    "bounds": "out-of-bounds",
    "xss": "xss",
    "uxss": "xss",
    "info leak": "info leak",
    "info-leak": "info leak",
    "infoleak": "info leak",
    "disclosure": "info leak",
    "sop": "same-origin bypass",
    "same-origin": "same-origin bypass",
    "same-origin-bypass": "same-origin bypass",
    "same origin": "same-origin bypass",
    "sandbox": "sandbox escape",
    "sandbox escape": "sandbox escape",
    "sandbox-escape": "sandbox escape",
    "rce": "code execution",
    "code-execution": "code execution",
    "dos": "denial of service",
    "denial of service": "denial of service",
    "denial-of-service": "denial of service",
    "race": "race condition",
    "race condition": "race condition",
    "race-condition": "race condition",
    "privesc": "privilege escalation",
    "priv-esc": "privilege escalation",
    "privilege escalation": "privilege escalation",
    "privilege-escalation": "privilege escalation",
    "spoof": "spoofing",
    "spoofing": "spoofing",
    "uninitialized": "uninitialized memory",
    "uninitialized memory": "uninitialized memory",
    "uninitialized-memory": "uninitialized memory",
    "nullptr": "null pointer",
    "null pointer": "null pointer",
    "null-pointer": "null pointer",
    "undefined": "undefined behavior",
    "undefined behavior": "undefined behavior",
    "undefined-behavior": "undefined behavior",
    "jit": "jit",
    "clickjacking": "clickjacking",
    "frame poisoning": "frame poisoning",
    "frame-poisoning": "frame poisoning",
    "oom": "out of memory",
    "out of memory": "out of memory",
    "out-of-memory": "out of memory",
    "site isolation": "site isolation",
    "site-isolation": "site isolation",
    "side channel": "side channel",
    "side-channel": "side channel",
    "crypto": "crypto",
    "type confusion": "type confusion",
    "type-confusion": "type confusion",
    "integer overflow": "integer overflow",
    "integer-overflow": "integer overflow",
    "memory corruption": "memory corruption",
    "memory-corruption": "memory corruption",
    "wild pointer": "wild pointer",
    "wild-pointer": "wild pointer",
    "double free": "double free",
    "double-free": "double free",
    "mitigation bypass": "mitigation bypass",
    "mitigation-bypass": "mitigation bypass",
    "path traversal": "path traversal",
    "path-traversal": "path traversal",
    "prototype pollution": "prototype pollution",
    "prototype-pollution": "prototype pollution",
    "open redirect": "open redirect",
    "open-redirect": "open redirect",
    "policy bypass": "policy bypass",
    "policy-bypass": "policy bypass",
    "cross-origin leak": "cross-origin leak",
    "cross-origin-leak": "cross-origin leak",
    "other": "other",
}

SEVERITY_ALIASES = {
    "crit": "critical",
    "critical": "critical",
    "high": "high",
    "mod": "moderate",
    "moderate": "moderate",
    "medium": "moderate",
    "low": "low",
}

BROWSER_ALIASES = {
    "ff": "firefox",
    "firefox": "firefox",
    "moz": "firefox",
    "mozilla": "firefox",
    "wk": "webkit",
    "webkit": "webkit",
    "safari": "webkit",
    "all": "all",
}

REWARD_ALIASES = {
    "yes": "awarded",
    "true": "awarded",
    "awarded": "awarded",
    "+": "awarded",
    "1": "awarded",
    "pending": "nominated",
    "nominated": "nominated",
    "?": "nominated",
    "no": "denied",
    "false": "denied",
    "denied": "denied",
    "-": "denied",
    "0": "denied",
    "any": "any",
    "*": "any",
}

STATUS_ALIASES = {
    "fixed": "fixed",
    "open": "open",
    "duplicate": "duplicate",
    "dup": "duplicate",
    "wontfix": "wontfix",
    "invalid": "invalid",
}

FILTER_KEYS = {
    "browser",
    "type",
    "component",
    "product",
    "severity",
    "reward",
    "cve",
    "status",
    "year",
    "after",
    "before",
    "sort",
}


def normalize(value, aliases):
    value = str(value).strip()
    return aliases.get(value.lower(), value)


def parse_search(raw):
    raw = (raw or "").strip()
    # aceita reward > 0 com espacos tambem
    raw = re.sub(r"\breward\s*>=?\s*(\d+)", r"reward>\1", raw, flags=re.I)
    try:
        tokens = shlex.split(raw)
    except ValueError:
        tokens = raw.split()

    filters = {key: [] for key in FILTER_KEYS}
    words = []

    for token in tokens:
        # aceita reward>0, reward>=1 etc.
        match = re.match(r"^reward\s*>=?\s*(\d+)$", token, re.I)
        if match:
            filters["reward"].append("awarded")
            continue

        if ":" in token:
            key, value = token.split(":", 1)
            key = key.lower().strip()
            value = value.strip()

            if key == "bounty":
                key = "reward"
            elif key == "kind":
                key = "browser"

            if key in FILTER_KEYS and value:
                if key == "type":
                    value = normalize(value, TYPE_ALIASES)
                elif key == "severity":
                    value = normalize(value, SEVERITY_ALIASES)
                elif key == "browser":
                    value = normalize(value, BROWSER_ALIASES)
                elif key == "reward":
                    value = normalize(value, REWARD_ALIASES)
                elif key == "status":
                    value = normalize(value, STATUS_ALIASES)
                filters[key].append(value)
                continue

        words.append(token)

    return {
        "raw": raw,
        "text": " ".join(words).strip(),
        "filters": filters,
    }


def to_fts(text):
    # coloca cada termo entre aspas para o fts5 nao interpretar hifen como operador.
    parts = []
    for word in re.findall(r'"[^"]+"|\S+', text):
        if word.startswith('"') and word.endswith('"') and len(word) > 1:
            value = word[1:-1].replace('"', '""')
            if value:
                parts.append(f'"{value}"')
            continue

        clean = re.sub(r"[^\w\-]+", " ", word, flags=re.UNICODE).strip()
        for piece in clean.split():
            if piece:
                parts.append('"' + piece.replace('"', '""') + '"')

    return " AND ".join(parts)


def build_conditions(parsed):
    from_sql = "from items i"
    conditions = []
    params = []

    text = parsed["text"]
    if text:
        fts = to_fts(text)
        if fts:
            from_sql += " join items_fts on items_fts.rowid = i.id"
            conditions.append("items_fts match ?")
            params.append(fts)
        else:
            conditions.append("0")

    filters = parsed["filters"]

    for browser in filters["browser"]:
        if browser and browser != "all":
            conditions.append("i.kind = ?")
            params.append(browser)

    for value in filters["type"]:
        conditions.append("i.vuln_type = ?")
        params.append(value)

    for value in filters["component"]:
        conditions.append("i.component like ?")
        params.append(f"%{value}%")

    for value in filters["product"]:
        conditions.append("i.product like ?")
        params.append(f"%{value}%")

    for value in filters["severity"]:
        conditions.append("i.severity = ?")
        params.append(value)

    for value in filters["reward"]:
        if value in ("awarded", "yes", "true", "1"):
            conditions.append("i.reward_value > 0")
        elif value == "nominated":
            conditions.append("i.reward = 'nominated'")
        elif value == "denied":
            conditions.append("i.reward = 'denied'")
        elif value == "any":
            conditions.append("i.reward != ''")

    for value in filters["cve"]:
        conditions.append("i.cve like ?")
        params.append(f"%{value.upper()}%")

    for value in filters["status"]:
        if value == "fixed":
            conditions.append(
                "(upper(i.resolution) in ('FIXED', 'VERIFIED') "
                "or upper(i.status) in ('RESOLVED', 'VERIFIED', 'CLOSED', 'FIXED'))"
            )
        elif value == "open":
            conditions.append(
                "upper(i.status) not in ('RESOLVED', 'VERIFIED', 'CLOSED', 'FIXED')"
            )
        elif value == "duplicate":
            conditions.append("upper(i.resolution) = 'DUPLICATE'")
        elif value == "wontfix":
            conditions.append("upper(i.resolution) = 'WONTFIX'")
        elif value == "invalid":
            conditions.append("upper(i.resolution) = 'INVALID'")

    for value in filters["year"]:
        conditions.append("substr(i.created_at, 1, 4) = ?")
        params.append(value)

    for value in filters["after"]:
        conditions.append("i.created_at >= ?")
        params.append(f"{value}-01-01")

    for value in filters["before"]:
        conditions.append("i.created_at < ?")
        params.append(f"{value}-01-01")

    return from_sql, conditions, params


def order_by(parsed, has_fts):
    sort = (parsed["filters"]["sort"] or ["relevance"])[0].lower()
    if sort in ("old", "oldest"):
        return "i.created_at asc"
    if sort in ("new", "recent", "latest", "date"):
        return "i.created_at desc"
    if sort == "severity":
        return (
            "case lower(i.severity) "
            "when 'critical' then 4 when 'high' then 3 "
            "when 'moderate' then 2 when 'low' then 1 else 0 end desc, "
            "i.created_at desc"
        )
    if has_fts:
        return "rank asc, i.created_at desc"
    return "i.created_at desc"


def run_search(parsed, page):
    from_sql, conditions, params = build_conditions(parsed)
    where_sql = (" where " + " and ".join(conditions)) if conditions else ""
    has_fts = " join items_fts " in from_sql

    con = db.connect()
    total = con.execute(
        f"select count(*) {from_sql}{where_sql}", params
    ).fetchone()[0]

    pages = max(1, math.ceil(total / PER_PAGE))
    page = max(1, min(page, pages))
    offset = (page - 1) * PER_PAGE

    if has_fts:
        select_sql = (
            "select i.*, "
            "snippet(items_fts, 1, '<mark>', '</mark>', '…', 28) as snippet, "
            "bm25(items_fts) as rank "
        )
    else:
        select_sql = (
            "select i.*, substr(i.body, 1, 260) as snippet, 0 as rank "
        )

    rows = con.execute(
        f"{select_sql}{from_sql}{where_sql} order by {order_by(parsed, has_fts)} limit ? offset ?",
        params + [PER_PAGE, offset],
    ).fetchall()

    facets = {}
    for field in ("vuln_type", "component", "severity", "reward", "product"):
        facet_conditions = conditions + [f"i.{field} != ''"]
        facet_where = " where " + " and ".join(facet_conditions)
        facet_rows = con.execute(
            f"select i.{field} as value, count(*) as total "
            f"{from_sql}{facet_where} group by i.{field} "
            f"order by total desc, value asc limit 12",
            params,
        ).fetchall()
        facets[field] = [dict(r) for r in facet_rows]

    con.close()

    return {
        "rows": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "pages": pages,
        "facets": facets,
    }


def add_filter(raw, key, value):
    # troca o filtro antigo pelo novo, sem duplicar a chave.
    try:
        tokens = shlex.split(raw or "")
    except ValueError:
        tokens = (raw or "").split()

    kept = []
    for token in tokens:
        if token.lower().startswith(key.lower() + ":"):
            continue
        if key.lower() == "reward" and re.match(r"^reward\s*>", token, re.I):
            continue
        kept.append(token)

    value = str(value).replace('"', "")
    if " " in value or ":" in value:
        kept.append(f'{key}:"{value}"')
    else:
        kept.append(f"{key}:{value}")
    return " ".join(kept)


app.jinja_env.globals["add_filter"] = add_filter


@app.template_filter("hl")
def highlight(value):
    text = str(escape(value or ""))
    text = text.replace("&lt;mark&gt;", "<mark>").replace("&lt;/mark&gt;", "</mark>")
    return Markup(text)


@app.template_filter("short_date")
def short_date(value):
    if not value:
        return "—"
    return str(value)[:10]


@app.template_filter("safe_link")
def safe_link(value):
    # so deixa link http(s) vindo do bugzilla
    if not value:
        return ""
    parsed = urlparse(str(value))
    if parsed.scheme in ("http", "https"):
        return value
    return ""


@app.template_filter("item_url")
def item_url(item):
    if item["kind"] == "firefox":
        return url_for("firefox_detail", ref=item["ref"])
    return url_for("webkit_detail", ref=item["ref"])


@app.template_filter("reward_label")
def reward_label(value):
    labels = {
        "awarded": "bounty awarded",
        "nominated": "bounty nominated",
        "denied": "bounty denied",
    }
    return labels.get(value, value or "")


@app.context_processor
def inject_stats():
    return {"stats": db.stats()}


@app.route("/")
def home():
    return render_template(
        "home.html",
        firefox=db.latest("firefox", 6),
        webkit=db.latest("webkit", 6),
    )


@app.route("/search")
def search():
    raw = request.args.get("q", "")
    page = request.args.get("page", 1, type=int)
    parsed = parse_search(raw)
    result = run_search(parsed, page)
    return render_template(
        "search.html",
        parsed=parsed,
        result=result,
        raw=parsed["raw"],
        has_filters=any(parsed["filters"].values()),
    )


@app.route("/firefox")
def firefox_index():
    return redirect(url_for("search", q="browser:firefox"))


@app.route("/webkit")
def webkit_index():
    return redirect(url_for("search", q="browser:webkit"))


@app.route("/firefox/<ref>")
def firefox_detail(ref):
    item = db.get_item("firefox", ref)
    if not item:
        abort(404)
    return render_template("detail_firefox.html", item=item, extra=item["extra"])


@app.route("/webkit/<ref>")
def webkit_detail(ref):
    item = db.get_item("webkit", ref)
    if not item:
        abort(404)
    return render_template("detail_webkit.html", item=item, extra=item["extra"])


@app.errorhandler(404)
def not_found(_error):
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )
