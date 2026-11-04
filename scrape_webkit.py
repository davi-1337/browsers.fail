import argparse
import html
import json
import re
import time
from datetime import datetime, timezone

import requests

import db

SEARCH_URL = "https://github.com/search"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
BUG_RE = re.compile(r"bugs\.webkit\.org/show_bug\.cgi\?id=(\d+)", re.I)
PATH_RE = re.compile(
    r"^\s*\*\s+((?:Source|Tools|LayoutTests|PerformanceTests|Websites)/[^\s:]+)",
    re.M,
)

# cada consulta pega um grupo de termos. o github busca no texto do commit.
QUERIES = [
    'repo:WebKit/WebKit ("use-after-free" OR "use after free" OR UAF OR "freed memory")',
    'repo:WebKit/WebKit ("out-of-bounds" OR "buffer overflow" OR "heap overflow" OR OOB)',
    'repo:WebKit/WebKit ("type confusion" OR "integer overflow" OR "uninitialized memory")',
    'repo:WebKit/WebKit (XSS OR "cross-site scripting" OR UXSS)',
    'repo:WebKit/WebKit ("info leak" OR "information leak" OR "data leak" OR exfiltration)',
    'repo:WebKit/WebKit ("same-origin bypass" OR "cross-origin leak" OR "cross-origin read" OR "sandbox escape")',
    'repo:WebKit/WebKit ("security fix" OR "security issue" OR vulnerability OR CVE)',
    'repo:WebKit/WebKit (spoofing OR "address bar spoofing" OR "URL spoofing")',
    'repo:WebKit/WebKit ("race condition" OR "double free" OR "memory corruption" OR "wild pointer")',
    'repo:WebKit/WebKit ("arbitrary code execution" OR "code execution" OR "permission bypass" OR "policy bypass")',
    'repo:WebKit/WebKit ("path traversal" OR "prototype pollution" OR CSRF OR "open redirect" OR "header injection")',
    'repo:WebKit/WebKit ("malicious website" OR "malicious web content")',
]

# ordem importa: o primeiro tipo encontrado vira o tipo principal.
# o ultimo campo diz se o corpo do commit tambem pode confirmar o tipo.
STRONG_RULES = [
    (re.compile(r"\buse[- ]?after[- ]?free\b|\buaf\b|\bfreed (?:memory|object|buffer|vector|data|storage|range|proof|pointer|reference)\b|\bdangling pointer\b", re.I), "use-after-free", True),
    (re.compile(r"\bout[- ]of[- ]bounds?\b|\boob\s+(?:read|write|access|memory|buffer|crash)\b|\b(?:read|write|access)\s+(?:out[- ]of[- ]bounds?|oob)\b|\bbuffer overflow\b|\bheap overflow\b|\bstack buffer overflow\b|\bwild (?:read|write)\b|\bout[- ]of[- ]range\b|\boobable\b|\breads? past the end\b|\bpast the end of the buffer\b", re.I), "out-of-bounds", True),
    (re.compile(r"\btype confusion\b", re.I), "type confusion", True),
    (re.compile(r"\binteger (?:overflow|underflow)\b|\bunderflow\b", re.I), "integer overflow", True),
    (re.compile(r"\buninitiali[sz]ed\b", re.I), "uninitialized memory", True),
    (re.compile(r"\bdouble[- ]free\b", re.I), "double free", True),
    (re.compile(r"\bmemory corruption\b", re.I), "memory corruption", True),
    (re.compile(r"\b(?:toctou|race condition|data race)\b", re.I), "race condition", False),
    (re.compile(r"\bcross[- ]site scripting\b|\bxss\b|\buxss\b", re.I), "xss", True),
    (re.compile(r"\bxssauditor\b.*\b(?:tolerant|bypass|inject|vulnerab|security|block|filter|sanitize)\b", re.I), "xss", False),
    (re.compile(r"\binfo(?:rmation)? leak(?:age)?\b|\b(?:data|website data|privacy) leak(?:ed|s|ing|age)?\b|\bexfiltrat(?:e|ed|ion|ing)?\b", re.I), "info leak", False),
    (re.compile(r"\bcross[- ]origin (?:leak|read|access|bypass|exfiltrat\w*)\b", re.I), "cross-origin leak", True),
    (re.compile(r"\bsame[- ]origin (?:bypass|violation|policy bypass)\b|\bsop bypass\b", re.I), "same-origin bypass", True),
    (re.compile(r"\bsandbox[- ]?escape\b|\bescape (?:the )?sandbox\b|\bsandbox[- ]?extension\b", re.I), "sandbox escape", True),
    (re.compile(r"\barbitrary code execution\b|\bcode execution\b", re.I), "code execution", False),
    (re.compile(r"\b(?:address bar|url|origin|domain) spoof(?:ing)?\b|\bspoof(?:s|ed|ing)?\b", re.I), "spoofing", True),
    (re.compile(r"\bprivilege escalation\b|\bpermission bypass\b|\bpolicy bypass\b|\bmitigation bypass\b|\bsecurity bypass\b", re.I), "privilege escalation", True),
    (re.compile(r"\bpath traversal\b|\bdirectory traversal\b", re.I), "path traversal", False),
    (re.compile(r"\bprototype pollution\b", re.I), "prototype pollution", True),
    (re.compile(r"\bcsrf\b|\bcross[- ]site request forgery\b", re.I), "csrf", True),
    (re.compile(r"\bopen redirect\b", re.I), "open redirect", True),
    (re.compile(r"\b(?:header|crlf|command|sql) injection\b", re.I), "injection", True),
    (re.compile(r"\b(?:csp|content[- ]security[- ]policy) bypass\b", re.I), "policy bypass", True),
]

FIX_WORDS = (
    r"(?:fix(?:es|ed)?|avoid(?:s|ed)?|prevent(?:s|ed)?|address(?:es|ed)?|"
    r"correct(?:s|ed)?|guard(?:s|ed)?|validate(?:s|d)?|harden(?:s|ed)?|"
    r"resolve(?:s|d)?|patch(?:es|ed)?)"
)

# frases que deixam claro que o commit nao esta corrigindo uma vulnerabilidade.
NEGATIVE = [
    r"\bnot a real vulnerability\b",
    r"\bnot an actual vulnerability\b",
    r"\bnot a security (?:issue|bug|vulnerability)\b",
    r"\bno security impact\b",
    r"\bnot memory corruption\b",
]

TITLE_SKIP = [
    r"^\[securityflags\]",
    r"^\[site isolation\]",
    r"^layouttests",
    r"^webcore:$",
    r"^unreviewed",
    r"^reviewed by",
    r"^\d{4}-\d{2}-\d{2}",
    r"\btypos? (?:in|fixes?)\b",
    r"\bgardening\b",
    r"\brebase\b",
    r"\bexpected results\b",
    r"\badd (?:a )?(?:layouttest|test cases?)\b",
    r"\badd test\b",
    r"\btest cases?\b",
    r"\bxss-eval\b",
    r"\bis failing\b",
    r"\btests? (?:are )?failing\b",
    r"\bregression\b.*\bfail",
    r"\bxss-denied\b",
    r"\badd setting api\b",
    r"\bexperiment with\b",
    r"\bremove experimental\b",
    r"^support x-xss-protection",
    r"\bcheck-webkit-style\b",
    r"\bdebugger connection\b",
    r"\bthread count\b",
    r"\b(?:support|should support)\b.*\b(?:oob|out[- ]of[- ]bounds)\b",
    r"\bxss auditor\b.*\b(?:no-op|remove|turn off|disable)\b",
    r"\b(?:remove|disable|turn off)\b.*\bxss auditor\b",
]

MEMORY_TYPES = {
    "use-after-free",
    "out-of-bounds",
    "type confusion",
    "uninitialized memory",
    "double free",
    "memory corruption",
}

session = requests.Session()
session.headers.update(
    {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.8",
    }
)


def fix_context(text, pattern):
    # o termo aparece perto de um verbo de correcao?
    term = pattern.pattern
    before = rf"{FIX_WORDS}\b[\s\S]{{0,180}}(?:{term})"
    after = rf"(?:{term})[\s\S]{{0,180}}{FIX_WORDS}\b"
    return bool(re.search(before, text, re.I) or re.search(after, text, re.I))


def generic_security(text, title):
    if re.search(
        r"\bsecurity (?:issue|bug|fix|vulnerability|flaw|hole|problem)\b|\bvulnerab|\bcve-\d{4}-\d+",
        title,
        re.I,
    ):
        return True
    if re.search(
        r"\bfix(?:es|ed)?\s+(?:a |an )?(?:critical |important |serious )?security (?:issue|bug|vulnerability|flaw)\b",
        text,
        re.I,
    ):
        return True
    if re.search(r"\bfix(?:es|ed)?\s+cve-\d{4}-\d+", text, re.I):
        return True
    if re.search(
        r"\b(?:address(?:es|ed)?|patch(?:es|ed)?|resolve(?:s|d)?)\s+cve-\d{4}-\d+",
        text,
        re.I,
    ):
        return True
    return False


def classify(message):
    low = message.lower()
    title = message.splitlines()[0].strip().lower() if message else ""

    for pattern in NEGATIVE:
        if re.search(pattern, low):
            return None, []

    for pattern in TITLE_SKIP:
        if re.search(pattern, title):
            return None, []

    # atualizacao de dependencia so entra se o texto falar em corrigir um cve
    if title.startswith("update ") and not re.search(r"\bfix(?:es|ed)?\s+cve-\d{4}-\d+", low):
        return None, []

    found = []
    for pattern, name, allow_body in STRONG_RULES:
        if pattern.search(title):
            found.append(name)
        elif allow_body and name in MEMORY_TYPES and pattern.search(low):
            found.append(name)
        elif allow_body and fix_context(low, pattern):
            found.append(name)

    if generic_security(low, title):
        found.append("security")

    if re.search(r"\b(?:malicious|attacker)\b", title) and re.search(
        r"\b(?:read|access|execute|run|leak|corrupt|bypass|spoof|crash|gain)\b", low
    ):
        found.append("security")

    if "privacy" in title and "leak" in title:
        found.append("info leak")

    if not found:
        return None, []

    unique = []
    for name in found:
        if name not in unique:
            unique.append(name)
    return unique[0], unique


def find_paths(message):
    return PATH_RE.findall(message)


def pick_component(message, paths):
    for path in paths:
        if path.startswith("Source/"):
            parts = path.split("/")
            if len(parts) > 1:
                return parts[1]

    prefix = re.match(r"^\[([^\]]+)\]", message)
    if prefix:
        name = prefix.group(1).lower()
        if name in ("jsc", "javascriptcore"):
            return "JavaScriptCore"
        if name in ("wtf", "webkit"):
            return "WTF" if name == "wtf" else "WebKit"
        if name == "webcore":
            return "WebCore"
        if name == "site isolation":
            return "WebKit"

    return "WebKit"


def iso_utc(value):
    if not value:
        return ""
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return value[:19] + "Z" if len(value) >= 19 else value


def find_author(result):
    authors = result.get("authors") or []
    for author in authors:
        name = author.get("display_name") or author.get("login")
        if name:
            return name
    committer = result.get("committer") or {}
    return committer.get("display_name") or committer.get("login") or ""


def to_item(result, query):
    message = str(result.get("message") or "")
    sha = str(result.get("sha") or "")
    if not message or not sha:
        return None

    vuln_type, signals = classify(message)
    if not vuln_type:
        return None

    paths = find_paths(message)
    # commit que so mexe em teste ou ferramenta nao entra no indice.
    if paths and not any(p.startswith("Source/") for p in paths):
        return None

    cves = sorted({m.group(0).upper() for m in CVE_RE.finditer(message)})
    bug = BUG_RE.search(message)
    date = iso_utc(str(result.get("author_date") or ""))
    title = message.splitlines()[0].strip()

    return {
        "kind": "webkit",
        "ref": sha,
        "title": title,
        "body": message,
        "product": "WebKit",
        "component": pick_component(message, paths),
        "severity": "",
        "vuln_type": vuln_type,
        "status": "fixed",
        "resolution": "FIXED",
        "cve": ", ".join(cves),
        "keywords": ", ".join(signals),
        "reward": "",
        "reward_value": 0,
        "created_at": date,
        "updated_at": date,
        "fixed_at": date,
        "url": f"https://github.com/WebKit/WebKit/commit/{sha}",
        "extra": {
            "sha": sha,
            "author": find_author(result),
            "bug_id": bug.group(1) if bug else "",
            "paths": paths,
            "signals": signals,
            "query": query,
            "confidence": "cve" if cves else "heuristic",
        },
    }


def fetch_page(query, page, retry_wait=20):
    params = {"q": query, "type": "commits", "p": page}
    for attempt in range(4):
        try:
            resp = session.get(SEARCH_URL, params=params, timeout=45)
        except requests.RequestException as exc:
            print(f"  erro de rede: {exc}")
            time.sleep(4 + attempt * 3)
            continue

        if resp.status_code == 429:
            wait = retry_wait * (attempt + 1)
            print(f"  github pediu calma, esperando {wait:.0f}s")
            time.sleep(wait)
            continue

        if resp.status_code != 200:
            print(f"  github respondeu {resp.status_code}")
            time.sleep(4 + attempt * 3)
            continue

        match = re.search(
            r'<script type="application/json" data-target="react-app.embeddedData">(.*?)</script>',
            resp.text,
            re.S,
        )
        if not match:
            print("  nao achei os resultados na pagina")
            return None

        try:
            data = json.loads(html.unescape(match.group(1)))
            return data["payload"]["blackbirdSearchRoute"]
        except (json.JSONDecodeError, KeyError) as exc:
            print(f"  resposta estranha: {exc}")
            return None

    return None


def reclassify_existing():
    # usa o classificador novo nos commits que ja estao no banco.
    con = db.connect()
    rows = con.execute(
        "select id, ref, body, extra from items where kind = 'webkit'"
    ).fetchall()
    kept = 0
    removed = 0

    for row in rows:
        body = row["body"] or ""
        vuln_type, signals = classify(body)
        if not vuln_type:
            con.execute("delete from items where id = ?", (row["id"],))
            removed += 1
            continue

        try:
            extra = json.loads(row["extra"] or "{}")
        except json.JSONDecodeError:
            extra = {}
        extra["signals"] = signals
        extra["confidence"] = "cve" if CVE_RE.search(body) else "heuristic"

        con.execute(
            "update items set vuln_type = ?, keywords = ?, extra = ? where id = ?",
            (
                vuln_type,
                ", ".join(signals),
                json.dumps(extra, ensure_ascii=False),
                row["id"],
            ),
        )
        kept += 1

    con.commit()
    con.close()
    db.rebuild_search()
    print(f"reclassificados: {kept} mantidos, {removed} removidos")


def main():
    parser = argparse.ArgumentParser(description="indexa commits de seguranca do webkit")
    parser.add_argument("--pages", type=int, default=12, help="paginas por consulta")
    parser.add_argument("--sleep", type=float, default=1.2, help="pausa entre paginas")
    parser.add_argument("--retry-wait", type=float, default=20, help="espera base no 429")
    parser.add_argument("--query", action="append", help="consulta, pode repetir")
    parser.add_argument("--max-commits", type=int, default=0, help="para testes")
    parser.add_argument("--reclassify", action="store_true", help="so reclassifica o banco")
    parser.add_argument("--db", default="", help="caminho do sqlite")
    args = parser.parse_args()

    if args.db:
        db.DB_PATH = args.db

    db.init()
    if args.reclassify:
        reclassify_existing()
        return

    queries = args.query or QUERIES
    items = {}

    for query in queries:
        print(f"buscando: {query}")
        for page in range(1, args.pages + 1):
            route = fetch_page(query, page, args.retry_wait)
            if not route:
                break

            results = route.get("results") or []
            if not results:
                break

            for result in results:
                item = to_item(result, query)
                if item:
                    items[item["ref"]] = item

            total = route.get("result_count") or 0
            pages = route.get("page_count") or 0
            print(f"  pagina {page}/{pages}: {len(items)} commits no indice (github diz {total})")

            if args.max_commits and len(items) >= args.max_commits:
                break
            if page >= pages:
                break
            time.sleep(args.sleep)

        if args.max_commits and len(items) >= args.max_commits:
            break

    total = db.upsert_items(list(items.values()))
    db.rebuild_search()
    print(f"pronto: {total} commits de seguranca no banco")


if __name__ == "__main__":
    main()
