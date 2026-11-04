import argparse
import re
import time

import requests

import db

API = "https://bugzilla.mozilla.org/rest/bug"
KEYWORDS = ["sec-critical", "sec-high", "sec-moderate", "sec-low"]
FIELDS = [
    "id",
    "summary",
    "description",
    "product",
    "component",
    "severity",
    "status",
    "resolution",
    "keywords",
    "creation_time",
    "last_change_time",
    "cf_last_resolved",
    "whiteboard",
    "flags",
    "see_also",
    "url",
    "type",
    "priority",
    "version",
    "platform",
    "op_sys",
    "cf_crash_signature",
]

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
SEVERITY_RANK = {
    "sec-critical": 4,
    "sec-high": 3,
    "sec-moderate": 2,
    "sec-low": 1,
}
SEVERITY_NAME = {
    4: "critical",
    3: "high",
    2: "moderate",
    1: "low",
}
CSETYPE = {
    "csectype-uaf": "use-after-free",
    "csectype-bounds": "out-of-bounds",
    "csectype-intoverflow": "integer overflow",
    "csectype-uninitialized": "uninitialized memory",
    "csectype-wildptr": "wild pointer",
    "csectype-sop": "same-origin bypass",
    "csectype-priv-escalation": "privilege escalation",
    "csectype-disclosure": "info leak",
    "csectype-spoof": "spoofing",
    "csectype-dos": "denial of service",
    "csectype-mitigation-bypass": "mitigation bypass",
    "csectype-race": "race condition",
    "csectype-sandbox-escape": "sandbox escape",
    "csectype-nullptr": "null pointer",
    "csectype-undefined": "undefined behavior",
    "csectype-jit": "jit",
    "csectype-clickjacking": "clickjacking",
    "csectype-framepoisoning": "frame poisoning",
    "csectype-oom": "out of memory",
    "csectype-site-isolation": "site isolation",
    "csectype-side-channel": "side channel",
    "csectype-crypto": "crypto",
    "csectype-other": "other",
}

# quando o bug tem mais de um csectype, o primeiro desta lista vira o tipo principal.
TYPE_PRIORITY = [
    "use-after-free",
    "out-of-bounds",
    "type confusion",
    "integer overflow",
    "uninitialized memory",
    "double free",
    "memory corruption",
    "wild pointer",
    "race condition",
    "sandbox escape",
    "privilege escalation",
    "same-origin bypass",
    "info leak",
    "xss",
    "spoofing",
    "denial of service",
    "mitigation bypass",
    "path traversal",
    "prototype pollution",
    "csrf",
    "open redirect",
    "injection",
    "clickjacking",
    "frame poisoning",
    "side channel",
    "jit",
    "undefined behavior",
    "null pointer",
    "out of memory",
    "site isolation",
    "crypto",
    "other",
]

session = requests.Session()
session.headers.update(
    {
        "User-Agent": "browsers.fail indexer (+https://github.com/davi-1337/browsers.fail)",
        "Accept": "application/json",
    }
)


def fetch_page(keyword, offset, limit):
    # o bugzilla as vezes responde 429 ou 5xx. tenta de novo com uma pausa.
    params = {
        "keywords": keyword,
        "include_fields": ",".join(FIELDS),
        "limit": limit,
        "offset": offset,
    }
    for attempt in range(4):
        try:
            resp = session.get(API, params=params, timeout=60)
        except requests.RequestException as exc:
            print(f"  erro de rede: {exc}")
            time.sleep(2 + attempt * 2)
            continue

        if resp.status_code == 429:
            wait = int(resp.headers.get("Retry-After", "10"))
            print(f"  rate limit, esperando {wait}s")
            time.sleep(wait)
            continue

        if resp.status_code >= 500:
            print(f"  bugzilla respondeu {resp.status_code}, tentando de novo")
            time.sleep(2 + attempt * 2)
            continue

        resp.raise_for_status()
        data = resp.json()
        if data.get("error"):
            raise RuntimeError(data.get("message", "erro desconhecido do bugzilla"))
        return data.get("bugs", [])

    raise RuntimeError(f"nao consegui buscar {keyword} offset {offset}")


def find_cves(bug):
    parts = [
        str(bug.get("summary") or ""),
        str(bug.get("whiteboard") or ""),
        str(bug.get("url") or ""),
    ]
    parts.extend(str(x) for x in (bug.get("see_also") or []))
    text = " ".join(parts)
    return sorted({m.group(0).upper() for m in CVE_RE.finditer(text)})


def find_type(keywords, text):
    found = [CSETYPE[key] for key in keywords if key in CSETYPE]
    for name in TYPE_PRIORITY:
        if name in found:
            return name

    low = text.lower()
    guesses = [
        ("use-after-free", "use-after-free"),
        ("out-of-bounds", "out-of-bounds"),
        ("out of bounds", "out-of-bounds"),
        ("buffer overflow", "out-of-bounds"),
        ("type confusion", "type confusion"),
        ("integer overflow", "integer overflow"),
        ("uninitialized", "uninitialized memory"),
        ("cross-site scripting", "xss"),
        ("xss", "xss"),
        ("info leak", "info leak"),
        ("information leak", "info leak"),
        ("same-origin bypass", "same-origin bypass"),
        ("sandbox escape", "sandbox escape"),
        ("privilege escalation", "privilege escalation"),
        ("clickjacking", "clickjacking"),
        ("null pointer", "null pointer"),
        ("out of memory", "out of memory"),
        ("side channel", "side channel"),
        ("undefined behavior", "undefined behavior"),
        ("address bar spoof", "spoofing"),
        ("spoofing", "spoofing"),
        ("denial of service", "denial of service"),
        ("race condition", "race condition"),
    ]
    for needle, name in guesses:
        if needle in low:
            return name
    return "other"


def find_reward(flags):
    statuses = {
        f.get("status")
        for f in flags
        if f.get("name") == "sec-bounty"
    }
    if "+" in statuses:
        return "awarded", 1
    if "?" in statuses:
        return "nominated", 0
    if "-" in statuses:
        return "denied", 0
    return "", 0


def to_item(bug):
    keywords = [str(k) for k in (bug.get("keywords") or [])]
    rank = max((SEVERITY_RANK.get(k, 0) for k in keywords), default=0)
    severity = SEVERITY_NAME.get(rank, "")

    title = str(bug.get("summary") or "")
    description = str(bug.get("description") or "")
    crash = str(bug.get("cf_crash_signature") or "")
    body = description
    if crash:
        body += "\n\ncrash signature:\n" + crash

    cves = find_cves(bug)
    vuln_type = find_type(keywords, title + "\n" + description)
    reward, reward_value = find_reward(bug.get("flags") or [])
    see_also = [str(x) for x in (bug.get("see_also") or [])]

    return {
        "kind": "firefox",
        "ref": str(bug["id"]),
        "title": title,
        "body": body,
        "product": str(bug.get("product") or ""),
        "component": str(bug.get("component") or ""),
        "severity": severity,
        "vuln_type": vuln_type,
        "status": str(bug.get("status") or ""),
        "resolution": str(bug.get("resolution") or ""),
        "cve": ", ".join(cves),
        "keywords": ", ".join(keywords),
        "reward": reward,
        "reward_value": reward_value,
        "created_at": str(bug.get("creation_time") or ""),
        "updated_at": str(bug.get("last_change_time") or ""),
        "fixed_at": str(bug.get("cf_last_resolved") or ""),
        "url": f"https://bugzilla.mozilla.org/show_bug.cgi?id={bug['id']}",
        "extra": {
            "bug_id": bug["id"],
            "priority": bug.get("priority") or "",
            "type": bug.get("type") or "",
            "version": bug.get("version") or "",
            "platform": bug.get("platform") or "",
            "op_sys": bug.get("op_sys") or "",
            "whiteboard": bug.get("whiteboard") or "",
            "crash_signature": crash,
            "see_also": see_also,
            "flags": [
                {"name": f.get("name"), "status": f.get("status")}
                for f in (bug.get("flags") or [])
            ],
            "bounty": reward,
        },
    }


def main():
    parser = argparse.ArgumentParser(description="indexa bugs de seguranca do bugzilla")
    parser.add_argument("--keyword", action="append", help="keywords, pode repetir")
    parser.add_argument("--limit", type=int, default=500, help="bugs por pagina")
    parser.add_argument("--sleep", type=float, default=0.4, help="pausa entre paginas")
    parser.add_argument("--max-bugs", type=int, default=0, help="para testes")
    parser.add_argument("--db", default="", help="caminho do sqlite")
    args = parser.parse_args()

    if args.db:
        db.DB_PATH = args.db

    db.init()
    keywords = args.keyword or KEYWORDS
    items = {}

    for keyword in keywords:
        offset = 0
        print(f"buscando {keyword}")
        while True:
            bugs = fetch_page(keyword, offset, args.limit)
            if not bugs:
                break

            for bug in bugs:
                item = to_item(bug)
                items[item["ref"]] = item

            print(f"  {keyword}: {offset + len(bugs)} bugs")
            offset += len(bugs)

            if len(bugs) < args.limit:
                break
            if args.max_bugs and len(items) >= args.max_bugs:
                break
            time.sleep(args.sleep)

        if args.max_bugs and len(items) >= args.max_bugs:
            break

    total = db.upsert_items(list(items.values()))
    db.rebuild_search()
    print(f"pronto: {total} bugs de seguranca no banco")


if __name__ == "__main__":
    main()
