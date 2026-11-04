import argparse
import json
import re
import sqlite3
import subprocess
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import requests

BASE = Path(__file__).resolve().parent
DEFAULT_DB = BASE / "data" / "browsers.db"
DEFAULT_REPO = BASE.parent / "WebKit"
DEFAULT_OUT = DEFAULT_REPO / "db.json"

# valores do nvd usados quando a api nao responde. a api tenta primeiro.
CVE_FALLBACK = {
    "CVE-2013-0785": {"score": 4.3, "severity": "MEDIUM", "vector": ""},
    "CVE-2013-0786": {"score": 5.0, "severity": "MEDIUM", "vector": ""},
    "CVE-2016-2803": {"score": 6.1, "severity": "MEDIUM", "vector": ""},
    "CVE-2018-5123": {"score": 8.8, "severity": "HIGH", "vector": ""},
    "CVE-2022-31736": {"score": 9.8, "severity": "CRITICAL", "vector": ""},
    "CVE-2023-28100": {"score": 10.0, "severity": "CRITICAL", "vector": ""},
    "CVE-2023-5217": {"score": 8.8, "severity": "HIGH", "vector": ""},
    "CVE-2024-4367": {"score": 8.8, "severity": "HIGH", "vector": ""},
}

NEGATIVE = [
    r"not a security (?:risk|issue|bug|vulnerability)",
    r"no security impact",
    r"not exploitable",
    r"not a vulnerability",
    r"not memory corruption",
    r"false[- ]positive",
]

TITLE_SKIP = [
    r"^style-checker",
    r"check-webkit-style",
    r"^fix (?:fast|http|imported|media|svg|webanimations|webgl|js|dom|xhtml)/",
    r"^fix .*\.html after r",
    r"^source/.*runtime error:",
    r"undefined behavior when querying",
    r"^integer overflow check code",
]

CRITICAL_RULES = [
    (r"\barbitrary code execution\b|\bremote code execution\b|\bRCE\b", "arbitrary/remote code execution"),
    (r"\bsandbox escape\b|\bescape (?:the )?sandbox\b", "sandbox escape"),
    (
        r"\b(?:compromised|malicious|hostile) (?:web ?content|content|renderer|gpu|web) process\b"
        r"[\s\S]{0,240}\b(?:parent process|system|kernel|sandbox escape|code execution|full control)\b",
        "compromised process reaches parent/system",
    ),
    (
        r"\barbitrary (?:read|write)\b|\bread/write primitive\b|\bfull read/write\b"
        r"|\barbitrary memory (?:read|write)\b",
        "arbitrary read/write",
    ),
    (
        r"\b(?:heap[- ])?use[- ]after[- ]free write\b|\buaf write\b|\bout[- ]of[- ]bounds write\b"
        r"|\boob write\b|\bheap[- ]buffer[- ]overflow write\b|\bwild write\b",
        "write primitive",
    ),
]

TYPE_PATTERNS = {
    "use-after-free": r"use[- ]?after[- ]?free|\buaf\b|\bfreed\b",
    "out-of-bounds": (
        r"out[- ]of[- ]bounds?|\boob\b|buffer overflow|heap overflow|"
        r"out[- ]of[- ]range|past the end"
    ),
    "type confusion": r"type confusion",
    "integer overflow": r"integer (?:overflow|underflow)|\bunderflow\b",
    "uninitialized memory": r"uninitiali[sz]ed",
    "double free": r"double[- ]free",
    "memory corruption": r"memory corruption",
    "wild pointer": r"wild pointer|dangling pointer",
    "cross-origin leak": r"cross[- ]origin[\s\S]{0,80}(?:leak|read|access|bypass|exfiltrat)",
    "same-origin bypass": r"same[- ]origin[\s\S]{0,80}(?:bypass|violation)|sop bypass",
    "privilege escalation": (
        r"privilege escalation|permission bypass|policy bypass|"
        r"mitigation bypass|security bypass"
    ),
    "code execution": r"code execution",
}

HIGH_TEXT = [
    (r"\bcross[- ]origin (?:leak|read|access|bypass|exfiltrat\w*)\b", "cross-origin access/leak"),
    (r"\bsame[- ]origin (?:bypass|violation|policy bypass)\b|\bsop bypass\b", "same-origin bypass"),
    (
        r"\bprivilege escalation\b|\bpermission bypass\b|\bpolicy bypass\b|"
        r"\bmitigation bypass\b|\bsecurity bypass\b",
        "privilege/policy bypass",
    ),
    (
        r"\b(?:compromised|malicious|hostile) (?:web ?content|content|renderer|gpu|web) process\b"
        r"[\s\S]{0,240}\b(?:spoof|url bar|address bar|origin)\b",
        "compromised process UI/origin spoof",
    ),
    (
        r"\binfo(?:rmation)? leak(?:age)?\b[\s\S]{0,240}"
        r"\b(?:cross[- ]origin|credential|file|sensitive|private|origin)\b",
        "sensitive cross-origin info leak",
    ),
    (r"\bformat string vulnerability\b", "format string vulnerability"),
    (r"\bframe injection vulnerability\b", "frame injection vulnerability"),
    (r"\barbitrary file (?:exfiltration|access|read)\b", "arbitrary file access/exfiltration"),
    (r"\bsecurity hole\b", "security hole"),
    (r"\brace condition\b|\btoctou\b", "race condition"),
]

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
RADAR_RE = re.compile(r"rdar://(\d+)", re.I)


def run_git(repo, args):
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)
    if result.returncode != 0:
        return None, result.stderr.strip()
    return result.stdout, ""


def split_cves(value):
    return sorted({m.group(0).upper() for m in CVE_RE.finditer(value or "")})


def first_paragraph(text):
    for part in re.split(r"\n\s*\n", (text or "").strip()):
        part = part.strip()
        if part:
            return part
    return ""


def extract_impact(message):
    # tira cabecalho, links, review e a lista de arquivos. sobra a descricao.
    lines = (message or "").splitlines()
    if not lines:
        return ""

    output = []
    for line in lines[1:]:
        stripped = line.strip()
        if not stripped:
            if output and output[-1] != "":
                output.append("")
            continue

        if re.match(r"^(?:Canonical link|Originally-landed-as|Cherry-pick):", stripped, re.I):
            break
        if re.match(
            r"^(?:https?://bugs\.webkit\.org|https?://webkit\.org/b/|rdar://|<rdar://|"
            r"Reviewed by|Test(?:s)?:|No new tests|Patch by |git-svn-id:)",
            stripped,
            re.I,
        ):
            continue
        if re.match(r"^\*\s+", stripped):
            if re.search(r"[/.(]|\.(?:cpp|h|m|mm|js|py|html|txt|json|swift|cmake)\b", stripped, re.I):
                break
        if re.match(
            r"^(?:Source/[A-Za-z]+|WebCore|JavaScriptCore|WebKit|WTF|bmalloc|Tools|LayoutTests):\s*$",
            stripped,
        ):
            continue
        if re.match(r"^(?:Source|Tools|LayoutTests|PerformanceTests|Websites)/", stripped):
            continue
        if re.match(r"^(?:fast|http|imported|media|svg|webanimations|webgl|js|dom|xhtml)/", stripped):
            continue

        output.append(line.rstrip())

    text = "\n".join(output)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def extract_reviewed(message):
    match = re.search(r"Reviewed by ([^\n]+)", message or "", re.I)
    return match.group(1).strip() if match else ""


def extract_radar(message):
    return sorted({m.group(1) for m in RADAR_RE.finditer(message or "")})


def extract_tests(message, files):
    tests = []
    lines = (message or "").splitlines()
    for index, line in enumerate(lines):
        if re.match(r"^Test(?:s)?:", line.strip(), re.I):
            value = line.split(":", 1)[1].strip()
            if value:
                tests.append(value)
            cursor = index + 1
            while cursor < len(lines) and lines[cursor].startswith((" ", "\t")):
                value = lines[cursor].strip()
                if value:
                    tests.append(value)
                cursor += 1
    for entry in files:
        if entry["area"] == "test":
            tests.append(entry["path"])
    return sorted({test for test in tests if test})


def file_area(path):
    if path.startswith("Source/"):
        return "source"
    if path.startswith("LayoutTests/") or path.startswith("Tools/TestWebKitAPI/Tests/"):
        return "test"
    if path.startswith("Tools/"):
        return "tool"
    if path.startswith("Websites/"):
        return "website"
    return "other"


def score_label(score):
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def fetch_nvd(cve_id):
    try:
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
            headers={"User-Agent": "browsers.fail webkit export"},
            timeout=30,
        )
        response.raise_for_status()
        cve = response.json()["vulnerabilities"][0]["cve"]
    except (requests.RequestException, KeyError, IndexError, ValueError) as exc:
        print(f"  nvd falhou para {cve_id}: {exc}")
        return None

    best = None
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for metric in metrics.get(key, []):
            data = metric.get("cvssData") or {}
            score = data.get("baseScore")
            if score is None:
                continue
            candidate = {
                "score": float(score),
                "severity": data.get("baseSeverity") or score_label(float(score)),
                "vector": data.get("vectorString") or "",
                "version": data.get("version") or "",
            }
            if best is None or candidate["score"] > best["score"]:
                best = candidate

    description = ""
    for item in cve.get("descriptions") or []:
        if item.get("lang") == "en":
            description = item.get("value") or ""
            break

    references = []
    for item in cve.get("references") or []:
        url = item.get("url")
        if url:
            references.append(url)

    result = {
        "id": cve_id,
        "description": description,
        "references": references,
        "source": "NVD",
    }
    if best:
        result.update(best)
    return result


def load_cve_data(cves, use_nvd):
    data = {}
    for index, cve_id in enumerate(sorted(cves)):
        item = None
        if use_nvd:
            print(f"buscando nvd {index + 1}/{len(cves)}: {cve_id}")
            item = fetch_nvd(cve_id)
            time.sleep(6)
        if not item:
            fallback = CVE_FALLBACK.get(cve_id)
            if fallback:
                item = {
                    "id": cve_id,
                    "description": "",
                    "references": [],
                    "source": "fallback",
                    **fallback,
                }
        elif item.get("score") is None and cve_id in CVE_FALLBACK:
            item.update(CVE_FALLBACK[cve_id])
        if item:
            data[cve_id] = item
    return data


def severity_for(item, impact, cve_details):
    scored = [cve for cve in cve_details if cve.get("score") is not None]
    if scored:
        best = max(scored, key=lambda cve: cve["score"])
        reason = f"{best['id']} CVSS {best['score']:.1f}"
        if best["score"] >= 9.0:
            return "critical", [reason], "NVD CVSS", "high"
        if best["score"] >= 7.0:
            return "high", [reason], "NVD CVSS", "high"
        return None, [reason + " below 7.0"], "NVD CVSS", "high"

    full = (item["title"] + "\n" + (item["body"] or "")).lower()
    text = (item["title"] + "\n" + impact).lower()

    for pattern in TITLE_SKIP:
        if re.search(pattern, text, re.I):
            return None, ["title skip"], "commit message heuristic", "low"

    for pattern in NEGATIVE:
        if re.search(pattern, full, re.I):
            return None, ["negative phrase"], "commit message heuristic", "low"

    for pattern, reason in CRITICAL_RULES:
        if re.search(pattern, text, re.I):
            return "critical", [reason], "commit message", "high"

    type_pattern = TYPE_PATTERNS.get(item["vuln_type"])
    if type_pattern and re.search(type_pattern, text, re.I):
        return "high", [item["vuln_type"]], "commit message", "medium"

    for pattern, reason in HIGH_TEXT:
        if re.search(pattern, text, re.I):
            if reason == "race condition" and not re.search(
                r"use[- ]after[- ]free|memory corruption|arbitrary|security|bypass",
                text,
                re.I,
            ):
                continue
            return "high", [reason], "commit message", "medium"

    return None, [], "commit message heuristic", "low"


def parse_numstat(text):
    files = []
    for line in (text or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        additions, deletions, path = parts[0], parts[1], "\t".join(parts[2:])
        files.append(
            {
                "path": path,
                "additions": None if additions == "-" else int(additions),
                "deletions": None if deletions == "-" else int(deletions),
                "area": file_area(path),
            }
        )
    return files


def enrich(item, repo, cve_data, negative_titles):
    if item["title"].strip().lower() in negative_titles:
        return None

    message = item["body"] or ""
    impact = extract_impact(message)
    cves = split_cves(item["cve"])
    cve_details = [cve_data[cve] for cve in cves if cve in cve_data]

    severity, reasons, severity_source, severity_confidence = severity_for(
        item, impact, cve_details
    )
    if not severity:
        return None

    try:
        extra = json.loads(item["extra"] or "{}")
    except json.JSONDecodeError:
        extra = {}

    metadata_format = "%H%x00%P%x00%an%x00%ae%x00%aI%x00%cI%x00%B"
    metadata, metadata_error = run_git(
        repo, ["show", "-s", f"--format={metadata_format}", item["ref"]]
    )
    if metadata is None:
        metadata_parts = [item["ref"], "", "", "", item["created_at"], item["created_at"], message]
    else:
        metadata_parts = metadata.split("\x00", 6)
        if len(metadata_parts) < 7:
            metadata_parts = [item["ref"], "", "", "", item["created_at"], item["created_at"], message]

    commit, parents, author_name, author_email, author_date, committer_date, full_message = metadata_parts
    parent_list = [parent for parent in parents.split() if parent]

    diff, diff_error = run_git(
        repo,
        [
            "show",
            "--format=",
            "--patch",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            item["ref"],
        ],
    )
    if diff is None:
        diff = ""

    numstat, _numstat_error = run_git(
        repo, ["show", "--numstat", "--format=", item["ref"]]
    )
    files = parse_numstat(numstat)

    cve_description = " ".join(
        cve.get("description", "") for cve in cve_details if cve.get("description")
    ).strip()
    impact_source = "commit message"
    if len(impact.strip()) < 40 and cve_description:
        impact = cve_description
        impact_source = "NVD"
    if not impact.strip():
        impact = item["title"]
    if cve_description and len(impact) < 160 and cve_description not in impact:
        impact = impact.rstrip() + "\n\nCVE: " + cve_description
        impact_source = "commit message + NVD"

    impact_summary = first_paragraph(impact) or item["title"]
    tests = extract_tests(full_message, files)

    bug_id = str(extra.get("bug_id") or "")
    bug_url = f"https://bugs.webkit.org/show_bug.cgi?id={bug_id}" if bug_id else ""
    commit_url = f"https://github.com/WebKit/WebKit/commit/{commit}"
    commits_webkit_url = f"https://commits.webkit.org/{commit}"
    cve_urls = [f"https://nvd.nist.gov/vuln/detail/{cve}" for cve in cves]

    references = []
    for value in [commit_url, commits_webkit_url, bug_url, *cve_urls]:
        if value and value not in references:
            references.append(value)
    for cve in cve_details:
        for value in cve.get("references") or []:
            if value and value not in references:
                references.append(value)

    best_cvss = None
    if cve_details:
        scored = [cve for cve in cve_details if cve.get("score") is not None]
        if scored:
            best_cvss = max(scored, key=lambda cve: cve["score"])

    diff_stat = {
        "files": len(files),
        "additions": sum(entry["additions"] or 0 for entry in files),
        "deletions": sum(entry["deletions"] or 0 for entry in files),
    }

    return {
        "id": commit,
        "short_id": commit[:12],
        "title": item["title"],
        "severity": severity,
        "severity_reason": reasons,
        "severity_source": severity_source,
        "severity_confidence": severity_confidence,
        "impact": impact,
        "impact_summary": impact_summary,
        "impact_source": impact_source,
        "vulnerability_type": item["vuln_type"],
        "classifier_signals": extra.get("signals") or [],
        "classifier_confidence": extra.get("confidence") or "",
        "component": item["component"],
        "product": item["product"],
        "author": {
            "name": author_name,
            "email": author_email,
        },
        "date": author_date or item["created_at"],
        "committer_date": committer_date or item["updated_at"],
        "bug_id": bug_id,
        "bug_url": bug_url,
        "cve": cves,
        "cvss": best_cvss,
        "cve_details": cve_details,
        "radar": extract_radar(full_message),
        "reviewed_by": extract_reviewed(full_message),
        "commit": commit,
        "commit_url": commit_url,
        "commits_webkit_url": commits_webkit_url,
        "parents": parent_list,
        "report": full_message,
        "report_source": "WebKit commit",
        "tests": tests,
        "files": files,
        "diff_stat": diff_stat,
        "patch": diff,
        "patch_size": len(diff.encode("utf-8")),
        "references": references,
        "source": "WebKit/WebKit",
        "metadata_error": metadata_error or "",
        "diff_error": diff_error or "",
    }


def main():
    parser = argparse.ArgumentParser(description="exporta os bugs webkit high/critical para json")
    parser.add_argument("--db", default=str(DEFAULT_DB), help="caminho do sqlite")
    parser.add_argument("--repo", default=str(DEFAULT_REPO), help="checkout do webkit")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="arquivo json de saida")
    parser.add_argument("--no-nvd", action="store_true", help="nao consulta o nvd")
    parser.add_argument("--limit", type=int, default=0, help="limita itens para teste")
    args = parser.parse_args()

    db_path = Path(args.db).expanduser().resolve()
    repo = Path(args.repo).expanduser().resolve()
    out_path = Path(args.out).expanduser().resolve()

    if not db_path.exists():
        raise SystemExit(f"banco nao encontrado: {db_path}")
    if not (repo / ".git").exists():
        raise SystemExit(f"repositorio git nao encontrado: {repo}")

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    rows = [dict(row) for row in connection.execute("select * from items where kind = 'webkit'")]
    connection.close()
    if args.limit:
        rows = rows[: args.limit]

    negative_titles = {
        item["title"].strip().lower()
        for item in rows
        if any(re.search(pattern, item["body"] or "", re.I) for pattern in NEGATIVE)
    }

    all_cves = set()
    for item in rows:
        all_cves.update(split_cves(item["cve"]))
    cve_data = load_cve_data(all_cves, not args.no_nvd)

    bugs = []
    excluded = Counter()
    for index, item in enumerate(rows, start=1):
        bug = enrich(item, repo, cve_data, negative_titles)
        if bug:
            bugs.append(bug)
        else:
            excluded[item["vuln_type"]] += 1
        if index % 25 == 0 or index == len(rows):
            print(f"processados {index}/{len(rows)}: {len(bugs)} high/critical")

    # critical primeiro e, dentro do grupo, mais recente primeiro
    bugs.sort(key=lambda bug: bug["date"], reverse=True)
    bugs.sort(key=lambda bug: 0 if bug["severity"] == "critical" else 1)

    severity_counts = Counter(bug["severity"] for bug in bugs)
    type_counts = Counter(bug["vulnerability_type"] for bug in bugs)
    component_counts = Counter(bug["component"] for bug in bugs)
    cve_items = sum(1 for bug in bugs if bug["cve"])

    output = {
        "meta": {
            "name": "browsers.fail — WebKit high/critical export",
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source_db": str(db_path),
            "source_repo": str(repo),
            "source_repo_url": "https://github.com/WebKit/WebKit",
            "webkit_items_total": len(rows),
            "exported_total": len(bugs),
            "excluded_total": len(rows) - len(bugs),
            "severity_counts": dict(severity_counts),
            "type_counts": dict(type_counts),
            "component_counts": dict(component_counts),
            "items_with_cve": cve_items,
            "severity_filter": ["critical", "high"],
            "severity_method": (
                "CVEs usam o maior CVSS do NVD. os outros commits usam regras de impacto "
                "tiradas da mensagem do commit (rce, sandbox escape, processo comprometido, "
                "arbitrary read/write, use-after-free, oob, type confusion, etc.). "
                "webKit nao publica uma severidade oficial por bug."
            ),
            "severity_rules": {
                "critical": [
                    "arbitrary/remote code execution",
                    "sandbox escape",
                    "compromised process reaches parent/system",
                    "arbitrary read/write",
                    "explicit write primitive",
                ],
                "high": [
                    "use-after-free, out-of-bounds, type confusion, integer overflow",
                    "uninitialized memory, double free, memory corruption, wild pointer",
                    "cross-origin leak, same-origin bypass, privilege/policy bypass",
                    "format string / frame injection / arbitrary file access",
                    "compromised process UI or origin spoof",
                ],
                "excluded": [
                    "xss, spoofing, denial of service, generic security hardening",
                    "info leak without cross-origin/sensitive data",
                    "commits with CVE CVSS below 7.0",
                ],
            },
            "field_notes": {
                "impact": "descricao limpa, tirada da mensagem do commit; para CVEs curtos, inclui a descricao do NVD",
                "report": "mensagem completa do commit",
                "patch": "diff unificado completo do commit",
                "files": "arquivos alterados com additions/deletions e area (source/test/tool)",
                "tests": "testes citados na mensagem ou em LayoutTests/Tools",
                "cvss": "melhor metrica NVD para os CVEs do item",
                "severity_source": "NVD CVSS ou heuristica da mensagem",
            },
            "excluded_by_type": dict(excluded),
            "caveats": [
                "a severidade dos commits sem CVE e uma heuristica, nao um rating oficial da Apple/WebKit",
                "commits antigos podem ter mensagens curtas ou formato de ChangeLog",
                "o patch completo esta incluido para permitir busca de variantes",
            ],
        },
        "bugs": bugs,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"pronto: {len(bugs)} bugs high/critical em {out_path}")
    print(f"critical={severity_counts.get('critical', 0)} high={severity_counts.get('high', 0)}")


if __name__ == "__main__":
    main()
