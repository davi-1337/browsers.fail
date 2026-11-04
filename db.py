import json
import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("BROWSERS_DB", os.path.join(BASE_DIR, "data", "browsers.db"))

# o banco e simples de proposito. um item pode ser um bug do bugzilla ou um commit do webkit.
SCHEMA = """
create table if not exists items (
    id integer primary key autoincrement,
    kind text not null,
    ref text not null,
    title text not null,
    body text not null default '',
    product text not null default '',
    component text not null default '',
    severity text not null default '',
    vuln_type text not null default '',
    status text not null default '',
    resolution text not null default '',
    cve text not null default '',
    keywords text not null default '',
    reward text not null default '',
    reward_value integer not null default 0,
    created_at text not null default '',
    updated_at text not null default '',
    fixed_at text not null default '',
    url text not null default '',
    extra text not null default '{}',
    unique(kind, ref)
);

create index if not exists idx_items_kind_date on items(kind, created_at);
create index if not exists idx_items_component on items(component);
create index if not exists idx_items_type on items(vuln_type);
create index if not exists idx_items_cve on items(cve);
create index if not exists idx_items_reward on items(reward_value);

create virtual table if not exists items_fts using fts5(
    title,
    body,
    product,
    component,
    vuln_type,
    cve,
    keywords,
    content='items',
    content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);
"""

UPSERT = """
insert into items (
    kind, ref, title, body, product, component, severity, vuln_type,
    status, resolution, cve, keywords, reward, reward_value,
    created_at, updated_at, fixed_at, url, extra
) values (
    :kind, :ref, :title, :body, :product, :component, :severity, :vuln_type,
    :status, :resolution, :cve, :keywords, :reward, :reward_value,
    :created_at, :updated_at, :fixed_at, :url, :extra
)
on conflict(kind, ref) do update set
    title = excluded.title,
    body = excluded.body,
    product = excluded.product,
    component = excluded.component,
    severity = excluded.severity,
    vuln_type = excluded.vuln_type,
    status = excluded.status,
    resolution = excluded.resolution,
    cve = excluded.cve,
    keywords = excluded.keywords,
    reward = excluded.reward,
    reward_value = excluded.reward_value,
    created_at = excluded.created_at,
    updated_at = excluded.updated_at,
    fixed_at = excluded.fixed_at,
    url = excluded.url,
    extra = excluded.extra
"""


def connect():
    folder = os.path.dirname(DB_PATH)
    if folder:
        os.makedirs(folder, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("pragma journal_mode = wal")
    con.execute("pragma foreign_keys = on")
    return con


def init():
    con = connect()
    con.executescript(SCHEMA)
    con.commit()
    con.close()


def prepare(item):
    # garante que todo campo exista, mesmo quando o scraper esquece algo
    row = {
        "kind": str(item.get("kind", "")),
        "ref": str(item.get("ref", "")),
        "title": str(item.get("title", "")),
        "body": str(item.get("body", "")),
        "product": str(item.get("product", "")),
        "component": str(item.get("component", "")),
        "severity": str(item.get("severity", "")),
        "vuln_type": str(item.get("vuln_type", "")),
        "status": str(item.get("status", "")),
        "resolution": str(item.get("resolution", "")),
        "cve": str(item.get("cve", "")),
        "keywords": str(item.get("keywords", "")),
        "reward": str(item.get("reward", "")),
        "reward_value": int(item.get("reward_value", 0) or 0),
        "created_at": str(item.get("created_at", "")),
        "updated_at": str(item.get("updated_at", "")),
        "fixed_at": str(item.get("fixed_at", "")),
        "url": str(item.get("url", "")),
        "extra": json.dumps(item.get("extra") or {}, ensure_ascii=False),
    }
    return row


def upsert_items(items):
    if not items:
        return 0
    con = connect()
    con.executemany(UPSERT, [prepare(i) for i in items])
    con.commit()
    con.close()
    return len(items)


def rebuild_search():
    # a tabela fts guarda uma copia dos campos. refaz ela depois de cada carga.
    con = connect()
    con.execute("insert into items_fts(items_fts) values('rebuild')")
    con.commit()
    con.close()


def get_item(kind, ref):
    con = connect()
    row = con.execute(
        "select * from items where kind = ? and ref = ?", (kind, str(ref))
    ).fetchone()
    con.close()
    if not row:
        return None
    item = dict(row)
    try:
        item["extra"] = json.loads(item["extra"] or "{}")
    except json.JSONDecodeError:
        item["extra"] = {}
    return item


def latest(kind, limit=6):
    con = connect()
    rows = con.execute(
        "select * from items where kind = ? order by created_at desc limit ?",
        (kind, limit),
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def stats():
    con = connect()
    rows = con.execute(
        "select kind, count(*) as total from items group by kind"
    ).fetchall()
    counts = {r["kind"]: r["total"] for r in rows}
    last = con.execute("select max(updated_at) from items").fetchone()[0]
    con.close()
    return {
        "total": sum(counts.values()),
        "firefox": counts.get("firefox", 0),
        "webkit": counts.get("webkit", 0),
        "updated": last or "",
    }
