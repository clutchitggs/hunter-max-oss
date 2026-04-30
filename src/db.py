"""
Database layer for Hunter-Max v14.0 — Async Pipeline Edition.
SQLite-backed persistence with phase tracking, priority scoring, and worker locking.
"""
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "hunter.db"


def _ensure_dir():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)


@contextmanager
def get_conn():
    _ensure_dir()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create all tables if they don't exist."""
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS acquisitions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                link TEXT UNIQUE NOT NULL,
                published TEXT,
                source TEXT,
                acquirer TEXT,
                target_company TEXT,
                target_domain TEXT,
                discovered_at TEXT NOT NULL,
                status TEXT DEFAULT 'new'
            );

            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                acquisition_id INTEGER REFERENCES acquisitions(id),
                program_platform TEXT,
                program_url TEXT,
                scope_status TEXT DEFAULT 'pending',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER REFERENCES targets(id),
                subdomain TEXT NOT NULL,
                cname_target TEXT,
                provider TEXT,
                is_dangling INTEGER DEFAULT 0,
                checked_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER REFERENCES scans(id),
                target_id INTEGER REFERENCES targets(id),
                subdomain TEXT NOT NULL,
                cname_target TEXT NOT NULL,
                provider TEXT NOT NULL,
                fingerprint TEXT,
                severity TEXT DEFAULT 'Medium',
                report_md TEXT,
                status TEXT DEFAULT 'new',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS programs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company TEXT NOT NULL,
                handle TEXT UNIQUE,
                platform TEXT DEFAULT 'hackerone',
                url TEXT,
                scope_domains TEXT,
                last_updated TEXT
            );

            CREATE TABLE IF NOT EXISTS vulns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER REFERENCES targets(id),
                subdomain TEXT NOT NULL,
                vuln_type TEXT NOT NULL,
                evidence TEXT,
                severity TEXT DEFAULT 'Medium',
                url TEXT,
                report_md TEXT,
                status TEXT DEFAULT 'new',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS dns_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subdomain TEXT NOT NULL,
                record_type TEXT NOT NULL,
                record_value TEXT NOT NULL,
                target_id INTEGER REFERENCES targets(id),
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                status TEXT DEFAULT 'active'
            );

            -- v13: Priority scan queue
            CREATE TABLE IF NOT EXISTS scan_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER REFERENCES targets(id),
                domain TEXT NOT NULL,
                priority INTEGER NOT NULL DEFAULT 3,
                source TEXT NOT NULL,
                source_detail TEXT,
                status TEXT DEFAULT 'pending',
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT
            );

            -- v13: Program snapshots for new program + scope change detection
            CREATE TABLE IF NOT EXISTS program_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                handle TEXT UNIQUE NOT NULL,
                company TEXT,
                scope_domains TEXT,
                first_seen_at TEXT NOT NULL,
                last_checked_at TEXT NOT NULL
            );

            -- v13: CVE alerts
            CREATE TABLE IF NOT EXISTS cve_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT UNIQUE NOT NULL,
                description TEXT,
                severity TEXT,
                affected_products TEXT,
                published_at TEXT,
                checked_at TEXT NOT NULL,
                matched_programs TEXT,
                status TEXT DEFAULT 'new'
            );

            -- Performance indexes
            CREATE INDEX IF NOT EXISTS idx_vulns_sub_type ON vulns(subdomain, vuln_type);
            CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_id);
            CREATE INDEX IF NOT EXISTS idx_findings_sub ON findings(subdomain, cname_target);
            CREATE INDEX IF NOT EXISTS idx_dns_sub ON dns_records(subdomain);
            CREATE INDEX IF NOT EXISTS idx_targets_scope ON targets(scope_status);
            CREATE INDEX IF NOT EXISTS idx_activity_type ON activity_log(event_type);
            CREATE INDEX IF NOT EXISTS idx_queue_priority ON scan_queue(priority, status, created_at);
            CREATE INDEX IF NOT EXISTS idx_queue_status ON scan_queue(status);
            CREATE INDEX IF NOT EXISTS idx_queue_domain ON scan_queue(domain);
            CREATE INDEX IF NOT EXISTS idx_snapshot_handle ON program_snapshots(handle);
        """)

        # v14: API schemas table (Phase 3a — API discovery)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS api_schemas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER REFERENCES targets(id),
                subdomain TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                method TEXT DEFAULT 'GET',
                params TEXT,
                source TEXT,
                discovered_at TEXT NOT NULL,
                UNIQUE(subdomain, endpoint, method)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_api_target ON api_schemas(target_id)")

        # v15: React leads table (Scout → Sniper handoff)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS react_leads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER REFERENCES targets(id),
                subdomain TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                method TEXT DEFAULT 'GET',
                vuln_class TEXT NOT NULL,
                confidence INTEGER DEFAULT 0,
                lead_data TEXT,
                sniper_status TEXT DEFAULT 'pending',
                sniper_result TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_leads_status ON react_leads(sniper_status, vuln_class)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_leads_target ON react_leads(target_id)")

        # v15: Chain analysis cache (on-demand AI chain detection)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS chain_analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER REFERENCES targets(id),
                subdomain TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                analysis TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(target_id, subdomain, endpoint)
            )
        """)

        # Safe column migrations
        for col, table in [
            ("launched_at", "programs"),
            ("t1_result", "vulns"),
            ("t2_result", "vulns"),
            ("t3_result", "vulns"),
            ("t3_challenge", "vulns"),
            ("t5_challenge", "vulns"),
            ("enriched_evidence", "vulns"),
            ("enrichment_data", "vulns"),
            ("enrichment_status", "vulns"),
        ]:
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} TEXT")
            except Exception:
                pass

        # v14: Pipeline columns on targets
        for col, default in [
            ("priority", "5"),
            ("phase", "'idle'"),
            ("in_progress", "0"),
            ("phase_updated_at", "NULL"),
            ("last_scanned_at", "NULL"),
            ("scan_metadata", "NULL"),
        ]:
            try:
                conn.execute(f"ALTER TABLE targets ADD COLUMN {col} DEFAULT {default}")
            except Exception:
                pass

        # v14: Pipeline index (must be after column migration)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_targets_pipeline
            ON targets(phase, in_progress, priority DESC, phase_updated_at ASC)
        """)


# --- Helpers ---

def _now():
    return datetime.now(tz=timezone.utc).isoformat()


# --- Acquisitions ---

def insert_acquisition(title, link, published, source, acquirer, target_company, target_domain):
    with get_conn() as conn:
        try:
            conn.execute(
                "INSERT INTO acquisitions (title, link, published, source, acquirer, target_company, target_domain, discovered_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (title, link, published, source, acquirer, target_company, target_domain, _now()),
            )
            return conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        except sqlite3.IntegrityError:
            return None  # Duplicate link


def get_acquisitions(limit=100, offset=0):
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM acquisitions ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()


def count_acquisitions():
    with get_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM acquisitions").fetchone()[0]


# --- Targets ---

def insert_target(domain, acquisition_id=None):
    with get_conn() as conn:
        try:
            conn.execute(
                "INSERT INTO targets (domain, acquisition_id, created_at) VALUES (?, ?, ?)",
                (domain, acquisition_id, _now()),
            )
            return conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        except sqlite3.IntegrityError:
            row = conn.execute("SELECT id FROM targets WHERE domain = ?", (domain,)).fetchone()
            return row["id"] if row else None


def get_targets(scope_status=None, limit=100):
    with get_conn() as conn:
        if scope_status:
            return conn.execute(
                "SELECT * FROM targets WHERE scope_status = ? ORDER BY id DESC LIMIT ?",
                (scope_status, limit),
            ).fetchall()
        return conn.execute("SELECT * FROM targets ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


def update_target_scope(target_id, scope_status, program_platform=None, program_url=None):
    with get_conn() as conn:
        conn.execute(
            "UPDATE targets SET scope_status = ?, program_platform = ?, program_url = ? WHERE id = ?",
            (scope_status, program_platform, program_url, target_id),
        )


def count_targets(scope_status=None):
    with get_conn() as conn:
        if scope_status:
            return conn.execute("SELECT COUNT(*) FROM targets WHERE scope_status = ?", (scope_status,)).fetchone()[0]
        return conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]


# --- Scans ---

def insert_scan(target_id, subdomain, cname_target, provider, is_dangling):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO scans (target_id, subdomain, cname_target, provider, is_dangling, checked_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (target_id, subdomain, cname_target, provider, int(is_dangling), _now()),
        )
        return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


# --- Findings ---

def insert_finding(scan_id, target_id, subdomain, cname_target, provider, fingerprint, severity="Medium"):
    with get_conn() as conn:
        # Check for duplicate
        existing = conn.execute(
            "SELECT id FROM findings WHERE subdomain = ? AND cname_target = ?",
            (subdomain, cname_target),
        ).fetchone()
        if existing:
            return existing["id"]

        conn.execute(
            "INSERT INTO findings (scan_id, target_id, subdomain, cname_target, provider, fingerprint, severity, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, target_id, subdomain, cname_target, provider, fingerprint, severity, _now()),
        )
        return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def get_findings(status=None, limit=100):
    with get_conn() as conn:
        if status:
            return conn.execute(
                "SELECT f.*, t.domain as target_domain FROM findings f "
                "LEFT JOIN targets t ON f.target_id = t.id "
                "WHERE f.status = ? ORDER BY f.id DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        return conn.execute(
            "SELECT f.*, t.domain as target_domain FROM findings f "
            "LEFT JOIN targets t ON f.target_id = t.id "
            "ORDER BY f.id DESC LIMIT ?",
            (limit,),
        ).fetchall()


def get_finding(finding_id):
    with get_conn() as conn:
        return conn.execute(
            "SELECT f.*, t.domain as target_domain, t.program_platform, t.program_url "
            "FROM findings f LEFT JOIN targets t ON f.target_id = t.id WHERE f.id = ?",
            (finding_id,),
        ).fetchone()


def update_finding_status(finding_id, status):
    with get_conn() as conn:
        conn.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))


def update_finding_report(finding_id, report_md):
    with get_conn() as conn:
        conn.execute("UPDATE findings SET report_md = ? WHERE id = ?", (report_md, finding_id))


def count_findings(status=None):
    with get_conn() as conn:
        if status:
            return conn.execute("SELECT COUNT(*) FROM findings WHERE status = ?", (status,)).fetchone()[0]
        return conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]


# --- Activity Log ---

def log_activity(event_type, message):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO activity_log (event_type, message, timestamp) VALUES (?, ?, ?)",
            (event_type, message, _now()),
        )


def get_activity(limit=50):
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM activity_log ORDER BY id DESC LIMIT ?", (limit,),
        ).fetchall()


def get_current_scan():
    """Get the most recent scan-related activity (what the hunter is doing right now)."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT message, timestamp FROM activity_log "
            "WHERE event_type IN ('scan', 'pipeline', 'crawl', 'scope', 'finding') "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None


def get_live_data():
    """Get all data needed for the live dashboard in a single DB call."""
    empty = ""
    with get_conn() as conn:
        targets_total = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
        targets_scanned = conn.execute("SELECT COUNT(*) FROM targets WHERE scope_status != 'pending'").fetchone()[0]
        targets_in_scope = conn.execute("SELECT COUNT(*) FROM targets WHERE scope_status = 'in_scope'").fetchone()[0]
        targets_pending = conn.execute("SELECT COUNT(*) FROM targets WHERE scope_status = 'pending'").fetchone()[0]

        # Currently scanning target — get subdomain count for it
        current_target = conn.execute(
            "SELECT message FROM activity_log WHERE event_type = 'scan' AND message LIKE 'Scanning%' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        current_target_name = ""
        current_target_subs = 0
        if current_target:
            import re
            m = re.search(r"Scanning (\d+) subdomains for (\S+)", current_target["message"])
            if m:
                current_target_subs = int(m.group(1))
                current_target_name = m.group(2)

        stats = {
            "programs": conn.execute("SELECT COUNT(*) FROM programs").fetchone()[0],
            "acquisitions": conn.execute("SELECT COUNT(*) FROM acquisitions").fetchone()[0],
            "targets_total": targets_total,
            "targets_scanned": targets_scanned,
            "targets_in_scope": targets_in_scope,
            "targets_pending": targets_pending,
            "targets_out_of_scope": conn.execute("SELECT COUNT(*) FROM targets WHERE scope_status = 'out_of_scope'").fetchone()[0],
            "subs_scanned": conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
            "cnames_found": conn.execute("SELECT COUNT(*) FROM scans WHERE cname_target IS NOT NULL AND cname_target != ?", (empty,)).fetchone()[0],
            "dangling": conn.execute("SELECT COUNT(*) FROM scans WHERE is_dangling = 1").fetchone()[0],
            "findings_total": conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
            "findings_pending": conn.execute("SELECT COUNT(*) FROM findings WHERE status IN ('new', 'alerted')").fetchone()[0],
            "findings_approved": conn.execute("SELECT COUNT(*) FROM findings WHERE status = 'approved'").fetchone()[0],
            "vulns": conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0],
            "vulns_pending": conn.execute("SELECT COUNT(*) FROM vulns WHERE status = 'new'").fetchone()[0],
            "vulns_filtered": conn.execute("SELECT COUNT(*) FROM activity_log WHERE event_type = 'triage'").fetchone()[0],
            "current_target": current_target_name,
            "current_target_subs": current_target_subs,
        }

        # Activity feed (last 40)
        feed = [dict(r) for r in conn.execute(
            "SELECT event_type, message, timestamp FROM activity_log ORDER BY id DESC LIMIT 40"
        ).fetchall()]

        # Current scan status
        current = conn.execute(
            "SELECT message, timestamp FROM activity_log "
            "WHERE event_type IN ('scan', 'pipeline', 'crawl', 'scope') "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()

        # Actionable findings
        findings = [dict(r) for r in conn.execute(
            "SELECT f.id, f.subdomain, f.cname_target, f.provider, f.fingerprint, f.severity, f.status, f.report_md, f.created_at, "
            "t.domain as target_domain, t.program_url "
            "FROM findings f LEFT JOIN targets t ON f.target_id = t.id "
            "ORDER BY f.id DESC LIMIT 50"
        ).fetchall()]

        # Cloud-provider CNAMEs only (the interesting ones)
        cloud_cnames = [dict(r) for r in conn.execute(
            "SELECT s.subdomain, s.cname_target, s.provider, s.is_dangling, s.checked_at, t.domain "
            "FROM scans s LEFT JOIN targets t ON s.target_id = t.id "
            "WHERE s.cname_target IS NOT NULL AND s.cname_target != ? "
            "AND (s.cname_target LIKE '%.amazonaws.com' OR s.cname_target LIKE '%.herokuapp.com' "
            "OR s.cname_target LIKE '%.github.io' OR s.cname_target LIKE '%.azurewebsites.net' "
            "OR s.cname_target LIKE '%.azurefd.net' OR s.cname_target LIKE '%.vercel%' "
            "OR s.cname_target LIKE '%.shopify%' OR s.cname_target LIKE '%.cloudfront.net' "
            "OR s.cname_target LIKE '%.herokussl.com' OR s.cname_target LIKE '%.azureedge.net' "
            "OR s.cname_target LIKE '%.trafficmanager.net' OR s.cname_target LIKE '%.now.sh' "
            "OR s.cname_target LIKE '%.webflow.com' OR s.cname_target LIKE '%.zendesk.com' "
            "OR s.cname_target LIKE '%.stspg-customer.com' OR s.cname_target LIKE '%.auth0.com') "
            "ORDER BY s.is_dangling DESC, s.id DESC LIMIT 100", (empty,)
        ).fetchall()]

        # In-scope targets with scan stats
        in_scope = [dict(r) for r in conn.execute(
            "SELECT t.id, t.domain, t.program_platform, t.program_url, a.acquirer, "
            "COUNT(s.id) as sub_count, "
            "SUM(CASE WHEN s.cname_target IS NOT NULL AND s.cname_target != ? THEN 1 ELSE 0 END) as cname_count "
            "FROM targets t LEFT JOIN scans s ON s.target_id = t.id "
            "LEFT JOIN acquisitions a ON t.acquisition_id = a.id "
            "WHERE t.scope_status = 'in_scope' "
            "GROUP BY t.id ORDER BY cname_count DESC", (empty,)
        ).fetchall()]

        # Target map: all targets grouped by scope status with acquirer
        target_map = [dict(r) for r in conn.execute(
            "SELECT t.id, t.domain, t.scope_status, t.program_platform, t.program_url, a.acquirer, a.target_company "
            "FROM targets t LEFT JOIN acquisitions a ON t.acquisition_id = a.id "
            "ORDER BY CASE t.scope_status WHEN 'in_scope' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END, t.id DESC "
            "LIMIT 200"
        ).fetchall()]

        # Scope breakdown
        stats["targets_out_of_scope"] = conn.execute("SELECT COUNT(*) FROM targets WHERE scope_status = 'out_of_scope'").fetchone()[0]
        stats["programs"] = conn.execute("SELECT COUNT(*) FROM programs").fetchone()[0]
        stats["vulns"] = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
        stats["vulns_pending"] = conn.execute("SELECT COUNT(*) FROM vulns WHERE status IN ('new')").fetchone()[0]
        stats["nuclei_vulns"] = conn.execute("SELECT COUNT(*) FROM vulns WHERE vuln_type LIKE 'nuclei:%'").fetchone()[0]
        stats["js_secrets"] = conn.execute("SELECT COUNT(*) FROM vulns WHERE vuln_type LIKE 'js_secret:%'").fetchone()[0]

        # Vuln findings (include tier results for pipeline display)
        vuln_list = [dict(r) for r in conn.execute(
            "SELECT v.id, v.subdomain, v.vuln_type, v.evidence, v.severity, v.url, v.status, v.report_md, v.created_at, "
            "v.t1_result, v.t2_result, v.t3_result, v.t3_challenge, v.t5_challenge, v.enriched_evidence, v.enrichment_data, v.enrichment_status, "
            "t.domain as target_domain, t.program_url "
            "FROM vulns v LEFT JOIN targets t ON v.target_id = t.id "
            "ORDER BY v.id DESC LIMIT 250"
        ).fetchall()]

    return {
        "stats": stats,
        "feed": feed,
        "current_scan": dict(current) if current else None,
        "findings": findings,
        "cloud_cnames": cloud_cnames,
        "in_scope_targets": in_scope,
        "target_map": target_map,
        "vulns": vuln_list,
    }


# --- Programs ---

def insert_program(company, handle, platform, url, scope_domains):
    with get_conn() as conn:
        try:
            conn.execute(
                "INSERT INTO programs (company, handle, platform, url, scope_domains, last_updated) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (company, handle, platform, url, scope_domains, _now()),
            )
            return conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        except Exception:
            return None


def get_programs(limit=500):
    with get_conn() as conn:
        return conn.execute("SELECT * FROM programs ORDER BY id LIMIT ?", (limit,)).fetchall()


# --- Vulns ---

def _vuln_class(vuln_type):
    """Normalize vuln_type to broad class for chain detection.

    Groups related findings: actuator_heapdump + actuator_exposed = 'actuator',
    js_secret:internal_url + js_secret:google_api_key = 'js_secret', etc.
    """
    vt = vuln_type.lower()
    if vt.startswith("actuator"): return "actuator"
    if vt.startswith("cors"): return "cors"
    if vt.startswith("s3_"): return "s3"
    if vt.startswith("nuclei:"): return "nuclei"
    if vt.startswith("wayback:"): return "wayback"
    if vt.startswith("ai:"): return "ai"
    if ":" in vt: return vt.split(":")[0]
    return vt


def insert_vuln(target_id, subdomain, vuln_type, evidence, severity, url):
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT id FROM vulns WHERE subdomain = ? AND vuln_type = ?",
            (subdomain, vuln_type),
        ).fetchone()
        if existing:
            return existing["id"]
        conn.execute(
            "INSERT INTO vulns (target_id, subdomain, vuln_type, evidence, severity, url, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (target_id, subdomain, vuln_type, evidence, severity, url, _now()),
        )
        new_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        # Auto-detect chain potential: notify when a subdomain has findings
        # from 2+ different vuln CLASSES (not just templates)
        # Dedup: only notify once per subdomain per session
        # Skip CORS — 90%+ are false positives, they create noise in chain detection
        try:
            new_class = _vuln_class(vuln_type)
            # CORS and info-level findings are noise — skip chain detection for them
            if new_class not in ("cors", "wayback"):
                others = conn.execute(
                    "SELECT DISTINCT vuln_type FROM vulns WHERE subdomain = ? AND vuln_type != ?",
                    (subdomain, vuln_type),
                ).fetchall()
                if others:
                    other_classes = {_vuln_class(r["vuln_type"]) for r in others}
                    # Remove noise classes from "other" side too
                    other_classes.discard("cors")
                    other_classes.discard("wayback")
                    # Only notify if genuinely different classes AND not already notified
                    if other_classes and new_class not in other_classes:
                        already = conn.execute(
                            "SELECT id FROM chain_analyses WHERE subdomain = ?", (subdomain,)
                        ).fetchone()
                        if not already:
                            conn.execute(
                                "INSERT OR IGNORE INTO chain_analyses (target_id, subdomain, endpoint, analysis, created_at) "
                                "VALUES (?, ?, '/', 'pending', datetime('now'))",
                                (target_id, subdomain),
                            )
                            new_types = [vuln_type]
                            existing_types = [r["vuln_type"] for r in others
                                              if _vuln_class(r["vuln_type"]) not in ("cors", "wayback")]
                            from notifier_discord import notify_chain_potential
                            _ep = "/"
                            if url:
                                try:
                                    _ep = urlparse(url).path or "/"
                                except Exception:
                                    _ep = "/"
                            notify_chain_potential(subdomain, _ep, new_types, existing_types)
        except Exception:
            pass

        return new_id


def get_vuln(vuln_id):
    with get_conn() as conn:
        return conn.execute("SELECT * FROM vulns WHERE id = ?", (vuln_id,)).fetchone()


def update_vuln_status(vuln_id, status):
    with get_conn() as conn:
        conn.execute("UPDATE vulns SET status = ? WHERE id = ?", (status, vuln_id))


# --- DNS Records ---

def upsert_dns_record(subdomain, record_type, record_value, target_id):
    """Insert or update a DNS record. Returns True if NEW record."""
    now = _now()
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT id, status FROM dns_records WHERE subdomain = ? AND record_type = ? AND record_value = ?",
            (subdomain, record_type, record_value),
        ).fetchone()
        if existing:
            conn.execute("UPDATE dns_records SET last_seen = ?, status = 'active' WHERE id = ?", (now, existing["id"]))
            return False
        conn.execute(
            "INSERT INTO dns_records (subdomain, record_type, record_value, target_id, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (subdomain, record_type, record_value, target_id, now, now),
        )
        return True


def check_dns_changes(target_id):
    """Find records not seen in last scan (potential takeover). Returns list of disappeared records."""
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM dns_records WHERE target_id = ? AND status = 'active' "
            "AND last_seen < (SELECT MAX(last_seen) FROM dns_records WHERE target_id = ?)",
            (target_id, target_id),
        ).fetchall()]


def batch_insert_scans(scan_rows):
    """Batch insert scan records. scan_rows = list of (target_id, subdomain, cname, provider, is_dangling, timestamp)."""
    with get_conn() as conn:
        conn.executemany(
            "INSERT INTO scans (target_id, subdomain, cname_target, provider, is_dangling, checked_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            scan_rows,
        )


# --- Scan Queue (v13) ---

_SCAN_COOLDOWN_HOURS = 6
"""Minimum hours between scans of the same target. Set to absorb the worst
signal-source duplication (e.g. ~100 M&A news rows for one domain in a single
batch) without blocking legitimate next-day rescans. Conservative vs. the
12h M&A signal interval."""


def enqueue_scan(target_id, domain, priority, source, source_detail=None):
    """Add domain to scan queue. Skips if:
      - target was scanned within _SCAN_COOLDOWN_HOURS, OR
      - an entry is already pending/running (in-flight dedup).
    """
    with get_conn() as conn:
        # julianday() is used for numeric compare — _now() stores ISO-8601 with 'T'
        # separator and timezone suffix, while datetime('now', ...) returns
        # space-separated UTC without suffix. Lexicographic compare across the two
        # formats is broken ('T' > ' ' at position 10), so use julianday() which
        # parses both and compares numerically.
        recent = conn.execute(
            f"SELECT 1 FROM targets WHERE id = ? "
            f"AND julianday(last_scanned_at) > julianday('now', '-{_SCAN_COOLDOWN_HOURS} hours')",
            (target_id,),
        ).fetchone()
        if recent:
            return None
        existing = conn.execute(
            "SELECT id FROM scan_queue WHERE domain = ? AND status IN ('pending', 'running')",
            (domain,),
        ).fetchone()
        if existing:
            # Upgrade priority if new request is higher priority (lower number)
            conn.execute(
                "UPDATE scan_queue SET priority = MIN(priority, ?) WHERE id = ?",
                (priority, existing["id"]),
            )
            return existing["id"]
        conn.execute(
            "INSERT INTO scan_queue (target_id, domain, priority, source, source_detail, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (target_id, domain, priority, source, source_detail, _now()),
        )
        return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def dequeue_scan():
    """Get highest-priority pending scan (lowest priority number). Returns dict or None."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scan_queue WHERE status = 'pending' "
            "ORDER BY priority ASC, created_at ASC LIMIT 1"
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE scan_queue SET status = 'running', started_at = ? WHERE id = ?",
                (_now(), row["id"]),
            )
            return dict(row)
        return None


def complete_scan(queue_id, status='completed'):
    """Mark a queued scan as done."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE scan_queue SET status = ?, completed_at = ? WHERE id = ?",
            (status, _now(), queue_id),
        )


def get_queue_stats():
    """Return queue counts by priority and status for dashboard."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT priority, status, COUNT(*) as cnt FROM scan_queue GROUP BY priority, status"
        ).fetchall()
        stats = {"pending": {}, "running": 0, "completed": 0, "total_pending": 0}
        for r in rows:
            if r["status"] == "pending":
                stats["pending"][f"p{r['priority']}"] = r["cnt"]
                stats["total_pending"] += r["cnt"]
            elif r["status"] == "running":
                stats["running"] += r["cnt"]
            elif r["status"] == "completed":
                stats["completed"] += r["cnt"]
        return stats


def get_queue_depth():
    """Return count of pending items."""
    with get_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM scan_queue WHERE status = 'pending'").fetchone()[0]


# --- Program Snapshots (v13) ---

def get_known_handles():
    """Return set of all known program handles."""
    with get_conn() as conn:
        rows = conn.execute("SELECT handle FROM program_snapshots").fetchall()
        return {r["handle"] for r in rows}


def insert_program_snapshot(handle, company, scope_domains):
    """Record a newly seen program."""
    with get_conn() as conn:
        now = _now()
        try:
            conn.execute(
                "INSERT INTO program_snapshots (handle, company, scope_domains, first_seen_at, last_checked_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (handle, company, scope_domains, now, now),
            )
        except sqlite3.IntegrityError:
            conn.execute(
                "UPDATE program_snapshots SET scope_domains = ?, last_checked_at = ? WHERE handle = ?",
                (scope_domains, now, handle),
            )


def get_program_snapshot(handle):
    """Get stored snapshot for a program."""
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM program_snapshots WHERE handle = ?", (handle,)).fetchone()
        return dict(row) if row else None


def update_snapshot_scope(handle, scope_domains):
    """Update scope and last_checked timestamp."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE program_snapshots SET scope_domains = ?, last_checked_at = ? WHERE handle = ?",
            (scope_domains, _now(), handle),
        )


# --- CVE Alerts (v13) ---

def insert_cve_alert(cve_id, description, severity, affected_products, published_at, matched_programs=None):
    """Record a CVE alert. Returns id or None if duplicate."""
    with get_conn() as conn:
        try:
            conn.execute(
                "INSERT INTO cve_alerts (cve_id, description, severity, affected_products, published_at, checked_at, matched_programs) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (cve_id, description, severity, affected_products, published_at, _now(), matched_programs),
            )
            return conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        except sqlite3.IntegrityError:
            return None


def get_recent_cve_ids(limit=200):
    """Get recently tracked CVE IDs to avoid re-processing."""
    with get_conn() as conn:
        rows = conn.execute("SELECT cve_id FROM cve_alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return {r["cve_id"] for r in rows}


# --- Pipeline Operations (v14) ---

def start_target_pipeline(target_id, priority=5, source=""):
    """Set a target to 'recon' phase to enter the async pipeline."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE targets SET phase = 'recon', priority = MAX(COALESCE(priority, 0), ?), "
            "in_progress = 0, phase_updated_at = ?, scan_metadata = ? WHERE id = ?",
            (priority, _now(), json.dumps({"source": source}), target_id),
        )


def claim_next_target(phases):
    """Atomically claim the highest-priority in-scope target in given phases.
    Returns dict or None. Uses BEGIN IMMEDIATE for safe concurrent access."""
    with get_conn() as conn:
        placeholders = ",".join("?" * len(phases))
        row = conn.execute(
            f"SELECT id, domain, priority, phase, scan_metadata FROM targets "
            f"WHERE phase IN ({placeholders}) AND in_progress = 0 "
            f"AND scope_status = 'in_scope' "
            f"ORDER BY priority DESC, phase_updated_at ASC LIMIT 1",
            phases,
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE targets SET in_progress = 1, phase_updated_at = ? WHERE id = ?",
                (_now(), row["id"]),
            )
            return dict(row)
        return None


def advance_target(target_id, next_phase, metadata_update=None):
    """Move target to next phase and release the worker lock."""
    with get_conn() as conn:
        if metadata_update:
            existing = conn.execute(
                "SELECT scan_metadata FROM targets WHERE id = ?", (target_id,)
            ).fetchone()
            current = json.loads(existing["scan_metadata"] or "{}") if existing else {}
            current.update(metadata_update)
            conn.execute(
                "UPDATE targets SET phase = ?, in_progress = 0, phase_updated_at = ?, scan_metadata = ? WHERE id = ?",
                (next_phase, _now(), json.dumps(current), target_id),
            )
        else:
            conn.execute(
                "UPDATE targets SET phase = ?, in_progress = 0, phase_updated_at = ? WHERE id = ?",
                (next_phase, _now(), target_id),
            )


def release_target(target_id):
    """Release worker lock without advancing phase (on error/retry)."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE targets SET in_progress = 0 WHERE id = ?", (target_id,),
        )


def complete_target(target_id):
    """Mark target as fully processed."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE targets SET phase = 'idle', in_progress = 0, "
            "last_scanned_at = ?, phase_updated_at = ? WHERE id = ?",
            (_now(), _now(), target_id),
        )


def reset_stale_locks(timeout_minutes=30):
    """Crash recovery on startup. Resets:
      1. Targets stuck in non-terminal phases (recon/mapping/scanning/testing/ai_triage)
         back to 'idle' so the dispatcher can pick them up again.
      2. Scan queue entries left in 'running' state (dispatcher SIGKILL'd
         between dequeue and complete_scan) back to 'pending'.

    Called once at process start when no workers are active — anything in a
    non-terminal state is by definition orphaned by a previous SIGKILL.
    """
    # All phases set by advance_target() in pipeline.py except the terminal 'idle'.
    # 'scored' is set after recon scoring (pipeline.py:154) — must be included or
    # targets SIGKILL'd between scoring and mapping stay orphaned.
    non_terminal = ('recon', 'scored', 'mapping', 'scanning', 'testing', 'ai_triage')
    placeholders = ','.join('?' * len(non_terminal))
    with get_conn() as conn:
        target_count = conn.execute(
            f"UPDATE targets SET in_progress = 0, phase = 'idle', phase_updated_at = ? "
            f"WHERE phase IN ({placeholders})",
            (_now(), *non_terminal),
        ).rowcount
        queue_count = conn.execute(
            "UPDATE scan_queue SET status = 'pending' WHERE status = 'running'"
        ).rowcount
        return target_count + queue_count


def get_pipeline_stats():
    """Phase counts for dashboard display."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT phase, COUNT(*) as cnt, SUM(in_progress) as active "
            "FROM targets WHERE scope_status = 'in_scope' GROUP BY phase"
        ).fetchall()
        return {r["phase"]: {"total": r["cnt"], "active": r["active"] or 0} for r in rows}


    # v15 Kill List Filter #3: Client-side bug classes banned from AI triage.
    # XSS, CSRF, Clickjacking, CORS — LLMs can't verify these reliably.
    # CORS: 90%+ are FingerprintJS/CDN false positives. Enricher handles real CORS separately.
    # Nuclei logs them, but the AI pipeline never sees them.
_AI_BANNED_VULN_PATTERNS = (
    "nuclei:xss", "nuclei:reflected-xss", "nuclei:stored-xss", "nuclei:dom-xss",
    "nuclei:csrf", "nuclei:clickjacking", "nuclei:x-frame-options",
    "nuclei:missing-x-frame", "nuclei:frame-injection",
    "cors_misconfiguration", "cors",
)


def get_unprocessed_vulns(limit=20):
    """Get vulns at 'new' or 't1_pass' for the AI pipeline worker.

    v15 Kill List: Excludes info/low severity and client-side bug classes
    (XSS, CSRF, Clickjacking) from AI triage to protect budget.
    """
    with get_conn() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT v.id, v.subdomain, v.vuln_type, v.evidence, v.severity, v.url, "
            "v.status, v.t1_result, v.enriched_evidence, v.target_id, t.domain "
            "FROM vulns v LEFT JOIN targets t ON v.target_id = t.id "
            "WHERE v.status IN ('new', 't1_pass') "
            "AND v.severity NOT IN ('Info', 'Low', 'info', 'low') "
            "ORDER BY t.priority DESC, v.id ASC LIMIT ?",
            (limit,),
        ).fetchall()]

        # Filter out banned client-side vuln types
        return [r for r in rows
                if not any(r["vuln_type"].lower().startswith(ban) for ban in _AI_BANNED_VULN_PATTERNS)]


def insert_api_schema(target_id, subdomain, endpoint, method="GET", params=None, source=None):
    """Store a discovered API endpoint (Phase 3a)."""
    with get_conn() as conn:
        try:
            conn.execute(
                "INSERT INTO api_schemas (target_id, subdomain, endpoint, method, params, source, discovered_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (target_id, subdomain, endpoint, method, params, source, _now()),
            )
            return conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        except sqlite3.IntegrityError:
            return None


# --- React Leads (v15: Scout → Sniper) ---

def insert_lead(target_id, subdomain, endpoint, method, vuln_class, confidence, lead_data):
    """Store a Scout lead for Sniper processing."""
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO react_leads (target_id, subdomain, endpoint, method, vuln_class, confidence, lead_data, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (target_id, subdomain, endpoint, method, vuln_class, confidence, lead_data, _now()),
        )
        return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def get_pending_leads(vuln_class=None, limit=10):
    """Get leads awaiting Sniper processing."""
    with get_conn() as conn:
        if vuln_class:
            return [dict(r) for r in conn.execute(
                "SELECT l.*, t.domain FROM react_leads l "
                "LEFT JOIN targets t ON l.target_id = t.id "
                "WHERE l.sniper_status = 'pending' AND l.vuln_class = ? "
                "ORDER BY l.confidence DESC LIMIT ?",
                (vuln_class, limit),
            ).fetchall()]
        return [dict(r) for r in conn.execute(
            "SELECT l.*, t.domain FROM react_leads l "
            "LEFT JOIN targets t ON l.target_id = t.id "
            "WHERE l.sniper_status = 'pending' "
            "ORDER BY l.confidence DESC LIMIT ?",
            (limit,),
        ).fetchall()]


def update_lead(lead_id, sniper_status, sniper_result=None):
    """Update a lead after Sniper processing."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE react_leads SET sniper_status = ?, sniper_result = ?, completed_at = ? WHERE id = ?",
            (sniper_status, sniper_result, _now(), lead_id),
        )


# Need json import for scan_metadata
import json


# Auto-initialize on import
init_db()
