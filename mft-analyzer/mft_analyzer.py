#!/usr/bin/env python3
"""MFT Analyzer - a forensic GUI for exploring $MFT exports produced by MFTECmd.

Data engine: DuckDB. The CSV is indexed once into a cached .duckdb file (next to
the CSV, or under ~/.cache/mft_analyzer when the source directory is not
writable, e.g. read-only mounted evidence). Subsequent loads of the same file
are near-instant, and filtering / sorting / exporting run as vectorised SQL
queries instead of loading the whole file into Python memory.

Usage:
    python3 mft_analyzer.py [path/to/MFTECmd_output.csv]

Requirement: duckdb (pip install duckdb)
Optional: matplotlib, for the exfiltration score histogram (pip install matplotlib)
"""

import argparse
import csv
import datetime
import hashlib
import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    import duckdb
except ImportError:
    print("This tool requires duckdb: pip install duckdb", file=sys.stderr)
    sys.exit(1)

try:
    import matplotlib

    matplotlib.use("TkAgg")
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
    from matplotlib.figure import Figure

    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


from config import (
    APP_NAME,
    ARCHIVE_EXTENSIONS,
    BOOL_COLUMNS,
    COLUMN_WIDTHS,
    DATE_COLUMNS,
    DATE_INPUT_FORMATS,
    DEFAULT_COLUMN_WIDTH,
    DEFAULT_COLUMNS,
    DELTA_COLUMNS,
    HIGH_SCORE_THRESHOLD,
    MACB_COLUMNS,
    NUMERIC_COLUMNS,
    OLD_COPY_DELTA_DAYS,
    PAGE_SIZE_DEFAULT,
    POINTS_ARCHIVE,
    POINTS_DELETED_ARCHIVE,
    POINTS_OLD_COPY,
    POINTS_STAGING_LOCATION,
    POINTS_STAGING_STRONG,
    POINTS_STAGING_WEAK,
    ROW_COLORS,
    ROW_TAG_COLUMNS,
    SCORE_COLUMN,
    SCORE_MAX,
    STAGING_CREATED_SPAN_SECONDS,
    STAGING_LOCATION_KEYWORDS,
    STAGING_MIN_FILES_STRONG,
    STAGING_MIN_FILES_WEAK,
    STAGING_MODIFIED_SPAN_DAYS,
    TIMELINE_CONTEXT_COLUMNS,
    TIMELINE_DISPLAY_LIMIT,
    VERY_HIGH_SCORE_THRESHOLD,
)


# Bump when the ingestion logic changes, to invalidate existing .duckdb caches.
CACHE_SCHEMA_VERSION = "3"


# ---------- helpers ----------

def qident(name):
    """Quote an SQL identifier."""
    return '"' + name.replace('"', '""') + '"'


def sql_literal(text):
    """Quote a string as an SQL literal (only where parameters are not allowed, e.g. COPY ... TO)."""
    return "'" + text.replace("'", "''") + "'"


def format_timedelta(td):
    if td is None:
        return ""
    total_seconds = int(td.total_seconds())
    sign = "-" if total_seconds < 0 else ""
    days, rem = divmod(abs(total_seconds), 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)
    return f"{sign}{days}d {hours:02d}:{minutes:02d}:{seconds:02d}"


def format_size(n):
    if n is None:
        return ""
    n = float(n)
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(n) < 1024:
            return f"{int(n)} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def format_int(n):
    return f"{n:,}"


def format_value(value, precise=False):
    """Human-readable rendering of a DuckDB value."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, datetime.datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S.%f" if precise else "%Y-%m-%d %H:%M:%S")
    if isinstance(value, datetime.timedelta):
        return format_timedelta(value)
    return str(value)


def parse_user_datetime(text, end_of_range=False):
    """Parse a date typed by the user. A bare end date covers the whole day."""
    text = text.strip()
    for fmt in DATE_INPUT_FORMATS:
        try:
            value = datetime.datetime.strptime(text, fmt)
        except ValueError:
            continue
        if end_of_range and fmt == "%Y-%m-%d":
            value = value.replace(hour=23, minute=59, second=59, microsecond=999999)
        return value
    raise ValueError(f"Invalid date: '{text}'. Expected YYYY-MM-DD or YYYY-MM-DD HH:MM[:SS].")


class MFTStore:
    """Data access layer: CSV -> DuckDB ingestion, then SQL queries."""

    def __init__(self):
        self.con = None
        self.columns = []
        self.total_rows = 0
        self.cache_path = None
        self.has_folder_stats = False
        self.score_sql = None

    @property
    def is_loaded(self):
        return self.con is not None

    def has(self, *names):
        return all(name in self.columns for name in names)

    def close(self):
        if self.con is not None:
            self.con.close()
        self.con = None
        self.columns = []
        self.total_rows = 0
        self.has_folder_stats = False
        self.score_sql = None

    # ---------- loading / caching ----------

    @staticmethod
    def cache_path_for(csv_path):
        base = os.path.splitext(os.path.basename(csv_path))[0]
        source_dir = os.path.dirname(os.path.abspath(csv_path))
        if os.access(source_dir, os.W_OK):
            return os.path.join(source_dir, base + ".mft.duckdb")
        cache_dir = os.path.join(os.path.expanduser("~"), ".cache", "mft_analyzer")
        os.makedirs(cache_dir, exist_ok=True)
        key = hashlib.sha1(os.path.abspath(csv_path).encode("utf-8")).hexdigest()[:16]
        return os.path.join(cache_dir, f"{base}_{key}.mft.duckdb")

    def load(self, csv_path, force_reindex=False):
        self.close()
        self.cache_path = self.cache_path_for(csv_path)
        try:
            self.con = duckdb.connect(self.cache_path)
            if force_reindex or not self._cache_is_valid(csv_path):
                self._ingest(csv_path)
            self._read_schema()
        except Exception:
            self.close()
            raise

    def _read_schema(self):
        info = self.con.execute("PRAGMA table_info('mft')").fetchall()
        self.columns = [row[1] for row in info if row[1] != "_rid"]
        self.total_rows = self.con.execute("SELECT count(*) FROM mft").fetchone()[0]
        self.has_folder_stats = (
            self.con.execute(
                "SELECT count(*) FROM information_schema.tables WHERE table_name = 'folder_stats'"
            ).fetchone()[0]
            > 0
        )
        self.score_sql = self._build_score_expression()

    @staticmethod
    def _source_fingerprint(csv_path):
        stat = os.stat(csv_path)
        # Column typing comes from config.py: editing it must invalidate the cache too.
        typing = repr((sorted(BOOL_COLUMNS), sorted(DATE_COLUMNS), sorted(NUMERIC_COLUMNS)))
        return {
            "source_path": os.path.abspath(csv_path),
            "source_size": str(stat.st_size),
            "source_mtime": str(int(stat.st_mtime)),
            "schema_version": CACHE_SCHEMA_VERSION,
            "column_typing": hashlib.sha1(typing.encode("utf-8")).hexdigest(),
        }

    def _cache_is_valid(self, csv_path):
        try:
            meta = dict(self.con.execute("SELECT key, value FROM _meta").fetchall())
        except duckdb.Error:
            return False
        return meta == self._source_fingerprint(csv_path)

    def _ingest(self, csv_path):
        con = self.con
        for table in ("_meta", "mft", "raw_mft", "folder_stats"):
            con.execute(f"DROP TABLE IF EXISTS {table}")

        rel = con.read_csv(csv_path, all_varchar=True)
        header = list(rel.columns)
        rel.create("raw_mft")

        select_exprs = ["row_number() OVER () AS _rid"]
        for col in header:
            q = qident(col)
            if col in BOOL_COLUMNS:
                select_exprs.append(f"(CASE lower({q}) WHEN 'true' THEN true WHEN 'false' THEN false END) AS {q}")
            elif col in DATE_COLUMNS:
                # MFTECmd writes 7 fractional digits; Python/DuckDB %f accepts 6.
                select_exprs.append(
                    f"COALESCE(try_strptime(substr({q}, 1, 26), '%Y-%m-%d %H:%M:%S.%f'), "
                    f"try_strptime(substr({q}, 1, 19), '%Y-%m-%d %H:%M:%S')) AS {q}"
                )
            elif col in NUMERIC_COLUMNS:
                select_exprs.append(f"TRY_CAST({q} AS BIGINT) AS {q}")
            else:
                select_exprs.append(q)

        select_sql = ",\n        ".join(select_exprs)
        con.execute(f"CREATE TABLE mft AS SELECT\n        {select_sql}\n    FROM raw_mft")
        con.execute("DROP TABLE raw_mft")

        if "ParentPath" in header and "Created0x10" in header:
            modified_span_expr = (
                'max("LastModified0x10") - min("LastModified0x10")'
                if "LastModified0x10" in header
                else "NULL"
            )
            con.execute(
                f"""
                CREATE TABLE folder_stats AS
                SELECT "ParentPath",
                       count(*) AS file_count,
                       max("Created0x10") - min("Created0x10") AS created_span,
                       {modified_span_expr} AS modified_span
                FROM mft
                WHERE "ParentPath" IS NOT NULL
                GROUP BY "ParentPath"
                """
            )

        # Written last: an interrupted ingestion leaves no _meta and is redone next time.
        con.execute("CREATE TABLE _meta(key VARCHAR, value VARCHAR)")
        con.executemany("INSERT INTO _meta VALUES (?, ?)", list(self._source_fingerprint(csv_path).items()))
        con.execute("CHECKPOINT")

    # ---------- SQL building blocks ----------

    def _base_from(self, needs_score):
        if needs_score and self.has_folder_stats:
            return 'mft LEFT JOIN folder_stats USING ("ParentPath")'
        return "mft"

    def _from_where(self, where_sql, needs_score):
        sql = f" FROM {self._base_from(needs_score)}"
        if where_sql:
            sql += f" WHERE {where_sql}"
        return sql

    @staticmethod
    def _order_by(order_by, ascending):
        # _rid as tie-breaker keeps LIMIT/OFFSET pagination deterministic.
        if order_by:
            return f' ORDER BY {qident(order_by)} {"ASC" if ascending else "DESC"} NULLS LAST, _rid'
        return " ORDER BY _rid"

    def _build_score_expression(self):
        """Heuristic 0-10 score: a triage aid, not proof. See explain_score()."""
        terms = []

        if self.has_folder_stats:
            staging = (
                f"created_span <= INTERVAL {STAGING_CREATED_SPAN_SECONDS} SECOND "
                f"AND modified_span >= INTERVAL {STAGING_MODIFIED_SPAN_DAYS} DAY"
            )
            terms.append(
                f"CASE WHEN file_count >= {STAGING_MIN_FILES_STRONG} AND {staging} THEN {POINTS_STAGING_STRONG} "
                f"WHEN file_count >= {STAGING_MIN_FILES_WEAK} AND {staging} THEN {POINTS_STAGING_WEAK} "
                f"ELSE 0 END"
            )

        if self.has("Extension"):
            archive_list = ", ".join(f"'{e}'" for e in ARCHIVE_EXTENSIONS)
            is_archive = f"lower(ltrim(COALESCE(\"Extension\", ''), '.')) IN ({archive_list})"
            terms.append(f"CASE WHEN {is_archive} THEN {POINTS_ARCHIVE} ELSE 0 END")
            if self.has("InUse"):
                terms.append(f'CASE WHEN {is_archive} AND NOT "InUse" THEN {POINTS_DELETED_ARCHIVE} ELSE 0 END')

        if self.has("ParentPath"):
            keyword_checks = " OR ".join(
                f"contains(lower(COALESCE(\"ParentPath\", '')), '{kw}')" for kw in STAGING_LOCATION_KEYWORDS
            )
            terms.append(f"CASE WHEN {keyword_checks} THEN {POINTS_STAGING_LOCATION} ELSE 0 END")

        if self.has("Created0x10", "LastModified0x10"):
            terms.append(
                f'CASE WHEN ("Created0x10" - "LastModified0x10") >= '
                f"INTERVAL {OLD_COPY_DELTA_DAYS} DAY THEN {POINTS_OLD_COPY} ELSE 0 END"
            )

        if not terms:
            return None
        return f"LEAST({SCORE_MAX}, " + " + ".join(terms) + ")"

    def select_expr(self, name):
        if name in DELTA_COLUMNS:
            return f"{DELTA_COLUMNS[name][0]} AS {qident(name)}"
        if name == SCORE_COLUMN:
            return f"{self.score_sql or 'NULL'} AS {qident(name)}"
        return qident(name)

    # ---------- queries ----------

    def count(self, where_sql, params, needs_score=False):
        sql = "SELECT count(*)" + self._from_where(where_sql, needs_score)
        return self.con.execute(sql, params).fetchone()[0]

    def fetch_page(self, select_names, where_sql, params, order_by, ascending, limit, offset, needs_score=False):
        select_sql = ", ".join(self.select_expr(c) for c in select_names)
        sql = (
            f"SELECT {select_sql}"
            + self._from_where(where_sql, needs_score)
            + self._order_by(order_by, ascending)
            + " LIMIT ? OFFSET ?"
        )
        return self.con.execute(sql, list(params) + [limit, offset]).fetchall()

    def fetch_row(self, rid):
        select_sql = ", ".join(qident(c) for c in self.columns)
        row = self.con.execute(f"SELECT {select_sql} FROM mft WHERE _rid = ?", [rid]).fetchone()
        return dict(zip(self.columns, row)) if row else None

    def distinct_values(self, column, contains_text=None, limit=500):
        q = qident(column)
        sql = f"SELECT DISTINCT {q} FROM mft WHERE {q} IS NOT NULL"
        params = []
        if contains_text:
            sql += f" AND contains(lower({q}), lower(?))"
            params.append(contains_text)
        sql += f" ORDER BY {q} LIMIT ?"
        params.append(limit)
        return [r[0] for r in self.con.execute(sql, params).fetchall()]

    def export_csv(self, select_names, where_sql, params, order_by, ascending, dest_path, needs_score=False):
        select_sql = ", ".join(self.select_expr(c) for c in select_names)
        query = f"SELECT {select_sql}" + self._from_where(where_sql, needs_score) + self._order_by(order_by, ascending)
        self.con.execute(f"COPY ({query}) TO {sql_literal(dest_path)} (HEADER, DELIMITER ',')", params)

    def _macb_query(self, where_sql, params, needs_score, limit=None):
        """Build a MACB timeline query: one row per (entry, timestamp), flags merged (e.g. 'M.CB')."""
        sources = [(col, code) for col, code in MACB_COLUMNS if col in self.columns]
        if not sources:
            return None
        context = [c for c in TIMELINE_CONTEXT_COLUMNS if c in self.columns]

        filtered_cols = ", ".join(["_rid"] + [qident(c) for c in context] + [qident(c) for c, _ in sources])
        events = " UNION ALL ".join(
            f"SELECT _rid, {qident(col)} AS ts, '{code}' AS code FROM filtered WHERE {qident(col)} IS NOT NULL"
            for col, code in sources
        )
        flags = " || ".join(
            f"CASE WHEN bool_or(code = '{code}') THEN '{code}' ELSE '.' END" for _, code in MACB_COLUMNS
        )
        context_select = "".join(f", f.{qident(c)}" for c in context)
        sql = (
            f"WITH filtered AS (SELECT {filtered_cols}{self._from_where(where_sql, needs_score)}), "
            f"events AS ({events}), "
            f"grouped AS (SELECT _rid, ts, {flags} AS macb FROM events GROUP BY _rid, ts) "
            f'SELECT g.ts AS "Timestamp", g.macb AS "MACB"{context_select} '
            f"FROM grouped g JOIN filtered f USING (_rid) ORDER BY g.ts, _rid"
        )
        params = list(params)
        if limit:
            sql += " LIMIT ?"
            params.append(limit)
        return sql, params, ["Timestamp", "MACB"] + context

    def macb_timeline(self, where_sql, params, needs_score=False, limit=None):
        query = self._macb_query(where_sql, params, needs_score, limit)
        if query is None:
            return [], []
        sql, full_params, columns = query
        return columns, self.con.execute(sql, full_params).fetchall()

    def export_macb_timeline(self, where_sql, params, dest_path, needs_score=False):
        query = self._macb_query(where_sql, params, needs_score)
        if query is None:
            raise ValueError("No MACB timestamp column available.")
        sql, full_params, _ = query
        self.con.execute(f"COPY ({sql}) TO {sql_literal(dest_path)} (HEADER, DELIMITER ',')", full_params)

    def stats(self, where_sql, params, needs_score=False):
        aggregates = [("total", "count(*)")]
        if self.has("IsDirectory"):
            aggregates.append(("dirs", 'count(*) FILTER (WHERE "IsDirectory")'))
            aggregates.append(("files", 'count(*) FILTER (WHERE NOT "IsDirectory")'))
        if self.has("InUse"):
            aggregates.append(("deleted", 'count(*) FILTER (WHERE NOT "InUse")'))
        if self.has("HasAds"):
            aggregates.append(("ads", 'count(*) FILTER (WHERE "HasAds")'))
        if self.has("SI<FN"):
            aggregates.append(("timestomp", 'count(*) FILTER (WHERE "SI<FN")'))
        if self.has("ZoneIdContents"):
            aggregates.append(("internet", "count(*) FILTER (WHERE COALESCE(\"ZoneIdContents\", '') != '')"))
        if self.has("FileSize"):
            aggregates.append(("total_size", 'sum("FileSize")'))
        if self.has("Created0x10"):
            aggregates.append(("min_created", 'min("Created0x10")'))
            aggregates.append(("max_created", 'max("Created0x10")'))
        score_thresholds = (HIGH_SCORE_THRESHOLD, VERY_HIGH_SCORE_THRESHOLD)
        if self.score_sql:
            needs_score = True
            for threshold in score_thresholds:
                aggregates.append((f"score_ge_{threshold}", f"count(*) FILTER (WHERE ({self.score_sql}) >= {threshold})"))

        select_sql = ", ".join(f"{expr} AS {alias}" for alias, expr in aggregates)
        from_where = self._from_where(where_sql, needs_score)
        row = self.con.execute(f"SELECT {select_sql}{from_where}", params).fetchone()
        result = dict(zip((alias for alias, _ in aggregates), row))

        if self.score_sql:
            result["score_counts"] = {t: result.pop(f"score_ge_{t}") for t in score_thresholds}

        if self.has("Extension"):
            sql = (
                f"SELECT COALESCE(\"Extension\", '(none)') AS ext, count(*) AS c{from_where} "
                "GROUP BY ext ORDER BY c DESC LIMIT 10"
            )
            result["top_extensions"] = self.con.execute(sql, params).fetchall()

        return result

    def score_histogram(self, where_sql, params):
        """Number of entries for each score value 0..SCORE_MAX."""
        sql = (
            f"SELECT CAST({self.score_sql} AS INTEGER) AS score, count(*) AS n"
            + self._from_where(where_sql, needs_score=True)
            + " GROUP BY score"
        )
        counts = dict(self.con.execute(sql, params).fetchall())
        return [counts.get(s, 0) for s in range(SCORE_MAX + 1)]

    def explain_score(self, rid):
        """Score breakdown for one entry: {"total": int, "details": [(label, points, matched, note)]}."""
        row = self.fetch_row(rid)
        if row is None or not self.score_sql:
            return None

        details = []

        if self.has_folder_stats:
            stats_row = None
            parent = row.get("ParentPath")
            if parent is not None:
                stats_row = self.con.execute(
                    'SELECT file_count, created_span, modified_span FROM folder_stats WHERE "ParentPath" = ?',
                    [parent],
                ).fetchone()
            file_count, created_span, modified_span = stats_row or (None, None, None)
            points = 0
            if file_count is not None and created_span is not None and modified_span is not None:
                clustered = (
                    created_span <= datetime.timedelta(seconds=STAGING_CREATED_SPAN_SECONDS)
                    and modified_span >= datetime.timedelta(days=STAGING_MODIFIED_SPAN_DAYS)
                )
                if clustered and file_count >= STAGING_MIN_FILES_STRONG:
                    points = POINTS_STAGING_STRONG
                elif clustered and file_count >= STAGING_MIN_FILES_WEAK:
                    points = POINTS_STAGING_WEAK
            note = (
                f"{file_count} file(s) in this folder, created within {format_timedelta(created_span)}, "
                f"original modification dates spread over {format_timedelta(modified_span)}."
                if file_count is not None
                else "Unknown parent folder."
            )
            details.append(("Staging folder (files clustered in time)", points, points > 0, note))

        ext = str(row.get("Extension") or "").lower().lstrip(".")
        is_archive = ext in ARCHIVE_EXTENSIONS
        details.append((
            "Archive / container extension",
            POINTS_ARCHIVE if is_archive else 0, is_archive, f"Extension: {ext or '(none)'}",
        ))

        deleted_archive = is_archive and row.get("InUse") is False
        details.append((
            "Archive deleted after use (InUse=False)",
            POINTS_DELETED_ARCHIVE if deleted_archive else 0, deleted_archive, "",
        ))

        parent_lower = str(row.get("ParentPath") or "").lower()
        in_staging_location = any(kw in parent_lower for kw in STAGING_LOCATION_KEYWORDS)
        details.append((
            "Typical staging location (Temp/AppData/Downloads/ProgramData)",
            POINTS_STAGING_LOCATION if in_staging_location else 0, in_staging_location,
            row.get("ParentPath") or "",
        ))

        created, modified = row.get("Created0x10"), row.get("LastModified0x10")
        old_copy = (
            created is not None and modified is not None
            and (created - modified) >= datetime.timedelta(days=OLD_COPY_DELTA_DAYS)
        )
        details.append((
            f"Recent copy of an old file (Created - Modified >= {OLD_COPY_DELTA_DAYS} days)",
            POINTS_OLD_COPY if old_copy else 0, old_copy, "",
        ))

        total = sum(points for _, points, _, _ in details)
        return {"total": min(SCORE_MAX, total), "details": details}


class MFTAnalyzerApp(tk.Tk):
    def __init__(self, initial_path=None):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1450x840")

        self.store = MFTStore()
        self.loading = False
        self.total_filtered = 0
        self.page = 0
        self.display_columns = []
        self.sort_column = None
        self.sort_ascending = True
        self._where_sql = ""
        self._where_params = []
        self._needs_score = False
        self._filter_defaults = []

        self._build_widgets()
        self.bind_all("<MouseWheel>", self._on_mousewheel, add="+")
        self.bind_all("<Button-4>", self._on_mousewheel, add="+")
        self.bind_all("<Button-5>", self._on_mousewheel, add="+")
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        if initial_path:
            self.after(100, lambda: self._load_file(initial_path))

    def _on_close(self):
        if not self.loading:
            self.store.close()
        self.destroy()

    # ---------- widget helpers ----------

    def _register_filter_var(self, var, default):
        self._filter_defaults.append((var, default))
        return var

    @staticmethod
    def _section(parent, title):
        frame = ttk.LabelFrame(parent, text=title, padding=6)
        frame.pack(fill=tk.X, pady=4)
        return frame

    def _bind_apply(self, widget):
        widget.bind("<Return>", lambda _event: self.apply_filters())

    def _labeled_entry(self, parent, label):
        ttk.Label(parent, text=label).pack(anchor=tk.W)
        var = self._register_filter_var(tk.StringVar(), "")
        entry = ttk.Entry(parent, textvariable=var)
        entry.pack(fill=tk.X, pady=2)
        self._bind_apply(entry)
        return var

    def _check(self, parent, text, default=False, command=None, side=None):
        var = self._register_filter_var(tk.BooleanVar(value=default), default)
        button = ttk.Checkbutton(parent, text=text, variable=var, command=command)
        if side:
            button.pack(side=side)
        else:
            button.pack(anchor=tk.W)
        return var

    @staticmethod
    def _scrolled_text(win, content):
        frame = ttk.Frame(win)
        frame.pack(fill=tk.BOTH, expand=True)
        text = tk.Text(frame, wrap=tk.WORD, padx=6, pady=6)
        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text.yview)
        text.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        text.insert(tk.END, content)
        text.configure(state=tk.DISABLED)
        return text

    # ---------- UI construction ----------

    def _build_widgets(self):
        self._build_topbar()
        self._build_statusbar()
        main = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        main.pack(fill=tk.BOTH, expand=True)

        filters_frame = ttk.Frame(main, width=360)
        results_frame = ttk.Frame(main)
        main.add(filters_frame, weight=0)
        main.add(results_frame, weight=1)

        self._build_filters(filters_frame)
        self._build_results(results_frame)

    def _build_topbar(self):
        bar = ttk.Frame(self, padding=6)
        bar.pack(fill=tk.X)
        ttk.Label(bar, text="CSV file:").pack(side=tk.LEFT)
        self.path_var = tk.StringVar()
        path_entry = ttk.Entry(bar, textvariable=self.path_var, width=75)
        path_entry.pack(side=tk.LEFT, padx=6)
        path_entry.bind("<Return>", lambda _event: self._load_file(self.path_var.get()))
        ttk.Button(bar, text="Browse...", command=self._browse_file).pack(side=tk.LEFT)
        self.force_reindex = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Force re-index", variable=self.force_reindex).pack(side=tk.LEFT, padx=6)
        ttk.Button(bar, text="Load", command=lambda: self._load_file(self.path_var.get())).pack(
            side=tk.LEFT, padx=6
        )
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=150)
        self.progress.pack(side=tk.LEFT, padx=6)

    def _build_filters(self, parent):
        canvas = tk.Canvas(parent, highlightthickness=0)
        vsb = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.filters_canvas = canvas

        container = ttk.Frame(canvas, padding=8)
        container_id = canvas.create_window((0, 0), window=container, anchor="nw")
        container.bind("<Configure>", lambda _event: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda event: canvas.itemconfigure(container_id, width=event.width))

        # --- Search ---
        box = self._section(container, "Search")
        self.name_var = self._labeled_entry(box, "File name contains:")

        ttk.Label(box, text="Extension(s), comma-separated:").pack(anchor=tk.W)
        self.ext_var = self._register_filter_var(tk.StringVar(), "")
        self.ext_combo = ttk.Combobox(box, textvariable=self.ext_var, values=[])
        self.ext_combo.pack(fill=tk.X, pady=2)
        self._bind_apply(self.ext_combo)

        ttk.Label(box, text="Folder (ParentPath):").pack(anchor=tk.W)
        path_row = ttk.Frame(box)
        path_row.pack(fill=tk.X, pady=2)
        self.parentpath_var = self._register_filter_var(tk.StringVar(), "")
        path_entry = ttk.Entry(path_row, textvariable=self.parentpath_var)
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._bind_apply(path_entry)
        ttk.Button(path_row, text="...", width=3, command=self._pick_parent_path).pack(side=tk.LEFT)

        self.path_mode = self._register_filter_var(tk.StringVar(value="subtree"), "subtree")
        mode_row = ttk.Frame(box)
        mode_row.pack(fill=tk.X)
        for label, value in [("Contains", "contains"), ("Subtree", "subtree"), ("Exact", "exact")]:
            ttk.Radiobutton(mode_row, text=label, variable=self.path_mode, value=value).pack(side=tk.LEFT)

        # --- Type / state ---
        box = self._section(container, "Type / state")
        self.exclude_dirs = self._check(box, "Exclude directories")
        self.only_deleted = self._check(box, "Deleted entries only (InUse=False)")
        self.only_ads = self._check(box, "Files with Alternate Data Streams only")
        self.exclude_dos_names = self._check(box, "Exclude DOS short names (8.3)", default=True)

        # --- Date filter ---
        box = self._section(container, "Date filter (UTC)")
        row = ttk.Frame(box)
        row.pack(fill=tk.X)
        self.filter_access = self._check(row, "Last access", default=True, side=tk.LEFT)
        self.filter_modif = self._check(row, "Last modified", default=True, side=tk.LEFT)
        self.date_start_var = self._labeled_entry(box, "From (YYYY-MM-DD [HH:MM:SS]):")
        self.date_end_var = self._labeled_entry(box, "To (YYYY-MM-DD [HH:MM:SS]):")

        # --- Forensic indicators ---
        box = self._section(container, "Forensic indicators")
        self.only_timestomp = self._check(box, "Timestomping hints (SI < FN)")
        self.only_useczeros = self._check(box, "Rounded timestamps (uSecZeros)")
        self.only_copied = self._check(box, "Flagged as copied (Copied)")
        self.only_internet = self._check(box, "Mark of the Web (Zone.Identifier)")

        # (variable, required column, SQL condition, short label for chart titles)
        self._flag_filters = [
            (self.exclude_dirs, "IsDirectory", 'NOT COALESCE("IsDirectory", false)', "no directories"),
            (self.only_deleted, "InUse", 'NOT "InUse"', "deleted only"),
            (self.only_ads, "HasAds", '"HasAds"', "ADS only"),
            (self.exclude_dos_names, "NameType", "COALESCE(\"NameType\", '') != 'Dos'", None),
            (self.only_timestomp, "SI<FN", '"SI<FN"', "SI<FN"),
            (self.only_useczeros, "uSecZeros", '"uSecZeros"', "uSecZeros"),
            (self.only_copied, "Copied", '"Copied"', "Copied"),
            (self.only_internet, "ZoneIdContents", "COALESCE(\"ZoneIdContents\", '') != ''", "Zone.Identifier"),
        ]

        # --- Exfiltration indicator ---
        box = self._section(container, "Exfiltration indicator (heuristic)")
        self.show_score = self._check(box, "Show score (column + highlighting)", command=self.apply_filters)
        score_row = ttk.Frame(box)
        score_row.pack(fill=tk.X, pady=2)
        ttk.Label(score_row, text=f"Minimum score (0-{SCORE_MAX}):").pack(side=tk.LEFT)
        self.min_score_var = self._register_filter_var(tk.StringVar(value="0"), "0")
        score_entry = ttk.Entry(score_row, textvariable=self.min_score_var, width=4)
        score_entry.pack(side=tk.LEFT, padx=4)
        self._bind_apply(score_entry)
        ttk.Label(
            box,
            text="Triage aid, not proof.\nDouble-click a row for the breakdown.",
            font=("TkDefaultFont", 8, "italic"),
            foreground="#666666",
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(2, 0))
        ttk.Button(box, text="Score histogram", command=self.show_score_histogram).pack(fill=tk.X, pady=(6, 0))

        # --- Actions ---
        btn_row = ttk.Frame(container)
        btn_row.pack(fill=tk.X, pady=8)
        ttk.Button(btn_row, text="Apply filters", command=self.apply_filters).pack(
            side=tk.LEFT, expand=True, fill=tk.X
        )
        ttk.Button(btn_row, text="Reset", command=self.reset_filters).pack(
            side=tk.LEFT, expand=True, fill=tk.X, padx=(4, 0)
        )

        # --- Display / pagination ---
        box = self._section(container, "Display")
        self.show_deltas = self._check(box, "Show created / modified / accessed deltas", command=self.apply_filters)

        ttk.Label(box, text="Page size:").pack(anchor=tk.W)
        self.page_size_var = tk.StringVar(value=str(PAGE_SIZE_DEFAULT))
        page_size_entry = ttk.Entry(box, textvariable=self.page_size_var, width=10)
        page_size_entry.pack(anchor=tk.W)
        page_size_entry.bind("<Return>", lambda _event: self._goto_page(0))

        pager = ttk.Frame(box)
        pager.pack(fill=tk.X, pady=4)
        ttk.Button(pager, text="◀ Previous", command=lambda: self._goto_page(self.page - 1)).pack(side=tk.LEFT)
        self.page_label_var = tk.StringVar(value="page 0/0")
        ttk.Label(pager, textvariable=self.page_label_var).pack(side=tk.LEFT, padx=6)
        ttk.Button(pager, text="Next ▶", command=lambda: self._goto_page(self.page + 1)).pack(side=tk.LEFT)

        # --- Tools ---
        box = self._section(container, "Tools")
        ttk.Button(box, text="Export results (CSV)", command=self.export_results).pack(fill=tk.X, pady=2)
        ttk.Button(box, text="MACB timeline", command=self.open_macb_timeline).pack(fill=tk.X, pady=2)
        ttk.Button(box, text="Statistics", command=self.show_statistics).pack(fill=tk.X, pady=2)

    def _build_results(self, parent):
        self.result_count_var = tk.StringVar(value="No file loaded.")
        ttk.Label(
            parent, textvariable=self.result_count_var, font=("TkDefaultFont", 11, "bold"), padding=(4, 4)
        ).pack(fill=tk.X, anchor=tk.W)

        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(frame, columns=[], show="headings", selectmode="browse")
        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        for tag, color in ROW_COLORS.items():
            self.tree.tag_configure(tag, background=color)

        self.tree.bind("<Double-1>", self._on_row_double_click)
        self.tree.bind("<Return>", self._on_row_double_click)

    def _build_statusbar(self):
        self.status_var = tk.StringVar(value="No file loaded.")
        ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W).pack(
            fill=tk.X, side=tk.BOTTOM
        )

    def _set_status(self, text):
        self.status_var.set(text)

    def _set_busy(self, busy):
        self.loading = busy
        if busy:
            self.progress.start(12)
        else:
            self.progress.stop()

    def _require_data(self, title):
        if self.loading:
            messagebox.showinfo(title, "A file is being indexed, please wait.")
            return False
        if not self.store.is_loaded:
            messagebox.showinfo(title, "Load a file first.")
            return False
        return True

    def _on_mousewheel(self, event):
        widget = self.winfo_containing(event.x_root, event.y_root)
        while widget is not None:
            if widget is self.filters_canvas:
                if getattr(event, "num", None) == 4:
                    self.filters_canvas.yview_scroll(-1, "units")
                elif getattr(event, "num", None) == 5:
                    self.filters_canvas.yview_scroll(1, "units")
                elif getattr(event, "delta", 0):
                    self.filters_canvas.yview_scroll(-1 if event.delta > 0 else 1, "units")
                return
            widget = getattr(widget, "master", None)

    # ---------- file loading ----------

    def _browse_file(self):
        path = filedialog.askopenfilename(
            title="Select an MFTECmd export (CSV)",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if path:
            self._load_file(path)

    def _load_file(self, path):
        path = path.strip()
        if not path or self.loading:
            return
        if not os.path.isfile(path):
            messagebox.showerror("Load error", f"File not found:\n{path}")
            return
        self.path_var.set(path)
        self._set_busy(True)
        self._set_status(f"Indexing {path}... (first load may take a while)")

        force = self.force_reindex.get()
        result = {}

        def worker():
            try:
                self.store.load(path, force_reindex=force)
            except Exception as exc:
                result["error"] = exc
            finally:
                result["done"] = True

        # Tk is not thread-safe: the worker only touches the store, the UI polls for completion.
        def poll():
            if not result.get("done"):
                self.after(100, poll)
            elif "error" in result:
                self._on_load_error(result["error"])
            else:
                self._on_load_success()

        threading.Thread(target=worker, daemon=True).start()
        poll()

    def _on_load_success(self):
        self._set_busy(False)
        self.force_reindex.set(False)
        self.sort_column = None
        self.sort_ascending = True
        if self.store.has("Extension"):
            self.ext_combo["values"] = self.store.distinct_values("Extension", limit=300)
        self.apply_filters()
        self._set_status(f"{format_int(self.store.total_rows)} entries loaded — cache: {self.store.cache_path}")

    def _on_load_error(self, exc):
        self._set_busy(False)
        self.tree.delete(*self.tree.get_children())
        self.total_filtered = 0
        self.result_count_var.set("No file loaded.")
        self.page_label_var.set("page 0/0")
        self._set_status("Load error.")
        messagebox.showerror(
            "Load error",
            f"Could not load the file:\n{exc}\n\n"
            "Make sure it is an unmodified MFTECmd CSV export "
            "(one record per line, UTF-8 encoding).",
        )

    def _pick_parent_path(self):
        if not self._require_data("Folders"):
            return
        if not self.store.has("ParentPath"):
            messagebox.showinfo("Folders", "This file has no ParentPath column.")
            return

        win = tk.Toplevel(self)
        win.title("Choose a folder")
        win.geometry("650x500")

        search_var = tk.StringVar()
        search_entry = ttk.Entry(win, textvariable=search_var)
        search_entry.pack(fill=tk.X, padx=6, pady=6)
        search_entry.focus_set()
        listbox = tk.Listbox(win)
        listbox.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0, 6))
        pending = {"id": None}

        def refresh():
            listbox.delete(0, tk.END)
            for p in self.store.distinct_values("ParentPath", search_var.get().strip(), limit=500):
                listbox.insert(tk.END, p)

        def on_change(*_):
            if pending["id"]:
                win.after_cancel(pending["id"])
            pending["id"] = win.after(250, refresh)

        def select():
            sel = listbox.curselection()
            if sel:
                self.parentpath_var.set(listbox.get(sel[0]))
                self.path_mode.set("subtree")
                win.destroy()
                self.apply_filters()

        search_var.trace_add("write", on_change)
        refresh()
        ttk.Button(win, text="Select", command=select).pack(pady=6)
        listbox.bind("<Double-1>", lambda _event: select())
        listbox.bind("<Return>", lambda _event: select())

    # ---------- SQL filter construction ----------

    def _min_score(self):
        try:
            return max(0, min(SCORE_MAX, int(self.min_score_var.get())))
        except ValueError:
            return 0

    def _build_where(self):
        """Translate the filter widgets into (where_sql, params, needs_score). Raises ValueError on bad input."""
        has = self.store.has
        conditions = []
        params = []

        name_q = self.name_var.get().strip()
        if name_q and has("FileName"):
            conditions.append('contains(lower("FileName"), lower(?))')
            params.append(name_q)

        exts = [e.strip().lower().lstrip(".") for e in self.ext_var.get().split(",") if e.strip()]
        if exts and has("Extension"):
            placeholders = ", ".join(["?"] * len(exts))
            conditions.append(f"lower(ltrim(\"Extension\", '.')) IN ({placeholders})")
            params.extend(exts)

        parent_q = self.parentpath_var.get().strip()
        if parent_q and has("ParentPath"):
            mode = self.path_mode.get()
            if mode == "exact":
                conditions.append('"ParentPath" = ?')
            elif mode == "subtree":
                conditions.append('starts_with("ParentPath", ?)')
            else:
                conditions.append('contains(lower("ParentPath"), lower(?))')
            params.append(parent_q)

        for var, column, condition, _ in self._flag_filters:
            if var.get() and has(column):
                conditions.append(condition)

        date_clause, date_params = self._build_date_condition()
        if date_clause:
            conditions.append(date_clause)
            params.extend(date_params)

        needs_score = self.show_score.get()
        min_score = self._min_score()
        if min_score > 0 and self.store.score_sql:
            conditions.append(f"({self.store.score_sql}) >= ?")
            params.append(min_score)
            needs_score = True

        return " AND ".join(conditions), params, needs_score

    def _build_date_condition(self):
        start_s = self.date_start_var.get().strip()
        end_s = self.date_end_var.get().strip()
        if not start_s and not end_s:
            return None, []

        start = parse_user_datetime(start_s) if start_s else datetime.datetime.min
        end = parse_user_datetime(end_s, end_of_range=True) if end_s else datetime.datetime.max
        if start > end:
            raise ValueError("The start date is after the end date.")

        targets = []
        if self.filter_access.get():
            targets.append("LastAccess0x10")
        if self.filter_modif.get():
            targets.append("LastModified0x10")
        targets = [c for c in targets if self.store.has(c)]
        if not targets:
            return None, []

        clause = " OR ".join(f"({qident(c)} BETWEEN ? AND ?)" for c in targets)
        return f"({clause})", [start, end] * len(targets)

    def _current_display_columns(self):
        cols = [c for c in DEFAULT_COLUMNS if self.store.has(c)]
        if self.show_deltas.get():
            cols += [name for name, (_, needed) in DELTA_COLUMNS.items() if self.store.has(*needed)]
        if self.show_score.get() and self.store.score_sql:
            cols.append(SCORE_COLUMN)
        return cols

    def _effective_sort_column(self, display_cols):
        """Drop the sort on a computed column that is no longer displayed."""
        if self.sort_column and (self.store.has(self.sort_column) or self.sort_column in display_cols):
            return self.sort_column
        return None

    # ---------- filtering / pagination ----------

    def apply_filters(self):
        if not self.store.is_loaded or self.loading:
            return
        try:
            where_sql, params, needs_score = self._build_where()
            self.total_filtered = self.store.count(where_sql, params, needs_score=needs_score)
        except (ValueError, duckdb.Error) as exc:
            messagebox.showwarning("Invalid filter", str(exc))
            return

        self._where_sql, self._where_params, self._needs_score = where_sql, params, needs_score
        self._goto_page(0)

    def _page_size(self):
        try:
            return max(1, int(self.page_size_var.get()))
        except ValueError:
            self.page_size_var.set(str(PAGE_SIZE_DEFAULT))
            return PAGE_SIZE_DEFAULT

    def _goto_page(self, page):
        if not self.store.is_loaded or self.loading:
            return
        total_pages = max(1, -(-self.total_filtered // self._page_size()))
        self.page = max(0, min(page, total_pages - 1))
        self._load_page()

    def _load_page(self):
        display_cols = self._current_display_columns()
        sort_col = self._effective_sort_column(display_cols)
        extra_cols = [c for c in ROW_TAG_COLUMNS if self.store.has(c) and c not in display_cols]
        select_names = ["_rid"] + display_cols + extra_cols
        page_size = self._page_size()

        try:
            rows = self.store.fetch_page(
                select_names, self._where_sql, self._where_params,
                sort_col, self.sort_ascending,
                page_size, self.page * page_size, needs_score=self._needs_score,
            )
        except duckdb.Error as exc:
            messagebox.showerror("Query error", str(exc))
            return

        self._configure_tree_columns(display_cols, sort_col)
        self._populate_tree(rows, select_names, display_cols)

        total_pages = max(1, -(-self.total_filtered // page_size))
        self.page_label_var.set(f"page {self.page + 1}/{total_pages}")

        n_filtered = format_int(self.total_filtered)
        n_total = format_int(self.store.total_rows)
        if self.total_filtered == self.store.total_rows:
            self.result_count_var.set(f"{n_filtered} entries (no active filter)")
        else:
            self.result_count_var.set(f"{n_filtered} entries match the filters (out of {n_total} loaded)")
        self._set_status(f"{n_filtered} result(s) out of {n_total} loaded entries")

    def reset_filters(self):
        for var, default in self._filter_defaults:
            var.set(default)
        self.sort_column = None
        self.sort_ascending = True
        self.apply_filters()

    # ---------- results table ----------

    def _configure_tree_columns(self, display_cols, sort_col):
        if display_cols != self.display_columns:
            # Only rebuild when the column set changes, to keep user-resized widths.
            self.display_columns = display_cols
            self.tree["columns"] = display_cols
            for col in display_cols:
                self.tree.column(col, width=COLUMN_WIDTHS.get(col, DEFAULT_COLUMN_WIDTH), anchor=tk.W, stretch=False)
        for col in display_cols:
            arrow = (" ▲" if self.sort_ascending else " ▼") if col == sort_col else ""
            self.tree.heading(col, text=col + arrow, command=lambda c=col: self._sort_by(c))

    def _populate_tree(self, rows, select_names, display_cols):
        self.tree.delete(*self.tree.get_children())
        pos = {name: i for i, name in enumerate(select_names)}
        for row in rows:
            values = [self._format_cell(col, row[pos[col]]) for col in display_cols]
            tag = self._row_tag(row, pos)
            self.tree.insert("", tk.END, iid=str(row[pos["_rid"]]), values=values, tags=(tag,) if tag else ())

    @staticmethod
    def _format_cell(col, value):
        if value is None:
            return ""
        if col == "FileSize":
            return format_size(value)
        if col == SCORE_COLUMN:
            return f"{value}/{SCORE_MAX}"
        return format_value(value)

    @staticmethod
    def _row_tag(row, pos):
        def get(name):
            i = pos.get(name)
            return row[i] if i is not None else None

        score = get(SCORE_COLUMN)
        if score is not None and score >= HIGH_SCORE_THRESHOLD:
            return "exfil"
        if get("InUse") is False:
            return "deleted"
        if get("SI<FN") is True:
            return "timestomp"
        if get("HasAds") is True or get("IsAds") is True:
            return "ads"
        return None

    def _sort_by(self, col):
        if self.sort_column == col:
            self.sort_ascending = not self.sort_ascending
        else:
            self.sort_column = col
            self.sort_ascending = True
        self._goto_page(0)

    def _on_row_double_click(self, _event):
        item = self.tree.focus()
        if not item:
            return
        rid = int(item)
        row = self.store.fetch_row(rid)
        if row:
            self._show_detail_popup(row, rid)

    def _show_detail_popup(self, row, rid):
        lines = [f"{col}: {format_value(val, precise=True)}" for col, val in row.items()]

        explanation = self.store.explain_score(rid)
        if explanation:
            lines += [
                "",
                "--- Exfiltration score (heuristic, triage only) ---",
                f"Total: {explanation['total']}/{SCORE_MAX}",
                "",
            ]
            for label, points, matched, note in explanation["details"]:
                lines.append(f"[{'✓' if matched else '✗'}] {label}: +{points}")
                if note:
                    lines.append(f"      {note}")
            lines += [
                "",
                "This score prioritises the investigation; it does not prove exfiltration. "
                "Correlate with $UsnJrnl, USB/network artefacts and execution logs.",
            ]

        win = tk.Toplevel(self)
        win.title(f"Details - {row.get('FileName', '')}")
        win.geometry("650x700")
        self._scrolled_text(win, "\n".join(lines))

    # ---------- export ----------

    def export_results(self):
        if not self._require_data("Export"):
            return
        if self.total_filtered == 0:
            messagebox.showinfo("Export", "No results to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")], title="Export filtered results"
        )
        if not path:
            return
        display_cols = self._current_display_columns()
        try:
            self.store.export_csv(
                display_cols, self._where_sql, self._where_params,
                self._effective_sort_column(display_cols), self.sort_ascending,
                path, needs_score=self._needs_score,
            )
        except Exception as exc:
            messagebox.showerror("Export", f"Export failed:\n{exc}")
            return
        messagebox.showinfo("Export", f"{format_int(self.total_filtered)} rows exported to:\n{path}")

    # ---------- MACB timeline ----------

    def open_macb_timeline(self):
        if not self._require_data("MACB timeline"):
            return
        if self.total_filtered == 0:
            messagebox.showinfo("MACB timeline", "No current results. Adjust the filters first.")
            return
        try:
            columns, rows = self.store.macb_timeline(
                self._where_sql, self._where_params, self._needs_score, limit=TIMELINE_DISPLAY_LIMIT
            )
        except duckdb.Error as exc:
            messagebox.showerror("MACB timeline", str(exc))
            return
        if not rows:
            messagebox.showinfo("MACB timeline", "No timestamps available to build a timeline.")
            return
        self._show_timeline_window(columns, rows)

    def _show_timeline_window(self, columns, rows):
        win = tk.Toplevel(self)
        truncated = f" (first {TIMELINE_DISPLAY_LIMIT})" if len(rows) >= TIMELINE_DISPLAY_LIMIT else ""
        win.title(f"MACB timeline — {format_int(len(rows))} events{truncated}")
        win.geometry("1100x600")

        def export():
            path = filedialog.asksaveasfilename(
                parent=win, defaultextension=".csv", filetypes=[("CSV", "*.csv")],
                title="Export the full MACB timeline",
            )
            if not path:
                return
            try:
                self.store.export_macb_timeline(self._where_sql, self._where_params, path, self._needs_score)
            except Exception as exc:
                messagebox.showerror("Export", f"Export failed:\n{exc}", parent=win)
                return
            messagebox.showinfo("Export", f"Timeline exported to:\n{path}", parent=win)

        ttk.Button(win, text="Export full timeline (CSV)", command=export).pack(side=tk.BOTTOM, pady=6)

        frame = ttk.Frame(win)
        frame.pack(fill=tk.BOTH, expand=True)
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        for c in columns:
            tree.heading(c, text=c)
            tree.column(c, width=COLUMN_WIDTHS.get(c, DEFAULT_COLUMN_WIDTH), anchor=tk.W, stretch=False)
        tree.column("MACB", width=60)
        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        hsb = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        for row in rows:
            tree.insert("", tk.END, values=[format_value(v) for v in row])

    # ---------- statistics ----------

    def show_statistics(self):
        if not self._require_data("Statistics"):
            return
        try:
            s = self.store.stats(self._where_sql, self._where_params, self._needs_score)
        except duckdb.Error as exc:
            messagebox.showerror("Statistics", str(exc))
            return

        lines = [
            f"Entries matching the filters: {format_int(s['total'])}",
            f"Total loaded entries: {format_int(self.store.total_rows)}",
        ]
        if "dirs" in s:
            lines.append(f"  directories: {format_int(s['dirs'])}")
            lines.append(f"  files: {format_int(s['files'])}")
        if "deleted" in s:
            lines.append(f"Deleted entries (InUse=False): {format_int(s['deleted'])}")
        if "ads" in s:
            lines.append(f"Files with ADS: {format_int(s['ads'])}")
        if "timestomp" in s:
            lines.append(f"Timestomping hints (SI<FN): {format_int(s['timestomp'])}")
        if "internet" in s:
            lines.append(f"Files with Mark of the Web (Zone.Identifier): {format_int(s['internet'])}")
        if "total_size" in s:
            lines.append(f"Total size: {format_size(s['total_size'])}")
        if s.get("top_extensions"):
            lines += ["", "Top 10 extensions:"]
            lines += [f"  {ext}: {format_int(count)}" for ext, count in s["top_extensions"]]
        if s.get("min_created") is not None:
            lines += [
                "",
                f"Time span (Created0x10): {format_value(s['min_created'])} -> {format_value(s['max_created'])}",
            ]
        if s.get("score_counts"):
            lines.append("")
            for threshold, n in s["score_counts"].items():
                lines.append(f"Exfiltration score >= {threshold}/{SCORE_MAX}: {format_int(n)}")
            lines.append("(triage heuristic, not proof)")

        win = tk.Toplevel(self)
        win.title("Statistics")
        win.geometry("540x600")
        self._scrolled_text(win, "\n".join(lines))

    # ---------- exfiltration score histogram ----------

    def _active_filters_description(self):
        parts = []
        name_q = self.name_var.get().strip()
        if name_q:
            parts.append(f"name~'{name_q}'")
        ext_q = self.ext_var.get().strip()
        if ext_q:
            parts.append(f"ext={ext_q}")
        parent_q = self.parentpath_var.get().strip()
        if parent_q:
            mode_symbol = {"exact": "=", "subtree": "⊇", "contains": "~"}.get(self.path_mode.get(), "~")
            parts.append(f"folder{mode_symbol}'{parent_q}'")
        parts += [label for var, _, _, label in self._flag_filters if label and var.get()]
        if self._min_score() > 0:
            parts.append(f"score>={self._min_score()}")
        filters_str = ", ".join(parts) if parts else "no filter"

        start_s = self.date_start_var.get().strip()
        end_s = self.date_end_var.get().strip()
        if start_s or end_s:
            which = []
            if self.filter_access.get():
                which.append("access")
            if self.filter_modif.get():
                which.append("modified")
            which_str = "/".join(which) if which else "date"
            date_str = f"{which_str} from {start_s or '(start)'} to {end_s or '(end)'}"
        else:
            date_str = "all dates"

        return filters_str, date_str

    def show_score_histogram(self):
        if not self._require_data("Histogram"):
            return
        if not MATPLOTLIB_AVAILABLE:
            messagebox.showerror("matplotlib missing", "The histogram requires matplotlib:\npip install matplotlib")
            return
        if not self.store.score_sql:
            messagebox.showinfo(
                "Histogram",
                "The exfiltration score cannot be computed for this file (required columns are missing).",
            )
            return

        try:
            counts = self.store.score_histogram(self._where_sql, self._where_params)
        except duckdb.Error as exc:
            messagebox.showerror("Histogram", str(exc))
            return
        scores = list(range(SCORE_MAX + 1))
        filters_str, date_str = self._active_filters_description()
        title = f"Exfiltration score distribution\nFilters: {filters_str}  —  {date_str}"
        self._show_histogram_window(scores, counts, title, filters_str, date_str)

    def _show_histogram_window(self, scores, counts, title, filters_str, date_str):
        win = tk.Toplevel(self)
        win.title("Exfiltration score histogram")
        win.geometry("900x700")

        fig = Figure(figsize=(8, 6), dpi=100)
        ax = fig.add_subplot(111)
        colors = ["#4a90d9" if s < HIGH_SCORE_THRESHOLD else "#c0392b" for s in scores]
        bars = ax.bar(scores, counts, color=colors, edgecolor="black", linewidth=0.5)
        for bar, count in zip(bars, counts):
            if count > 0:
                ax.annotate(
                    format_int(count),
                    xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha="center",
                    fontsize=8,
                )
        ax.set_xlabel(f"Exfiltration score (0-{SCORE_MAX})")
        ax.set_ylabel("Number of entries")
        ax.set_xticks(scores)
        ax.set_title(title, fontsize=10)
        fig.tight_layout()

        btn_row = ttk.Frame(win, padding=6)
        btn_row.pack(fill=tk.X, side=tk.BOTTOM)

        canvas = FigureCanvasTkAgg(fig, master=win)
        canvas.draw()
        toolbar = NavigationToolbar2Tk(canvas, win)
        toolbar.update()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        def export_image():
            path = filedialog.asksaveasfilename(
                parent=win,
                title="Save chart",
                defaultextension=".png",
                filetypes=[("PNG", "*.png"), ("PDF", "*.pdf"), ("SVG", "*.svg"), ("JPEG", "*.jpg"), ("All files", "*.*")],
            )
            if path:
                fig.savefig(path, dpi=150, bbox_inches="tight")
                messagebox.showinfo("Export", f"Chart saved:\n{path}", parent=win)

        def export_data():
            path = filedialog.asksaveasfilename(
                parent=win, title="Save chart data", defaultextension=".csv", filetypes=[("CSV", "*.csv")]
            )
            if not path:
                return
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(["Filters", filters_str])
                writer.writerow(["Date range", date_str])
                writer.writerow([])
                writer.writerow([SCORE_COLUMN, "Entry_Count"])
                writer.writerows(zip(scores, counts))
            messagebox.showinfo("Export", f"Data saved:\n{path}", parent=win)

        ttk.Button(btn_row, text="Export chart (image)", command=export_image).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Export data (CSV)", command=export_data).pack(side=tk.LEFT, padx=4)


def main():
    parser = argparse.ArgumentParser(description=f"{APP_NAME}: forensic GUI for MFTECmd $MFT CSV exports.")
    parser.add_argument("csv_path", nargs="?", help="CSV file to load on startup")
    args = parser.parse_args()
    app = MFTAnalyzerApp(initial_path=args.csv_path)
    app.mainloop()


if __name__ == "__main__":
    main()
