"""MFT Analyzer configuration: CSV schema, display settings and exfiltration score weights.

Edit this file to adapt the tool to your case. Changes to the column type lists
(BOOL / DATE / NUMERIC) automatically trigger a re-index of cached files.
"""

APP_NAME = "MFT Analyzer"

# ---------- MFTECmd schema (column types applied at ingestion) ----------

BOOL_COLUMNS = ["InUse", "IsDirectory", "HasAds", "IsAds", "SI<FN", "uSecZeros", "Copied"]

DATE_COLUMNS = [
    "Created0x10", "Created0x30",
    "LastModified0x10", "LastModified0x30",
    "LastRecordChange0x10", "LastRecordChange0x30",
    "LastAccess0x10", "LastAccess0x30",
]

NUMERIC_COLUMNS = [
    "FileSize", "ReferenceCount", "EntryNumber", "SequenceNumber",
    "ParentEntryNumber", "ParentSequenceNumber",
]

# ---------- display ----------

DEFAULT_COLUMNS = [
    "EntryNumber", "InUse", "FileName", "Extension", "ParentPath",
    "FileSize", "Created0x10", "LastModified0x10", "LastAccess0x10",
]

# Columns fetched with every page (even if hidden) to colour the rows.
ROW_TAG_COLUMNS = ["InUse", "SI<FN", "HasAds", "IsAds"]

ROW_COLORS = {
    "exfil": "#e6b3ff",
    "deleted": "#f8d7da",
    "timestomp": "#ffe5b4",
    "ads": "#d0e8ff",
}

COLUMN_WIDTHS = {
    "EntryNumber": 90, "InUse": 60, "FileName": 230, "Extension": 80,
    "ParentPath": 330, "FileSize": 90,
}
DEFAULT_COLUMN_WIDTH = 140

PAGE_SIZE_DEFAULT = 200

DATE_INPUT_FORMATS = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"]

# ---------- computed columns ----------

# name -> (SQL expression, required source columns)
DELTA_COLUMNS = {
    "Delta_Created_Accessed": ('("LastAccess0x10" - "Created0x10")', ("LastAccess0x10", "Created0x10")),
    "Delta_Created_Modified": ('("LastModified0x10" - "Created0x10")', ("LastModified0x10", "Created0x10")),
    "Delta_Modified_Accessed": ('("LastAccess0x10" - "LastModified0x10")', ("LastAccess0x10", "LastModified0x10")),
}
SCORE_COLUMN = "Exfil_Score"

# ---------- MACB timeline ----------

MACB_COLUMNS = [
    ("LastModified0x10", "M"),
    ("LastAccess0x10", "A"),
    ("LastRecordChange0x10", "C"),
    ("Created0x10", "B"),
]
TIMELINE_CONTEXT_COLUMNS = ["FileName", "ParentPath", "EntryNumber", "InUse"]
TIMELINE_DISPLAY_LIMIT = 5000

# ---------- "possible exfiltration" heuristic score (0-10, capped) ----------
# The most reliable signal is temporal clustering (staging), not an isolated
# indicator on a single file. See MFTStore.explain_score() and the README.

SCORE_MAX = 10
HIGH_SCORE_THRESHOLD = 6
VERY_HIGH_SCORE_THRESHOLD = 8

ARCHIVE_EXTENSIONS = ["zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "iso"]
STAGING_LOCATION_KEYWORDS = ["temp", "appdata", "downloads", "programdata"]
STAGING_MIN_FILES_STRONG = 5
STAGING_MIN_FILES_WEAK = 3
STAGING_CREATED_SPAN_SECONDS = 300
STAGING_MODIFIED_SPAN_DAYS = 30
OLD_COPY_DELTA_DAYS = 30

POINTS_STAGING_STRONG = 4
POINTS_STAGING_WEAK = 2
POINTS_ARCHIVE = 2
POINTS_DELETED_ARCHIVE = 2
POINTS_STAGING_LOCATION = 1
POINTS_OLD_COPY = 1
