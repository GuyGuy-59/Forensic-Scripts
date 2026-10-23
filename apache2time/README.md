# apache2time


Converts Apache access and error logs into [Google Timesketch](https://timesketch.org/) import format (JSONL or CSV). Handles rotated, compressed, and multi-host log trees out of the box.

---

## Requirements

- Python 3.6+
- No third-party dependencies

---

## Usage

```bash
# Directory
python apache2time.py /var/log/apache2/ -o web01.jsonl --auto-tag --dedup

# Recursive with split output and timezone
python apache2time.py /logs/ -r --split -o /tmp/out --tz "+02:00"

# Glob pattern
python apache2time.py "/logs/*.access.log*" -o out.jsonl

# From stdin
cat access.log | python apache2time.py - -o out.jsonl
```

### Options

| Option | Description |
|--------|-------------|
| `inputs` | Files, directories, glob patterns, or `-` for stdin |
| `-o, --output` | Output file (or prefix when `--split` is used) |
| `-r, --recursive` | Walk subdirectories |
| `--pattern` | Filename pattern to include (repeatable). Defaults: `*.log`, `*.log.*`, `access*`, `error*`, `*.gz` |
| `--exclude` | Regex of paths to exclude |
| `--type` | `access`, `error`, or `auto` (default) |
| `--format` | `jsonl` (default) or `csv` |
| `--split` | Write separate access / error files (prefix = `--output`) |
| `--auto-tag` | Tag suspicious events automatically |
| `--dedup` | Deduplicate overlapping entries across rotated files |
| `--tz` | Timezone for timestamps without an offset (e.g. `+02:00`) |
| `--host` | Force a hostname (otherwise inferred from the directory tree) |
| `--no-source-path` | Omit the `log_file` field |
| `--dry-run` | List files that would be processed, then exit |

---

## Supported Formats

| Type | Variants |
|------|---------|
| Access log | `common`, `combined`, `vhost_combined` (auto-detected) |
| Error log | Apache 2.2, Apache 2.4 |

Rotated files (`.1`, `.2.gz`…) and compressed archives (`.gz`, `.bz2`, `.xz`) are handled transparently.

---

## Auto-tagging

When `--auto-tag` is used, entries are tagged based on:

- Known scanner / bot user agents
- Path traversal patterns
- SQL injection / XSS signatures in the URI
- High-severity error levels (`crit`, `alert`, `emerg`)

---

## Output Fields

`datetime` · `message` · `timestamp_desc` · `data_type` · `client_ip` · `user` · `http_method` · `uri` · `http_status` · `bytes_sent` · `referer` · `user_agent` · `vhost` · `log_level` · `error_message` · `log_file` · `log_host` · `tag`

See `ALL_FIELDS` in the script for the full CSV column set.
