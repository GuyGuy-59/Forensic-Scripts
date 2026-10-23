"""
apache2time.py — Converts Apache logs (access & error) to a Google Timesketch
import format (JSONL or CSV).

Accepts a single file, a glob pattern, or a FULL DIRECTORY (recursive).
Handles log rotation (.1, .2.gz...), compression (.gz, .bz2, .xz),
deduplication of overlapping entries, and traceability of the source file.

Supported formats:
  - access log: common, combined, vhost_combined (auto-detected)
  - error log : Apache 2.2 and 2.4

Usage:
  ./apache2time.py /var/log/apache2/ -o web01.jsonl --auto-tag --dedup
  ./apache2time.py /logs/ -r --split -o /tmp/out --tz "+02:00"
  ./apache2time.py "/logs/*.access.log*" -o out.jsonl
"""

import argparse
import bz2
import csv
import glob
import gzip
import hashlib
import json
import lzma
import os
import re
import sys
from datetime import datetime

# --------------------------------------------------------------------------
# Regular expressions
# --------------------------------------------------------------------------

_Q = r'(?:[^"\\]|\\.)*'   # quoted field with escaped \"

ACCESS_RE = re.compile(
    r'^(?:(?P<vhost>[\w.\-*]+)(?::(?P<vport>\d+))?\s+)?'
    r'(?P<client_ip>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<request>' + _Q + r')"\s+'
    r'(?P<status>\d{3}|-)\s+'
    r'(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referer>' + _Q + r')"\s+"(?P<user_agent>' + _Q + r')")?'
    r'(?P<extra>.*)$'
)

REQUEST_RE = re.compile(r'^(?P<method>[A-Z_]+)\s+(?P<uri>\S+)(?:\s+(?P<protocol>\S+))?$')

ERROR_RE = re.compile(
    r'^\[(?P<ts>[^\]]+)\]\s+'
    r'\[(?:(?P<module>[^:\]\s]+):)?(?P<level>[^\]\s]+)\]\s+'
    r'(?:\[pid\s+(?P<pid>\d+)(?::tid\s+(?P<tid>\d+))?\]\s+)?'
    r'(?:\[client\s+(?P<client>[^\]]+)\]\s+)?'
    r'(?P<msg>.*)$'
)

ACCESS_TIME_FMT = '%d/%b/%Y:%H:%M:%S %z'
ERROR_TIME_FMTS = (
    '%a %b %d %H:%M:%S.%f %Y',
    '%a %b %d %H:%M:%S %Y',
    '%a %b %d %H:%M:%S.%f %Y %z',
)

# CSV columns (fixed union -> allows streaming writes)
ALL_FIELDS = [
    'datetime', 'message', 'timestamp_desc', 'data_type',
    'source_short', 'source_long',
    'client_ip', 'client_port', 'user', 'ident',
    'http_method', 'uri', 'uri_path', 'uri_query', 'http_protocol',
    'http_status', 'bytes_sent', 'referer', 'user_agent',
    'vhost', 'vhost_port', 'raw_request',
    'log_level', 'module', 'pid', 'tid', 'error_message',
    'log_file', 'log_host', 'tag',
]

TZ_SUFFIX_RE = re.compile(r'([+-]\d{2}:\d{2}|Z)$')


def _clean(value):
    return None if value in (None, '-', '') else value


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

def parse_access(line):
    m = ACCESS_RE.match(line)
    if not m:
        return None
    g = m.groupdict()
    try:
        dt = datetime.strptime(g['ts'], ACCESS_TIME_FMT)
    except ValueError:
        return None

    rec = {
        'datetime': dt.isoformat(),
        'timestamp_desc': 'Apache Access Time',
        'source_short': 'LOG',
        'source_long': 'Apache Access Log',
        'client_ip': g['client_ip'],
        'user': _clean(g['user']),
        'ident': _clean(g['ident']),
        'http_status': int(g['status']) if g['status'].isdigit() else None,
        'bytes_sent': int(g['bytes']) if g['bytes'].isdigit() else 0,
        'referer': _clean(g['referer']),
        'user_agent': _clean(g['user_agent']),
        'vhost': _clean(g['vhost']),
        'vhost_port': _clean(g['vport']),
    }

    req = g['request'] or ''
    rm = REQUEST_RE.match(req)
    if rm:
        rec['http_method'] = rm.group('method')
        rec['uri'] = rm.group('uri')
        rec['http_protocol'] = rm.group('protocol')
        if '?' in rm.group('uri'):
            path, _, query = rm.group('uri').partition('?')
            rec['uri_path'] = path
            rec['uri_query'] = query
        else:
            rec['uri_path'] = rm.group('uri')
    else:
        rec['raw_request'] = req or None

    rec['message'] = '{ip} - {method} {uri} -> {status} ({size} B) UA="{ua}"'.format(
        ip=rec['client_ip'],
        method=rec.get('http_method') or '?',
        uri=rec.get('uri') or req or '?',
        status=rec['http_status'] if rec['http_status'] is not None else '-',
        size=rec['bytes_sent'],
        ua=rec['user_agent'] or '-',
    )
    return rec


def parse_error(line):
    m = ERROR_RE.match(line)
    if not m:
        return None
    g = m.groupdict()

    dt = None
    for fmt in ERROR_TIME_FMTS:
        try:
            dt = datetime.strptime(g['ts'], fmt)
            break
        except ValueError:
            continue
    if dt is None:
        return None

    client = g['client']
    client_ip, client_port = client, None
    if client and client.count(':') == 1:
        client_ip, _, client_port = client.partition(':')

    return {
        'datetime': dt.isoformat(),
        'timestamp_desc': 'Apache Error Time',
        'source_short': 'LOG',
        'source_long': 'Apache Error Log',
        'log_level': g['level'],
        'module': g['module'],
        'pid': g['pid'],
        'tid': g['tid'],
        'client_ip': client_ip,
        'client_port': client_port,
        'message': '[{lvl}] {ip}{msg}'.format(
            lvl=g['level'],
            ip=(client_ip + ' ') if client_ip else '',
            msg=g['msg'],
        ),
        'error_message': g['msg'],
    }


# --------------------------------------------------------------------------
# Automatic tagging
# --------------------------------------------------------------------------

SUSPICIOUS_UA = re.compile(
    r'sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster|feroxbuster|'
    r'wpscan|hydra|zgrab|curl/|python-requests|go-http-client',
    re.I,
)
SUSPICIOUS_URI = re.compile(
    r'\.\./|/etc/passwd|union\s+select|<script|%3cscript|/wp-login|/phpmyadmin|'
    r'\.env\b|/\.git|cmd=|exec\(|base64_decode',
    re.I,
)


def auto_tag(rec):
    tags = []
    status = rec.get('http_status')
    if isinstance(status, int):
        if status in (401, 403):
            tags.append('access-denied')
        elif status == 404:
            tags.append('not-found')
        elif 500 <= status < 600:
            tags.append('server-error')
        elif 200 <= status < 300 and rec.get('http_method') in ('POST', 'PUT', 'DELETE'):
            tags.append('write-operation')
    if SUSPICIOUS_UA.search(rec.get('user_agent') or ''):
        tags.append('suspicious-ua')
    if SUSPICIOUS_URI.search(rec.get('uri') or ''):
        tags.append('suspicious-uri')
    if rec.get('log_level') in ('crit', 'alert', 'emerg', 'error'):
        tags.append('error')
    if tags:
        rec['tag'] = tags
    return rec


# --------------------------------------------------------------------------
# File discovery
# --------------------------------------------------------------------------

DEFAULT_PATTERNS = ('*.log', '*.log.*', '*_log', '*_log.*', 'access*', 'error*', '*.gz')
SKIP_RE = re.compile(r'\.(zip|tar|xz\.tar|pid|sock|db|sqlite|journal|offset|pos)$', re.I)
ROTATION_RE = re.compile(r'\.(\d+)(?:\.(?:gz|bz2|xz))?$')


def rotation_key(path):
    """Sort rotated files from oldest to newest: .5.gz < .2.gz < .1 < (current)."""
    m = ROTATION_RE.search(path)
    idx = int(m.group(1)) if m else -1
    base = ROTATION_RE.sub('', path)
    return (base, -idx)


def discover(inputs, recursive, patterns, exclude):
    files = []
    for item in inputs:
        if item == '-':
            files.append('-')
        elif os.path.isdir(item):
            if recursive:
                for root, _dirs, names in os.walk(item):
                    for n in names:
                        files.append(os.path.join(root, n))
            else:
                for n in os.listdir(item):
                    p = os.path.join(item, n)
                    if os.path.isfile(p):
                        files.append(p)
        elif any(c in item for c in '*?['):
            files.extend(glob.glob(item, recursive=True))
        elif os.path.isfile(item):
            files.append(item)
        else:
            print('  ! not found, skipped: {}'.format(item), file=sys.stderr)

    keep = []
    for f in files:
        if f == '-':
            keep.append(f)
            continue
        name = os.path.basename(f)
        if SKIP_RE.search(name):
            continue
        if exclude and re.search(exclude, f):
            continue
        if patterns and not any(glob.fnmatch.fnmatch(name, p) for p in patterns):
            continue
        keep.append(f)

    seen, out = set(), []
    for f in sorted(set(keep), key=lambda p: rotation_key(p) if p != '-' else ('', 0)):
        rp = os.path.realpath(f) if f != '-' else '-'
        if rp in seen:
            continue
        seen.add(rp)
        out.append(f)
    return out


def open_log(path):
    if path == '-':
        return sys.stdin
    if path.endswith('.gz'):
        return gzip.open(path, 'rt', errors='replace')
    if path.endswith('.bz2'):
        return bz2.open(path, 'rt', errors='replace')
    if path.endswith('.xz'):
        return lzma.open(path, 'rt', errors='replace')
    return open(path, 'r', errors='replace')


def guess_host(path, root):
    """Guess a hostname from the directory tree: /logs/web01/apache2/access.log -> web01"""
    if path == '-':
        return None
    rel = os.path.relpath(os.path.dirname(os.path.abspath(path)), os.path.abspath(root))
    parts = [p for p in rel.split(os.sep) if p not in ('.', '..', '')]
    ignore = {'apache2', 'httpd', 'log', 'logs', 'var'}
    for p in parts:
        if p.lower() not in ignore:
            return p
    return None


# --------------------------------------------------------------------------
# Writers
# --------------------------------------------------------------------------

class JsonlWriter:
    def __init__(self, path):
        self.fh = open(path, 'w')

    def write(self, rec):
        self.fh.write(json.dumps({k: v for k, v in rec.items() if v is not None},
                                 ensure_ascii=False) + '\n')

    def close(self):
        self.fh.close()


class CsvWriter:
    def __init__(self, path):
        self.fh = open(path, 'w', newline='')
        self.w = csv.DictWriter(self.fh, fieldnames=ALL_FIELDS, extrasaction='ignore')
        self.w.writeheader()

    def write(self, rec):
        row = dict(rec)
        if isinstance(row.get('tag'), list):
            row['tag'] = ','.join(row['tag'])
        self.w.writerow(row)

    def close(self):
        self.fh.close()


# --------------------------------------------------------------------------
# Main processing
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description='Apache -> Timesketch (file, glob, or full directory)')
    ap.add_argument('inputs', nargs='+',
                    help="files, directories, glob patterns, or '-' for stdin")
    ap.add_argument('-o', '--output', required=True,
                    help='output file (or prefix if --split)')
    ap.add_argument('-r', '--recursive', action='store_true',
                    help='walk subdirectories')
    ap.add_argument('--pattern', action='append', default=None,
                    help='filename pattern to keep (repeatable). '
                         'Default: *.log, *.log.*, access*, error*, *.gz')
    ap.add_argument('--exclude', default=None,
                    help='regex of paths to exclude')
    ap.add_argument('--type', choices=('access', 'error', 'auto'), default='auto')
    ap.add_argument('--format', choices=('jsonl', 'csv'), default='jsonl')
    ap.add_argument('--split', action='store_true',
                    help='separate access/error output (prefix = --output)')
    ap.add_argument('--auto-tag', action='store_true')
    ap.add_argument('--dedup', action='store_true',
                    help='deduplicate (overlaps between rotated files)')
    ap.add_argument('--tz', default=None, metavar='+02:00',
                    help='timezone applied to timestamps without an offset (error log)')
    ap.add_argument('--host', default=None,
                    help='hostname to force (otherwise guessed from the directory tree)')
    ap.add_argument('--no-source-path', action='store_true',
                    help='do not add the log_file field')
    ap.add_argument('--dry-run', action='store_true',
                    help='list the files that would be processed, then exit')
    args = ap.parse_args()

    patterns = args.pattern if args.pattern is not None else list(DEFAULT_PATTERNS)
    files = discover(args.inputs, args.recursive, patterns, args.exclude)

    if not files:
        sys.exit('No log file found. Adjust --pattern / --recursive.')

    if args.dry_run:
        print('{} file(s):'.format(len(files)))
        for f in files:
            print('  ' + f)
        return

    root = args.inputs[0] if os.path.isdir(args.inputs[0]) else os.path.dirname(
        os.path.abspath(args.inputs[0])) or '.'

    Writer = JsonlWriter if args.format == 'jsonl' else CsvWriter
    ext = '.jsonl' if args.format == 'jsonl' else '.csv'

    if args.split:
        base = args.output[:-len(ext)] if args.output.endswith(ext) else args.output
        writers = {'access': Writer(base + '.access' + ext),
                   'error': Writer(base + '.error' + ext)}
    else:
        w = Writer(args.output)
        writers = {'access': w, 'error': w}

    seen = set() if args.dedup else None
    total = skipped = dups = 0
    per_file = []

    for path in files:
        n_ok = n_ko = 0
        try:
            fh = open_log(path)
        except OSError as exc:
            print('  ! {} : {}'.format(path, exc), file=sys.stderr)
            continue

        host = args.host or guess_host(path, root)
        with fh:
            for line in fh:
                line = line.rstrip('\r\n')
                if not line.strip():
                    continue

                if args.type == 'auto':
                    rec = parse_error(line) if line.startswith('[') else parse_access(line)
                    if rec is None:
                        rec = parse_access(line) if line.startswith('[') else parse_error(line)
                elif args.type == 'error':
                    rec = parse_error(line) or parse_access(line)
                else:
                    rec = parse_access(line) or parse_error(line)

                if rec is None:
                    n_ko += 1
                    continue

                if seen is not None:
                    h = hashlib.blake2b(line.encode('utf-8', 'replace'),
                                        digest_size=16).digest()
                    if h in seen:
                        dups += 1
                        continue
                    seen.add(h)

                if args.tz and not TZ_SUFFIX_RE.search(rec['datetime']):
                    rec['datetime'] += args.tz

                kind = 'error' if rec['timestamp_desc'].endswith('Error Time') else 'access'
                rec['data_type'] = 'apache:' + kind
                if not args.no_source_path:
                    rec['log_file'] = path
                if host:
                    rec['log_host'] = host
                if args.auto_tag:
                    auto_tag(rec)

                writers[kind].write(rec)
                n_ok += 1

        total += n_ok
        skipped += n_ko
        per_file.append((path, n_ok, n_ko))
        print('  {:>9} ok  {:>6} ko   {}'.format(n_ok, n_ko, path), file=sys.stderr)

    for wr in set(writers.values()):
        wr.close()

    print('\n{} file(s), {} event(s), {} unparsed line(s), {} duplicate(s)'.format(
        len(per_file), total, skipped, dups), file=sys.stderr)

    worst = [(p, ok, ko) for p, ok, ko in per_file if ko and ko > ok]
    if worst:
        print('\nWarning — mostly unparsed files '
              '(custom LogFormat or another service?):', file=sys.stderr)
        for p, ok, ko in worst[:10]:
            print('  {} ({} ok / {} ko)'.format(p, ok, ko), file=sys.stderr)

    if total == 0:
        sys.exit(1)


if __name__ == '__main__':
    main()
