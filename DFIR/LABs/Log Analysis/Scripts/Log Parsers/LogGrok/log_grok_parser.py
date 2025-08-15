#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Log parser with py3grok — robust across py3grok API variants
- Loads Logstash-style patterns from a directory (recursively, any text file)
- Optionally merges an external patterns file (.json or .yaml)
- Supports: built-in patterns, inline pattern, specific pattern name, auto-select, preset JSON
- CSV / JSONL output, field selection, sampling limit

This version is hardened for older/newer py3grok builds where:
  * `Grok()` may not accept `custom_patterns` kwarg
  * `Grok()` may expect `available_patterns` as a dict of objects having `.regex_str`
  * pattern compilation happens via setting `.pattern` property
The code below adapts accordingly and wraps loaded pattern strings into lightweight
objects exposing `.regex_str`.
"""

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

try:
    from py3grok import Grok
except ImportError:
    sys.stderr.write("py3grok not found. Install:\n  pip install py3grok\n")
    raise

# ---------- Built-in example top-level patterns (optional) ----------
BUILTIN_TOPLEVEL: Dict[str, str] = {
    "apache_combined": r'%{IPORHOST:client_ip} %{DATA:ident} %{DATA:auth} \[%{HTTPDATE:ts}\] '
                       r'"%{WORD:method} %{URIPATHPARAM:uri} HTTP/%{NUMBER:http_version}" '
                       r'%{NUMBER:status:int} (?:%{NUMBER:bytes:int}|-) '
                       r'"%{DATA:referrer}" "%{DATA:user_agent}"',

    "nginx_access": r'%{IPORHOST:client_ip} - %{DATA:auth} \[%{HTTPDATE:ts}\] '
                    r'"%{WORD:method} %{URIPATHPARAM:uri} HTTP/%{NUMBER:http_version}" '
                    r'%{NUMBER:status:int} (?:%{NUMBER:bytes:int}|-) '
                    r'"%{DATA:referrer}" "%{DATA:user_agent}" '
                    r'(?:%{NUMBER:request_time:float}|-) (?:%{NUMBER:upstream_response_time:float}|-)',

    # RFC3164-ish; requires base SYSLOG* tokens from patterns
    "syslog_rfc3164": r'%{SYSLOGTIMESTAMP:ts} %{SYSLOGHOST:host} %{SYSLOGPROG}: %{GREEDYDATA:msg}',
}

# Minimal compatible base patterns for syslog, used as fallback when needed
MIN_SYSLOG_COMPAT: Dict[str, str] = {
    "WORD": r"\b\w+\b",
    "DATA": r".*?",
    "GREEDYDATA": r".*",
    "BASE10NUM": r"(?:[+-]?(?:[0-9]+)(?:\.[0-9]+)?)",
    "NUMBER": r"(?:%{BASE10NUM})",
    "INT": r"(?:[+-]?(?:[0-9]+))",
    "POSINT": r"\b(?:[1-9][0-9]*)\b",
    "MONTH": r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b",
    "MONTHDAY": r"(?:0?[1-9]|[12][0-9]|3[01])",
    "HOUR": r"(?:2[0-3]|[01]?[0-9])",
    "MINUTE": r"(?:[0-5]?[0-9])",
    "SECOND": r"(?:(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?)",
    "TIME": r"%{HOUR}:%{MINUTE}(?::%{SECOND})?",
    "HOSTNAME": r"\b(?:[A-Za-z0-9][A-Za-z0-9-]{0,62})(?:\.(?:[A-Za-z0-9][A-Za-z0-9-]{0,62}))*\b",
    "IP": r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.(?!$)|$)){4}",
    "IPORHOST": r"(?:%{IP}|%{HOSTNAME})",
    "SYSLOGHOST": r"%{IPORHOST}",
    "PROG": r"(?:[\w._/%-]+)",
    "SYSLOGPROG": r"%{PROG:program}(?:\[%{POSINT:pid}\])?",
    "SYSLOGTIMESTAMP": r"%{MONTH:month}\s+%{MONTHDAY:day}\s+%{TIME:time}",
    "SYSLOGLINE": r"%{SYSLOGTIMESTAMP:ts}\s+%{SYSLOGHOST:host}\s+%{SYSLOGPROG}:\s+%{GREEDYDATA:msg}",
}

# ---------- IO helpers ----------
def _expand(p: Optional[Path]) -> Optional[Path]:
    if p is None:
        return None
    try:
        return Path(str(p)).expanduser()
    except Exception:
        return p

def iter_lines(path: Path) -> Iterable[str]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            yield line.rstrip("\n")

def peek_lines(path: Path, max_lines: int) -> List[str]:
    out = []
    for i, line in enumerate(iter_lines(path)):
        out.append(line)
        if i + 1 >= max_lines:
            break
    return out

# ---------- Patterns loader (Logstash-style files) ----------
LINE_RE = re.compile(r"""
    ^\s*
    (?P<name>[A-Za-z0-9_:-]+)
    \s+
    (?P<pattern>.+?)
    \s*$
""", re.VERBOSE)

def is_probably_text(file: Path, sniff_bytes: int = 2048) -> bool:
    try:
        data = file.read_bytes()[:sniff_bytes]
        return b"\x00" not in data
    except Exception:
        return False

def load_patterns_dir(patterns_dir: Path) -> Dict[str, str]:
    patterns_dir = _expand(patterns_dir)
    if not patterns_dir or not patterns_dir.exists() or not patterns_dir.is_dir():
        raise FileNotFoundError(f"Patterns dir not found or not a directory: {patterns_dir}")
    patterns: Dict[str, str] = {}
    for file in sorted(patterns_dir.rglob("*")):
        if not file.is_file():
            continue
        if not is_probably_text(file):
            continue
        try:
            with file.open("r", encoding="utf-8", errors="replace") as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = LINE_RE.match(line)
                    if not m:
                        hash_pos = line.find(" #")
                        if hash_pos != -1:
                            line2 = line[:hash_pos].rstrip()
                            m = LINE_RE.match(line2)
                        if not m:
                            continue
                    name = m.group("name")
                    pattern = m.group("pattern")
                    hash_pos = pattern.find(" #")
                    if hash_pos != -1:
                        pattern = pattern[:hash_pos].rstrip()
                    patterns[name] = pattern
        except Exception:
            continue
    return patterns

# ---------- External patterns file (.json/.yaml) ----------
def load_patterns_file(path: Path) -> Dict[str, str]:
    if not path:
        return {}
    path = _expand(path)
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("JSON patterns file must be a mapping {name: pattern}.")
        return {str(k): str(v) for k, v in data.items()}
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except Exception as e:
            raise RuntimeError("YAML provided but PyYAML is not installed. pip install pyyaml") from e
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("YAML must contain mapping {name: pattern}.")
        return {str(k): str(v) for k, v in data.items()}
    raise ValueError("Unsupported patterns file type. Use .json or .yaml/.yml")

# ---------- Preset loader ----------
def load_preset_names(path: Path) -> List[str]:
    path = _expand(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Preset JSON must be a list of pattern names.")
    return [str(x) for x in data]

# ---------- py3grok compatibility wrappers ----------
class _CompatPattern:
    """Lightweight wrapper exposing .regex_str for py3grok variants."""
    __slots__ = ("regex_str",)
    def __init__(self, regex_str: str):
        self.regex_str = regex_str

def make_available_patterns(patterns: Dict[str, str]) -> Dict[str, _CompatPattern]:
    """Wrap string patterns into objects with .regex_str for py3grok."""
    return {name: _CompatPattern(regex) for name, regex in patterns.items()}

def build_grok(pattern_text: str, patterns: Dict[str, str]) -> Grok:
    """Try multiple py3grok constructor signatures, fallback to 2-step set."""
    avail = make_available_patterns(patterns)
    # 1) positional dict
    try:
        return Grok(pattern_text, avail)  # type: ignore[arg-type]
    except TypeError:
        pass
    # 2) keyword available_patterns
    try:
        return Grok(pattern_text, available_patterns=avail)  # type: ignore[call-arg]
    except TypeError:
        pass
    # 3) 2-step: create empty, set available_patterns, then set pattern (compiles)
    g = Grok("")
    setattr(g, "available_patterns", avail)
    g.pattern = pattern_text  # triggers compilation in most versions
    return g

# ---------- Parsing & Output ----------
def sanitize_field_order(fields: Optional[List[str]], example_match: Dict[str, object]) -> List[str]:
    if fields:
        return fields
    common = ["ts", "client_ip", "host", "program", "pid", "method", "uri", "status", "bytes", "user_agent", "referrer", "msg", "message"]
    ordered = [k for k in common if k in example_match]
    ordered += [k for k in example_match.keys() if k not in ordered]
    return ordered

def write_csv(rows: Iterable[Dict[str, object]], outfile: Path, field_order: List[str], delimiter: str = ",") -> int:
    n = 0
    with outfile.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=field_order, delimiter=delimiter, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow(row)
            n += 1
    return n

def write_jsonl(rows: Iterable[Dict[str, object]], outfile: Path) -> int:
    n = 0
    with outfile.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
            n += 1
    return n

def parse_stream(lines: Iterable[str], grok: Grok, fields: Optional[List[str]] = None, limit: Optional[int] = None) -> Iterable[Dict[str, object]]:
    count = 0
    for line in lines:
        m = grok.match(line)
        if m:
            yield {k: m.get(k) for k in (fields or m.keys())}
            count += 1
            if limit and count >= limit:
                break

# ---------- Auto selection ----------
def choose_best_pattern(sample_lines: List[str], candidate_names: List[str], all_patterns: Dict[str, str], min_fields_weight: float = 0.0) -> Tuple[Optional[str], int, float]:
    best = (None, 0, 0.0)
    for name in candidate_names:
        if name not in all_patterns:
            continue
        pattern_text = f"%{{{name}}}"
        try:
            grok = build_grok(pattern_text, all_patterns)
        except Exception:
            continue
        hits = 0
        fields_total = 0
        for ln in sample_lines:
            m = grok.match(ln)
            if m:
                hits += 1
                fields_total += len(m)
        richness = (fields_total / hits) if hits else 0.0
        if hits > best[1] or (hits == best[1] and richness > best[2]):
            best = (name, hits, richness)
    if best[0] is not None and best[2] < min_fields_weight:
        return (None, 0, 0.0)
    return best

# ---------- CLI ----------
def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Parse logs with Grok patterns (py3grok). Load patterns from directory or use inline/built-ins/preset.")
    p.add_argument("-i", "--input", required=True, type=Path, help="Path to log file")
    p.add_argument("-o", "--output", required=True, type=Path, help="Output file path (.csv or .jsonl)")
    p.add_argument("--format", choices=["csv", "jsonl"], help="Output format (infer from extension if omitted)")
    p.add_argument("--delimiter", default=",", help="CSV delimiter (default: ,)")
    p.add_argument("--limit", type=int, help="Stop after N matching lines")

    # pattern sources
    p.add_argument("--patterns-dir", type=Path, help="Directory with Logstash-style patterns (extension optional)")
    p.add_argument("--patterns-file", type=Path, help="External patterns file (.json or .yaml) [optional, merged]")
    p.add_argument("--use-pattern", help="Top-level pattern NAME from patterns (applied as '%{NAME}')")
    p.add_argument("--pattern-inline", help="Inline Grok pattern string (overrides --use-pattern)")
    p.add_argument("--builtin", choices=sorted(BUILTIN_TOPLEVEL.keys()), help="Use one of built-in top-level patterns")

    # auto detect
    p.add_argument("--auto", action="store_true", help="Auto-select the best top-level pattern from patterns-dir")
    p.add_argument("--sample", type=int, default=2000, help="How many first lines to test in auto mode (default: 2000)")
    p.add_argument("--min-richness", type=float, default=0.0, help="Auto/preset modes: min average fields per hit (default: 0.0)")

    # curated preset
    p.add_argument("--preset-from-file", type=Path, help="Path to JSON file with a list of pattern names (curated preset). Requires --patterns-dir.")

    # output fields
    p.add_argument("--fields", nargs="+", help="Output fields to keep (default: all matched)")

    return p

# ---------- Main ----------

def infer_format_from_path(path: Path, explicit: Optional[str]) -> str:
    if explicit:
        return explicit
    ext = path.suffix.lower()
    if ext == ".csv":
        return "csv"
    if ext in (".jsonl", ".ndjson"):
        return "jsonl"
    raise ValueError("Cannot infer format from output extension. Use --format.")

def main() -> None:
    args = build_argparser().parse_args()

    # expand ~ for all paths
    args.input = _expand(args.input)
    args.output = _expand(args.output)
    args.patterns_dir = _expand(args.patterns_dir)
    args.patterns_file = _expand(args.patterns_file)
    args.preset_from_file = _expand(args.preset_from_file)

    # collect patterns
    merged_patterns: Dict[str, str] = {}

    # 1) from dir (Logstash-style), ANY regular file
    if args.patterns_dir:
        merged_patterns.update(load_patterns_dir(args.patterns_dir))

    # 2) from external file (JSON/YAML) — optional
    if args.patterns_file:
        merged_patterns.update(load_patterns_file(args.patterns_file))

    # If user selected builtin syslog and we still lack base tokens, seed minimal set
    if args.builtin == "syslog_rfc3164":
        # Ensure core SYSLOG* tokens exist
        need = ("SYSLOGTIMESTAMP", "SYSLOGHOST", "SYSLOGPROG", "GREEDYDATA")
        if any(n not in merged_patterns for n in need):
            merged_patterns = {**MIN_SYSLOG_COMPAT, **merged_patterns}

    # Decide final pattern text
    pattern_text: Optional[str] = None
    chosen_name: Optional[str] = None

    if args.pattern_inline:
        pattern_text = args.pattern_inline
        chosen_name = "inline"
    elif args.use_pattern:
        if not merged_patterns:
            sys.stderr.write("--use-pattern requires --patterns-dir or --patterns-file with definitions.\n")
            sys.exit(2)
        if args.use_pattern not in merged_patterns:
            sys.stderr.write(f"Pattern '{args.use_pattern}' not found in provided patterns.\n")
            sys.exit(2)
        pattern_text = f"%{{{args.use_pattern}}}"
        chosen_name = args.use_pattern
    elif args.preset_from_file:
        if not args.patterns_dir and not args.patterns_file:
            sys.stderr.write("--preset-from-file requires --patterns-dir or --patterns-file.\n")
            sys.exit(2)
        if not merged_patterns:
            sys.stderr.write("No patterns loaded from directory/file.\n")
            sys.exit(2)
        try:
            candidate_names = load_preset_names(args.preset_from_file)
        except Exception as e:
            sys.stderr.write(f"Failed to load preset file: {e}\n")
            sys.exit(2)
        candidate_names = [n for n in candidate_names if n in merged_patterns]
        if not candidate_names:
            sys.stderr.write("None of the preset names were found in the provided patterns.\n")
            sys.exit(1)
        sample_lines = peek_lines(args.input, max_lines=args.sample)
        best_name, hits, richness = choose_best_pattern(sample_lines, candidate_names, merged_patterns, min_fields_weight=args.min_richness)
        if not best_name:
            sys.stderr.write("Preset auto-selection did not find a suitable pattern.\n")
            sys.exit(1)
        pattern_text = f"%{{{best_name}}}"
        chosen_name = f"preset:{best_name}"
        sys.stdout.write(f"[preset] Selected pattern: {best_name} (hits={hits}, avg_fields={richness:.2f})\n")
    elif args.auto:
        if not merged_patterns:
            sys.stderr.write("--auto requires patterns (dir or file).\n")
            sys.exit(2)
        sample_lines = peek_lines(args.input, max_lines=args.sample)
        candidate_names = list(merged_patterns.keys())
        best_name, hits, richness = choose_best_pattern(sample_lines, candidate_names, merged_patterns, min_fields_weight=args.min_richness)
        if not best_name:
            sys.stderr.write("Auto mode failed to find a suitable pattern.\n")
            sys.exit(1)
        pattern_text = f"%{{{best_name}}}"
        chosen_name = best_name
        sys.stdout.write(f"[auto] Selected pattern: {best_name} (hits={hits}, avg_fields={richness:.2f})\n")
    elif args.builtin:
        pattern_text = BUILTIN_TOPLEVEL[args.builtin]
        chosen_name = args.builtin
    else:
        sys.stderr.write(
            "No pattern provided. Use one of:\n"
            "  --pattern-inline '<grok>'\n"
            "  --use-pattern NAME --patterns-dir DIR or --patterns-file FILE\n"
            "  --preset-from-file PRESET.json --patterns-dir DIR or --patterns-file FILE\n"
            "  --auto --patterns-dir DIR or --patterns-file FILE\n"
            "  --builtin {" + ", ".join(BUILTIN_TOPLEVEL.keys()) + "}\n"
        )
        sys.exit(2)

    # compile grok (compat across py3grok builds)
    try:
        grok = build_grok(pattern_text, merged_patterns) if merged_patterns else build_grok(pattern_text, MIN_SYSLOG_COMPAT)
    except Exception as e:
        sys.stderr.write(f"Failed to compile Grok pattern: {e}\n")
        sys.exit(2)

    # first match to establish field order (unless user provided --fields)
    first_match = None
    for line in iter_lines(args.input):
        m = grok.match(line)
        if m:
            first_match = m
            break

    if not first_match:
        sys.stderr.write("No lines matched the selected pattern.\n")
        sys.exit(1)

    field_order = sanitize_field_order(args.fields, first_match)
    out_fmt = infer_format_from_path(args.output, args.format)

    # stream parse
    rows = parse_stream(iter_lines(args.input), grok, fields=field_order if field_order else None, limit=args.limit)

    # write
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if out_fmt == "csv":
        n = write_csv(rows, args.output, field_order, delimiter=args.delimiter)
    else:
        n = write_jsonl(rows, args.output)

    sys.stdout.write(
        f"Done. Wrote {n} record(s) to {args.output} using pattern {chosen_name}.\n"
        f"Fields: {', '.join(field_order)}\n"
    )

if __name__ == "__main__":
    main()
