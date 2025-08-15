# log-grok-parser

Robust single-file CLI to parse logs using **Grok** patterns via `py3grok`.  
It supports Logstash-style pattern files, curated presets, inline/builtin patterns, CSV/JSONL output, and an auto-selection mode.

> **Why this tool?** It adapts across multiple `py3grok` API variants and includes a minimal syslog-compat layer, so it keeps working even when upstream changes break other scripts.

## Features
- Load patterns from a directory (recursively, any text file)
- Merge an external patterns file (`.json` or `.yaml`)
- Choose pattern by:
  - `--use-pattern NAME` (from loaded patterns)
  - `--pattern-inline "<grok…>"`
  - `--builtin {apache_combined, nginx_access, syslog_rfc3164}`
  - `--auto` (scores candidates against a sample)
  - `--preset-from-file presets/*.json` (try a curated list in order, picks best by hits/field-richness)
- Output to **CSV** (`--delimiter` supported) or **JSONL**
- Keep only specific fields with `--fields`
- Works even with older/newer `py3grok` builds

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Basic usage (syslog):
```bash
python log_grok_parser.py \\
  -i examples/syslog_rfc3164.log \\  -o out.jsonl \\  --builtin syslog_rfc3164
```

With custom patterns:
```bash
python log_grok_parser.py \\  -i examples/nginx_access.log \\  -o out.csv \\  --format csv \\  --patterns-dir patterns/custom \\  --use-pattern NGINX_ACCESS \\  --fields ts client_ip method uri status bytes user_agent
```

Auto-select from your patterns:
```bash
python log_grok_parser.py \\  -i /var/log/syslog \\  -o syslog.csv \\  --auto --sample 2000 --patterns-dir patterns/custom
```

Preset-driven selection:
```bash
python log_grok_parser.py \\  -i /var/log/syslog \\  -o parsed.jsonl \\  --preset-from-file presets/common_web_and_syslog.json \\  --patterns-dir patterns/custom \\  --min-richness 2.0
```

Merge an external mapping (JSON/YAML):
```bash
python log_grok_parser.py \\  -i my.log \\  -o parsed.jsonl \\  --patterns-dir patterns/custom \\  --patterns-file patterns/custom/patterns.json
```

Inline pattern (overrides other selectors):
```bash
python log_grok_parser.py \\  -i my.log \\  -o out.csv \\  --pattern-inline '%{IPORHOST:ip} - - \[%{HTTPDATE:ts}\] "%{WORD:method} %{URIPATHPARAM:uri} HTTP/%{NUMBER:ver}"' \\  --format csv
```

## CLI
Run `python log_grok_parser.py -h` for the full help.

**Key flags:**
- `-i, --input` path to the log file (required)
- `-o, --output` path to write (.csv or .jsonl) (required)
- `--format` explicit output format (otherwise inferred from extension)
- `--delimiter` CSV delimiter (default: `,`)
- `--limit` stop after N matching lines

**Pattern sources**
- `--patterns-dir DIR` load Logstash-style patterns (recursively)
- `--patterns-file FILE` merge mapping from `.json`/`.yaml`
- `--use-pattern NAME` wrap as `%{NAME}` and use it
- `--pattern-inline "<grok>"` full Grok expression
- `--builtin [apache_combined|nginx_access|syslog_rfc3164]` minimal built-ins

**Auto / Preset**
- `--auto` try all loaded names and pick the best
- `--sample N` first N lines to score (default: 2000)
- `--min-richness F` min avg. fields per hit (default: 0.0)
- `--preset-from-file FILE` JSON list with names to consider

**Fields / Output**
- `--fields f1 f2 …` explicit field order (default: detected)
- Outputs CSV or JSONL depending on `--format` or `-o` extension

## Patterns
Place your Logstash-style files under `patterns/custom/`. Each non-comment line is:
```
NAME REGEX...
```
Example (see `patterns/custom/example.grok`):
```
NGINX_ACCESS %{IPORHOST:client_ip} - %{DATA:auth} \[%{HTTPDATE:ts}\] "%{WORD:method} %{URIPATHPARAM:uri} HTTP/%{NUMBER:http_version}" %{NUMBER:status:int} (?:%{NUMBER:bytes:int}|-) "%{DATA:referrer}" "%{DATA:user_agent}" (?:%{NUMBER:request_time:float}|-) (?:%{NUMBER:upstream_response_time:float}|-)
```

To reuse curated lists, drop third‑party packs under `patterns/3rdparty/` (already populated if you provided `Patterns.zip`).

## Presets
A preset is a JSON array of pattern names, e.g. `presets/common_web_and_syslog.json`:
```json
[
  "SYSLOG_RFC3164",
  "NGINX_ACCESS",
  "APACHE_COMBINED"
]
```

## Tips & Troubleshooting
- **No lines matched**: verify the selected pattern; try `--auto` or a simpler builtin first.
- **Preset auto-selection did not find a suitable pattern**: raise `--sample`, loosen `--min-richness`, or expand your preset list.
- **YAML errors**: install `pyyaml` or stick to JSON for `--patterns-file`.
- **Syslog tokens missing**: built-in `syslog_rfc3164` seeds a minimal compat set automatically.

## License
MIT — see [LICENSE](LICENSE).

## Acknowledgements
- [`py3grok`](https://pypi.org/project/py3grok/) — Grok engine for Python.
- Community Logstash/Grok patterns collections.