# utmp-tools

Two tiny CLI utilities for Linux **UTMP/WTMP** inspection with a readable framed table output.

- **utmp_localtime.py** — prints timestamps in **local time**.
- **utmp_utctime.py** — prints timestamps in **UTC**.

Both tools:
- read binary UTMP/WTMP files (e.g., `/var/log/wtmp`);
- render a fixed-width table with borders (`=`, `-`, `|`);
- colorize the **type** column (BOOT_TIME/USER/DEAD/etc.) when writing to a TTY;
- keep quotes on all fields (CSV-like) and compute padding ignoring ANSI codes;
- can write to a file via `-o/--output` (no colors in files).

> ⚠️ These scripts parse the glibc UTMP layout (384 bytes). They are intended for typical Linux systems.

## Install

No dependencies are required (stdlib only). You can run directly with Python 3.9+:

```bash
python utmp_utctime.py -h
python utmp_localtime.py -h
```

Optional: make them executable and add to `$PATH`:

```bash
chmod +x utmp_utctime.py utmp_localtime.py
sudo install -m 0755 utmp_utctime.py /usr/local/bin/utmp-utctime
sudo install -m 0755 utmp_localtime.py /usr/local/bin/utmp-localtime
```

## Usage

```bash
# UTC time
./utmp_utctime.py /var/log/wtmp

# Local time
./utmp_localtime.py /var/log/wtmp

# Save to file (no colors)
./utmp_utctime.py /var/log/wtmp -o wtmp.table
```

### Output Format (columns)
`type | pid | line | id | user | host | term | exit | session | sec | usec | addr`

- **type** — decoded numeric UTMP type (BOOT_TIME, USER, DEAD, ...)
- **sec** — formatted time string (`HH:MM:SS, Weekday, DD Month YYYY`) in UTC or local time
- **addr** — parsed IPv4 address (big-endian 32-bit value)

## Examples

> Real UTMP files are system-specific; we do not ship samples here. On most distros, try `/var/log/wtmp` with sudo.

```bash
sudo ./utmp_utctime.py /var/log/wtmp | head -n 30
sudo ./utmp_localtime.py /var/log/wtmp -o wtmp_local.table
```

## Notes
- Colors are applied **only** when writing to a terminal and no `-o/--output` is used.
- Borders length is computed from **visible** characters, so alignment doesn't drift with ANSI colors.
- IPv6-only addresses in UTMP are not handled (most systems store IPv4 or IPv4-mapped values here).

## License
MIT — see [LICENSE](LICENSE).

## Try with included examples

```bash
./utmp_utctime.py examples/example_wtmp_utc.bin
./utmp_localtime.py examples/example_wtmp_local.bin
```
