#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# utmp -> framed table (UTC) with optional ANSI colors for event "type"
# - '=' for top/bottom and under header
# - '-' between data rows
# - '|' vertical borders
# - Time in Local: HH:MM:SS, Weekday, DD Month YYYY
# Colors are applied only when writing to a TTY (not to files / pipes).

import os, sys, io, time, argparse, struct, ipaddress, re

# Ensure UTF-8 stdout (safe for pipes too)
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

parser = argparse.ArgumentParser(description="UTMP/WTMP framed table (UTC) with colorized types")
parser.add_argument("input", help="UTMP/WTMP file (e.g., /var/log/wtmp)")
parser.add_argument("-o", "--output", help="Output file (framed table). If omitted, prints to stdout (colors if TTY)")
args = parser.parse_args()

INPUT_FILE = args.input
OUTPUT_FILE = args.output

HEADERS = ["type", "pid", "line", "id", "user", "host", "term", "exit", "session", "sec", "usec", "addr"]

STATUS = {
    0: 'EMPTY',
    1: 'RUN_LVL',
    2: 'BOOT_TIME',
    3: 'NEW_TIME',
    4: 'OLD_TIME',
    5: 'INIT',
    6: 'LOGIN',
    7: 'USER',
    8: 'DEAD',
    9: 'ACCOUNTING',
}

RECORD_SIZE = 384  # glibc utmp record size on Linux

# ANSI colors
ANSI = {
    "reset":  "\033[0m",
    "red":    "\033[31m",
    "green":  "\033[32m",
    "yellow": "\033[33m",
    "blue":   "\033[34m",
    "cyan":   "\033[36m",
}
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

def q(val) -> str:
    """Quote any value like CSV-QUOTE_ALL did."""
    return f'"{str(val)}"'

def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)

def visible_len(s: str) -> int:
    return len(strip_ansi(s))

def parse_utmp(path):
    """Return list of rows with all values quoted as strings (row 0 is the header)."""
    rows = []
    rows.append([q(h) for h in HEADERS])

    with open(path, "rb") as f:
        filesize = os.path.getsize(path)
        offset = 0
        while offset + RECORD_SIZE <= filesize:
            f.seek(offset)

            typ  = struct.unpack("<L", f.read(4))[0]
            pid  = struct.unpack("<L", f.read(4))[0]
            line = f.read(32).decode("utf-8", "replace").split('\0', 1)[0]
            uid  = f.read(4).decode("utf-8", "replace").split('\0', 1)[0]
            user = f.read(32).decode("utf-8", "replace").split('\0', 1)[0]
            host = f.read(256).decode("utf-8", "replace").split('\0', 1)[0]
            term = struct.unpack("<H", f.read(2))[0]
            ex   = struct.unpack("<H", f.read(2))[0]
            sess = struct.unpack("<L", f.read(4))[0]
            sec  = struct.unpack("<L", f.read(4))[0]
            # Local formatted time
            sec_str = time.strftime("%H:%M:%S, %A, %d %B %Y", time.localtimetime(float(sec)))
            usec = struct.unpack("<L", f.read(4))[0]
            addr = ipaddress.IPv4Address(struct.unpack(">L", f.read(4))[0])

            typ_str = STATUS.get(typ, str(typ))

            row = [
                q(typ_str),
                q(pid),
                q(line),
                q(uid),
                q(user),
                q(host),
                q(term),
                q(ex),
                q(sess),
                q(sec_str),
                q(usec),
                q(addr),
            ]
            rows.append(row)
            offset += RECORD_SIZE

    return rows

def compute_widths(rows):
    """Compute max visible width for each column across all rows (no ANSI counted)."""
    ncols = len(rows[0])
    widths = [0]*ncols
    for r in rows:
        for i, val in enumerate(r):
            L = visible_len(val)
            if L > widths[i]:
                widths[i] = L
    return widths

def color_for_type(typ: str) -> str:
    """Choose ANSI color name for event type (plain string, not quoted)."""
    if   typ == "BOOT_TIME": return "yellow"
    elif typ == "RUN_LVL":   return "cyan"
    elif typ == "USER":      return "green"
    elif typ in ("LOGIN", "INIT"): return "blue"
    elif typ == "DEAD":      return "red"
    return ""  # no color

def maybe_color_cell(col_index: int, cell: str, is_header: bool, colorize: bool) -> str:
    """Colorize only the first column (type), keep quotes intact."""
    if not colorize or is_header:
        return cell
    if col_index != 0:
        return cell
    typ = cell.strip('"')
    cname = color_for_type(typ)
    if not cname:
        return cell
    return f"{ANSI[cname]}{cell}{ANSI['reset']}"

def format_row(row, widths, colorize=False, is_header=False):
    """Format a row with '|' borders and padded columns; padding counts visible width (ANSI-safe)."""
    parts = []
    for i, raw in enumerate(row):
        cell = maybe_color_cell(i, raw, is_header=is_header, colorize=colorize)
        pad = widths[i] - visible_len(raw)  # pad computed from uncolored content
        parts.append(cell + (" " * pad))
    return "|" + "|".join(parts) + "|"

def border(ch, length):
    return ch * length

def render_table(rows, colorize: bool):
    """Return the full framed table as a single string."""
    widths = compute_widths(rows)
    header_line = format_row(rows[0], widths, colorize=False, is_header=True)

    # borders must use **visible** length (no ANSI) to avoid drift when colors are present
    top_len = visible_len(header_line)
    top_border = border("=", top_len)
    header_border = border("=", top_len)

    out_lines = []
    out_lines.append(top_border)
    out_lines.append(header_line)
    out_lines.append(header_border)

    # Data rows with '-' separators and '=' bottom border
    for idx, r in enumerate(rows[1:], start=1):
        row_line = format_row(r, widths, colorize=colorize, is_header=False)
        out_lines.append(row_line)
        sep_len = visible_len(row_line)
        if idx < len(rows) - 1:
            out_lines.append(border("-", sep_len))
        else:
            out_lines.append(border("=", sep_len))
    return "\n".join(out_lines) + "\n"

def main():
    if not os.path.exists(INPUT_FILE):
        print("No input file found", file=sys.stderr)
        sys.exit(1)

    rows = parse_utmp(INPUT_FILE)

    # Enable colors only when writing to terminal AND no output file is specified
    colorize = (OUTPUT_FILE is None) and sys.stdout.isatty()

    table = render_table(rows, colorize=colorize)

    if OUTPUT_FILE:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as fo:
            fo.write(table)
    else:
        sys.stdout.write(table)

if __name__ == "__main__":
    main()
