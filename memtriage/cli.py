"""MEMTRIAGE command-line interface.

Usage:
    python -m memtriage triage DUMP [--format {table,json,html}] [--min-len N]
                                    [--output FILE] [--fail-on SEV]
    python -m memtriage --version

Exit codes:
    0  no findings at or above --fail-on threshold
    2  findings present (default fail-on=medium)
    3  usage / IO error
"""
from __future__ import annotations

import argparse
import sys

from . import core


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memtriage",
        description=f"{core.TOOL_NAME} v{core.TOOL_VERSION} — defensive memory-dump triage.",
    )
    p.add_argument("--version", action="version",
                   version=f"{core.TOOL_NAME} {core.TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    t = sub.add_parser("triage", help="Triage a memory-dump export.")
    t.add_argument("dump", help="Path to dump export ('-' for stdin).")
    t.add_argument("--format", choices=("table", "json", "html"),
                   default="table", help="Output format (default: table).")
    t.add_argument("--min-len", type=int, default=4,
                   help="Minimum printable-string length (default: 4).")
    t.add_argument("--output", "-o", help="Write report to FILE instead of stdout.")
    t.add_argument("--fail-on", choices=tuple(core.SEVERITY_ORDER),
                   default="medium",
                   help="Exit non-zero if a finding >= this severity exists "
                        "(default: medium).")
    return p


def _read_blob(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    with open(path, "rb") as fh:
        return fh.read()


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "triage":
        parser.print_help()
        return 3

    try:
        blob = _read_blob(args.dump)
    except OSError as exc:
        print(f"memtriage: cannot read {args.dump!r}: {exc}", file=sys.stderr)
        return 3

    source = "<stdin>" if args.dump == "-" else args.dump
    rep = core.analyze(blob, source=source, min_len=max(1, args.min_len))

    if args.format == "json":
        out = core.render_json(rep)
    elif args.format == "html":
        out = core.render_html(rep)
    else:
        out = core.render_table(rep)

    try:
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(out + ("\n" if not out.endswith("\n") else ""))
            print(f"memtriage: wrote {args.format} report to {args.output} "
                  f"(max severity: {rep.max_severity.upper()})", file=sys.stderr)
        else:
            print(out)
    except OSError as exc:
        print(f"memtriage: cannot write output: {exc}", file=sys.stderr)
        return 3

    threshold = core.SEVERITY_ORDER[args.fail_on]
    worst = core.SEVERITY_ORDER.get(rep.max_severity, 0)
    return 2 if (rep.findings and worst >= threshold) else 0


if __name__ == "__main__":
    raise SystemExit(main())
