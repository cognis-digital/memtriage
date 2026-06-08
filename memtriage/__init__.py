"""MEMTRIAGE — fast, stdlib-only memory-dump triage (defensive forensics).

Triages a memory-dump export you own: extracts printable strings, scores IOCs
(IPv4/URL/domain/email/BTC), flags suspicious processes/LOLBins, persistence
references, and injection/download heuristics. Spirit of Volatility 'strings'
+ IOC scan, in one zero-install package.
"""
from .core import (
    TOOL_NAME,
    TOOL_VERSION,
    Finding,
    Report,
    analyze,
    extract_strings,
    render_json,
    render_table,
    render_html,
)

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "Report",
    "analyze",
    "extract_strings",
    "render_json",
    "render_table",
    "render_html",
]
__version__ = TOOL_VERSION
