"""MEMTRIAGE core engine — defensive memory-dump triage.

Pure-stdlib analysis of a memory-dump export (a text/binary blob you own).
Extracts printable strings, scores IOCs (IPv4, URLs, hosts, emails, BTC,
registry persistence keys), and flags suspicious process names / artifacts.

No network. No external state. Read-only with respect to inputs.
"""
from __future__ import annotations

import json
import re
import html
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

TOOL_NAME = "MEMTRIAGE"
TOOL_VERSION = "1.0.0"

# Severity ordering (high index = worse) used for sorting + exit codes.
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# --- Extraction patterns ----------------------------------------------------

_ASCII_RUN = re.compile(rb"[\x20-\x7e]{4,}")

_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_RE_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\\]{4,256}", re.IGNORECASE)
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b")
_RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|top|xyz|info|biz|onion|su|cc|tk|pw)\b",
    re.IGNORECASE,
)
_RE_BTC = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_RE_WINPATH = re.compile(r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]+")

# Registry / persistence indicators.
_PERSISTENCE = re.compile(
    r"(?:CurrentVersion\\Run|CurrentVersion\\RunOnce|"
    r"\\Image File Execution Options|\\Winlogon|schtasks|"
    r"New-ScheduledTask|sc\.exe create|reg add)",
    re.IGNORECASE,
)

# Known-suspicious / living-off-the-land binaries that warrant a closer look
# when seen as a running image in a memory dump.
_SUSPICIOUS_PROCS = {
    "mimikatz.exe": "critical", "psexec.exe": "high", "psexesvc.exe": "high",
    "powershell.exe": "medium", "pwsh.exe": "medium", "cmd.exe": "low",
    "wscript.exe": "high", "cscript.exe": "high", "mshta.exe": "high",
    "rundll32.exe": "medium", "regsvr32.exe": "high", "certutil.exe": "high",
    "bitsadmin.exe": "high", "wmic.exe": "medium", "netcat.exe": "high",
    "nc.exe": "high", "cobaltstrike.exe": "critical", "lazagne.exe": "critical",
    "procdump.exe": "high", "sdelete.exe": "medium", "ngrok.exe": "high",
}

# Encoded-command / suspicious-string heuristics.
_SUSPICIOUS_STRINGS = [
    (re.compile(r"-enc(?:odedcommand)?\b", re.IGNORECASE), "high",
     "PowerShell encoded command"),
    (re.compile(r"FromBase64String", re.IGNORECASE), "high",
     "Base64 decode in script"),
    (re.compile(r"DownloadString|DownloadFile|Invoke-WebRequest|Net\.WebClient",
                re.IGNORECASE), "high", "In-memory download cradle"),
    (re.compile(r"Invoke-Expression|\bIEX\b", re.IGNORECASE), "high",
     "Dynamic code execution (IEX)"),
    (re.compile(r"VirtualAlloc|WriteProcessMemory|CreateRemoteThread",
                re.IGNORECASE), "critical", "Process-injection API"),
    (re.compile(r"-w(?:indowstyle)?\s+hidden", re.IGNORECASE), "medium",
     "Hidden window execution"),
    (re.compile(r"\b(?:ransom|decrypt your files|bitcoin wallet|\.locked)\b",
                re.IGNORECASE), "critical", "Ransomware note indicator"),
]

# RFC1918 / loopback / link-local — downgrade IPv4 findings that are internal.
_PRIVATE_NETS = (
    re.compile(r"^10\."), re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^127\."), re.compile(r"^169\.254\."), re.compile(r"^0\."),
)


@dataclass
class Finding:
    category: str
    severity: str
    value: str
    detail: str = ""
    count: int = 1

    def sort_key(self) -> tuple:
        return (-SEVERITY_ORDER.get(self.severity, 0), self.category, self.value)


@dataclass
class Report:
    tool: str = TOOL_NAME
    version: str = TOOL_VERSION
    source: str = ""
    generated: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    bytes_scanned: int = 0
    strings_extracted: int = 0
    findings: list = field(default_factory=list)

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "info"
        return max(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0)).severity

    def severity_counts(self) -> dict:
        counts = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_dict(self) -> dict:
        d = asdict(self)
        d["max_severity"] = self.max_severity
        d["severity_counts"] = self.severity_counts()
        return d


# --- Engine -----------------------------------------------------------------

def extract_strings(blob: bytes, min_len: int = 4) -> list:
    """Return printable ASCII runs (Volatility-style 'strings')."""
    if min_len <= 4:
        return [m.group().decode("ascii", "replace") for m in _ASCII_RUN.finditer(blob)]
    pat = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    return [m.group().decode("ascii", "replace") for m in pat.finditer(blob)]


def _dedup(values):
    seen = {}
    for v in values:
        seen[v] = seen.get(v, 0) + 1
    return seen


def analyze(blob: bytes, source: str = "<dump>", min_len: int = 4) -> Report:
    """Run the full triage pipeline over a memory-dump blob."""
    rep = Report(source=source, bytes_scanned=len(blob))
    strings = extract_strings(blob, min_len)
    rep.strings_extracted = len(strings)
    text = "\n".join(strings)

    findings: list = []

    # --- Network IOCs ---
    for ip, n in _dedup(_RE_IPV4.findall(text)).items():
        internal = any(p.match(ip) for p in _PRIVATE_NETS)
        findings.append(Finding(
            "ipv4", "low" if internal else "medium", ip,
            "RFC1918/loopback (internal)" if internal else "Public IPv4", n))

    for url, n in _dedup(_RE_URL.findall(text)).items():
        sev = "high" if re.search(r"\.(?:onion|top|xyz|tk|pw|ru|cn)\b", url, re.I) else "medium"
        findings.append(Finding("url", sev, url[:256], "Embedded URL", n))

    # Bare domains not already part of a URL/email.
    for dom, n in _dedup(m.group(0) for m in _RE_DOMAIN.finditer(text)).items():
        if dom in text and ("://" + dom not in text) and ("@" + dom not in text):
            sev = "high" if re.search(r"\.(?:onion|top|xyz|tk|pw)$", dom, re.I) else "low"
            findings.append(Finding("domain", sev, dom, "Hostname/domain", n))

    for em, n in _dedup(_RE_EMAIL.findall(text)).items():
        findings.append(Finding("email", "low", em, "Email address", n))

    for addr, n in _dedup(_RE_BTC.findall(text)).items():
        findings.append(Finding("crypto", "high", addr, "Bitcoin address", n))

    # --- Suspicious processes / images ---
    lowered = text.lower()
    for proc, sev in _SUSPICIOUS_PROCS.items():
        n = lowered.count(proc)
        if n:
            findings.append(Finding("process", sev, proc,
                                    "Suspicious / LOLBin image", n))

    # --- Persistence ---
    pcount = len(_PERSISTENCE.findall(text))
    if pcount:
        for m, n in _dedup(_PERSISTENCE.findall(text)).items():
            findings.append(Finding("persistence", "high", m,
                                    "Persistence mechanism reference", n))

    # --- Suspicious script / injection strings ---
    for pat, sev, label in _SUSPICIOUS_STRINGS:
        n = len(pat.findall(text))
        if n:
            findings.append(Finding("behavior", sev, label,
                                    "Heuristic match", n))

    # --- Notable file paths (executables in temp/appdata) ---
    for p, n in _dedup(_RE_WINPATH.findall(text)).items():
        if re.search(r"\\(?:Temp|AppData|ProgramData|Users\\Public)\\.*\.(?:exe|dll|ps1|bat|scr|vbs)$",
                     p, re.IGNORECASE):
            findings.append(Finding("path", "medium", p,
                                    "Executable in suspicious location", n))

    findings.sort(key=lambda f: f.sort_key())
    rep.findings = findings
    return rep


# --- Renderers --------------------------------------------------------------

def render_json(rep: Report) -> str:
    return json.dumps(rep.to_dict(), indent=2)


def render_table(rep: Report) -> str:
    lines = []
    lines.append(f"{TOOL_NAME} v{TOOL_VERSION} — memory triage report")
    lines.append(f"source : {rep.source}")
    lines.append(f"scanned: {rep.bytes_scanned:,} bytes  |  strings: {rep.strings_extracted:,}")
    sc = rep.severity_counts()
    lines.append("severity: " + "  ".join(
        f"{k}={sc[k]}" for k in ("critical", "high", "medium", "low", "info") if sc[k]))
    lines.append(f"max severity: {rep.max_severity.upper()}")
    lines.append("-" * 78)
    if not rep.findings:
        lines.append("No findings.")
        return "\n".join(lines)
    lines.append(f"{'SEV':<9}{'CATEGORY':<13}{'CNT':<5}VALUE / DETAIL")
    lines.append("-" * 78)
    for f in rep.findings:
        val = f.value if len(f.value) <= 46 else f.value[:43] + "..."
        lines.append(f"{f.severity:<9}{f.category:<13}{f.count:<5}{val}")
        if f.detail:
            lines.append(f"{'':<27}{f.detail}")
    lines.append("-" * 78)
    lines.append(f"{len(rep.findings)} finding(s).")
    return "\n".join(lines)


_SEV_COLORS = {
    "critical": "#7c1f2e", "high": "#c62828", "medium": "#ef6c00",
    "low": "#2e7d32", "info": "#546e7a",
}


def render_html(rep: Report) -> str:
    e = html.escape
    sc = rep.severity_counts()
    rows = []
    for f in rep.findings:
        color = _SEV_COLORS.get(f.severity, "#546e7a")
        rows.append(
            f'<tr><td><span class="badge" style="background:{color}">'
            f'{e(f.severity.upper())}</span></td>'
            f'<td class="cat">{e(f.category)}</td>'
            f'<td class="cnt">{f.count}</td>'
            f'<td class="val">{e(f.value)}</td>'
            f'<td class="det">{e(f.detail)}</td></tr>'
        )
    chips = "".join(
        f'<span class="chip" style="background:{_SEV_COLORS[k]}">{k}: {sc[k]}</span>'
        for k in ("critical", "high", "medium", "low", "info") if sc[k]
    ) or '<span class="chip" style="background:#546e7a">no findings</span>'
    max_color = _SEV_COLORS.get(rep.max_severity, "#546e7a")
    body = "\n".join(rows) or '<tr><td colspan="5" class="none">No findings.</td></tr>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(TOOL_NAME)} report — {e(rep.source)}</title>
<style>
*{{box-sizing:border-box}}
body{{font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
margin:0;background:#0f1419;color:#e6edf3}}
.wrap{{max-width:980px;margin:0 auto;padding:24px}}
header{{border-left:6px solid {max_color};padding:12px 18px;background:#161b22;border-radius:8px}}
h1{{margin:0 0 4px;font-size:20px}}
.sub{{color:#9aa7b4;font-size:13px}}
.meta{{display:flex;gap:18px;flex-wrap:wrap;margin:16px 0;font-size:13px;color:#c2ccd6}}
.meta b{{color:#e6edf3}}
.chips{{margin:12px 0}}
.chip,.badge{{display:inline-block;color:#fff;border-radius:12px;padding:2px 10px;
font-size:12px;font-weight:600;margin-right:6px}}
.badge{{border-radius:6px;padding:2px 8px;font-size:11px}}
table{{width:100%;border-collapse:collapse;margin-top:10px;background:#161b22;border-radius:8px;overflow:hidden}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #232b34;vertical-align:top}}
th{{background:#1c232c;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:#9aa7b4}}
td.val{{font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all}}
td.cnt{{text-align:right;color:#9aa7b4}}
td.det{{color:#9aa7b4;font-size:12px}}
.none{{text-align:center;color:#9aa7b4;padding:18px}}
footer{{margin-top:18px;color:#6b7785;font-size:12px}}
</style></head>
<body><div class="wrap">
<header>
<h1>{e(TOOL_NAME)} memory triage report</h1>
<div class="sub">Max severity: <b>{e(rep.max_severity.upper())}</b> &middot; {len(rep.findings)} finding(s)</div>
</header>
<div class="meta">
<span>source: <b>{e(rep.source)}</b></span>
<span>scanned: <b>{rep.bytes_scanned:,}</b> bytes</span>
<span>strings: <b>{rep.strings_extracted:,}</b></span>
<span>generated: <b>{e(rep.generated)}</b></span>
</div>
<div class="chips">{chips}</div>
<table>
<thead><tr><th>Severity</th><th>Category</th><th>Count</th><th>Value</th><th>Detail</th></tr></thead>
<tbody>
{body}
</tbody></table>
<footer>{e(TOOL_NAME)} v{e(TOOL_VERSION)} — defensive triage of artifacts you own. Heuristic; verify before acting.</footer>
</div></body></html>"""
