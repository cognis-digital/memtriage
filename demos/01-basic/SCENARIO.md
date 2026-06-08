# Demo 01 — Basic memory-dump triage

**Scenario.** An incident responder has captured a strings/IOC export from a
memory dump of a workstation they own and administer (`dump_export.txt`). They
need a fast first-pass triage before opening a full Volatility session.

This is a *defensive* workflow: analysis of an artifact you own. MEMTRIAGE does
not attack anything — it reads a blob, extracts printable strings, and scores
indicators.

## Run it

Table (human) view:

```
python -m memtriage triage demos/01-basic/dump_export.txt
```

Machine-readable for a pipeline:

```
python -m memtriage triage demos/01-basic/dump_export.txt --format json
```

Shareable HTML report (the tool's "UI"):

```
python -m memtriage triage demos/01-basic/dump_export.txt --format html -o report.html
```

Read from stdin (e.g. piping a live `strings` run):

```
strings memory.raw | python -m memtriage triage - --format json
```

## What it should find

- **critical** — `mimikatz.exe`, process-injection API combo
  (`VirtualAlloc`/`WriteProcessMemory`/`CreateRemoteThread`), ransom note text.
- **high** — C2 over `.top`/`.xyz`/`.ru` domains, download cradles
  (`DownloadString`, `certutil` URL fetch), encoded PowerShell (`-enc`),
  `mshta`/`certutil`/`ngrok` LOLBins, BTC wallet, registry/schtasks persistence.
- **medium** — public IPv4 C2 addresses, executables in `Temp`/`Public`.
- **low** — internal RFC1918 addresses, the operator email.

## Exit code

With the default `--fail-on medium`, this dump trips a non-zero exit (`2`)
because critical/high findings are present — handy for gating in CI / SOAR.
