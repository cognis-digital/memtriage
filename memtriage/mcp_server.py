"""MEMTRIAGE MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from memtriage.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-memtriage[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-memtriage[mcp]'")
        return 1
    app = FastMCP("memtriage")

    @app.tool()
    def memtriage_scan(target: str) -> str:
        """Triage memory-dump artifacts: strings, IOCs, suspicious processes from a dump export. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
