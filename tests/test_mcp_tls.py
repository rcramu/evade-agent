import secrets
from pathlib import Path

import pytest

from evadeagent.kernel_lab.mcp_tls import (
    LabMcp,
    LabMcpServer,
    McpError,
    call_tool,
    write_lab_certs,
)


def test_tls13_session_and_audit(tmp_path: Path) -> None:
    token = secrets.token_urlsafe(32)
    cert, key = write_lab_certs(tmp_path / "certs")
    audit = tmp_path / "mcp.jsonl"
    mcp = LabMcp(tmp_path / "ws", audit, token)
    server = LabMcpServer(mcp, cert, key).start()
    try:
        first = call_tool(server.url, cert, token, "document.search", 0)
        second = call_tool(
            server.url,
            cert,
            token,
            "document.read",
            1,
            {"path": "/workspace/documents/note.md"},
        )
    finally:
        server.stop()
    assert first["uri"] == "mcp://documents/search"
    assert second["uri"] == "mcp://documents/read"
    lines = [line for line in audit.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 2
    assert "TLSv1.3" in audit.read_text(encoding="utf-8")
    assert token not in audit.read_text(encoding="utf-8")


def test_bad_token_rejected(tmp_path: Path) -> None:
    token = secrets.token_urlsafe(32)
    cert, key = write_lab_certs(tmp_path / "certs")
    mcp = LabMcp(tmp_path / "ws", tmp_path / "mcp.jsonl", token)
    server = LabMcpServer(mcp, cert, key).start()
    try:
        with pytest.raises(McpError):
            call_tool(server.url, cert, "xxxxxxxxxxxxxxxx", "document.search", 0)
    finally:
        server.stop()


def test_path_outside_workspace_rejected(tmp_path: Path) -> None:
    token = secrets.token_urlsafe(32)
    cert, key = write_lab_certs(tmp_path / "certs")
    mcp = LabMcp(tmp_path / "ws", tmp_path / "mcp.jsonl", token)
    server = LabMcpServer(mcp, cert, key).start()
    try:
        with pytest.raises(McpError):
            call_tool(
                server.url,
                cert,
                token,
                "document.read",
                1,
                {"path": "/lab/secrets/token"},
            )
    finally:
        server.stop()


def test_token_not_in_source() -> None:
    text = Path(__file__).resolve().parents[1].joinpath("src/evadeagent/kernel_lab/mcp_tls.py").read_text(
        encoding="utf-8"
    )
    assert "EVADE_MCP_TOKEN" in text
    assert "sk_" not in text
