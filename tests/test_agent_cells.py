from evadeagent.kernel_lab.agent_cells import EXPECTED, PILOT_AGENTS, PILOT_CELLS
from evadeagent.kernel_lab.execute import write_executed_agent_dumps
from evadeagent.kernel_lab.mcp_tls import (
    LabMcp,
    LabMcpServer,
    McpError,
    call_tool,
    run_agent_session,
    write_lab_certs,
)
from evadeagent.kernel_lab.pilot import run_pilot
import secrets

import pytest


def test_all_pilot_agents_match_expected() -> None:
    for agent in PILOT_AGENTS:
        payload = run_pilot(agent=agent)
        assert payload["mismatches"] == [], payload["mismatches"]
        assert payload["encoding_disagreements"] == [], payload["encoding_disagreements"]
        for cell in PILOT_CELLS:
            assert payload["cells"][cell]["shape"]["C5"] == EXPECTED[cell]["C5"]


def test_executed_agent_dumps(tmp_path) -> None:
    dump = write_executed_agent_dumps(tmp_path / "agents")
    for agent in PILOT_AGENTS:
        payload = run_pilot(dump / agent, agent=agent)
        assert payload["mismatches"] == []


def test_coding_and_devops_tls_sessions(tmp_path) -> None:
    token = secrets.token_urlsafe(32)
    cert, key = write_lab_certs(tmp_path / "certs")
    mcp = LabMcp(tmp_path / "ws", tmp_path / "audit.jsonl", token)
    server = LabMcpServer(mcp, cert, key).start()
    try:
        run_agent_session(server.url, cert, token, "coding-agent")
        run_agent_session(server.url, cert, token, "devops-agent")
        run_agent_session(server.url, cert, token, "database-agent")
        run_agent_session(server.url, cert, token, "mail-agent")
        with pytest.raises(McpError):
            call_tool(server.url, cert, token, "k8s.diagnose", 1, {"path": "/lab/secrets/token"})
    finally:
        server.stop()
    text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "mcp://git/read" in text
    assert "mcp://k8s/observe" in text
    assert "mcp://db/query" in text
    assert "mcp://mail/read" in text
    assert token not in text
