"""Runtime Behavioral Contracts for the five laboratory agents."""

from __future__ import annotations

from evadeagent.models import RuntimeContract

CONTRACTS: dict[str, RuntimeContract] = {
    "document-assistant": RuntimeContract(
        agent="document-assistant",
        allowed_intents=frozenset({"document_search", "document_summary"}),
        allowed_tools=frozenset({"document.search", "document.read"}),
        allowed_mcp=frozenset({"mcp://documents/search", "mcp://documents/read"}),
        allowed_processes=frozenset({"document-assistant", "document-reader"}),
        allowed_files=frozenset({"/workspace/documents"}),
        allowed_endpoints=frozenset({"document-api", "llm-api"}),
    ),
    "coding-agent": RuntimeContract(
        agent="coding-agent",
        allowed_intents=frozenset({"code_edit", "run_tests"}),
        allowed_tools=frozenset({"git.read", "git.write", "test.execute"}),
        allowed_mcp=frozenset({"mcp://git/read", "mcp://git/write", "mcp://test/run"}),
        allowed_processes=frozenset({"coding-agent", "git", "compiler", "test-runner"}),
        allowed_files=frozenset({"/workspace/repository"}),
        allowed_endpoints=frozenset({"github.com", "package-registry"}),
    ),
    "devops-agent": RuntimeContract(
        agent="devops-agent",
        allowed_intents=frozenset({"restart_service", "diagnose_failure"}),
        allowed_tools=frozenset({"k8s.observe", "k8s.diagnose", "k8s.restart"}),
        allowed_mcp=frozenset({"mcp://k8s/observe", "mcp://k8s/diagnose", "mcp://k8s/restart"}),
        allowed_processes=frozenset({"devops-agent", "kubectl"}),
        allowed_files=frozenset({"/workspace/runbooks"}),
        allowed_endpoints=frozenset({"kubernetes-api"}),
    ),
    "database-agent": RuntimeContract(
        agent="database-agent",
        allowed_intents=frozenset({"query_report"}),
        allowed_tools=frozenset({"db.query", "report.generate"}),
        allowed_mcp=frozenset({"mcp://db/query", "mcp://report/generate"}),
        allowed_processes=frozenset({"database-agent", "query-engine"}),
        allowed_files=frozenset({"/workspace/reports"}),
        allowed_endpoints=frozenset({"database-api"}),
    ),
    "knowledge-agent": RuntimeContract(
        agent="knowledge-agent",
        allowed_intents=frozenset({"knowledge_search"}),
        allowed_tools=frozenset({"search.query", "vector.lookup"}),
        allowed_mcp=frozenset({"mcp://search/query", "mcp://vector/lookup"}),
        allowed_processes=frozenset({"knowledge-agent", "vector-client"}),
        allowed_files=frozenset({"/workspace/index"}),
        allowed_endpoints=frozenset({"search-api", "vector-db", "llm-api"}),
    ),
    "ticket-agent": RuntimeContract(
        agent="ticket-agent",
        allowed_intents=frozenset({"triage_ticket"}),
        allowed_tools=frozenset({"ticket.read", "ticket.comment"}),
        allowed_mcp=frozenset({"mcp://ticket/read", "mcp://ticket/comment"}),
        allowed_processes=frozenset({"ticket-agent", "ticket-client"}),
        allowed_files=frozenset({"/workspace/tickets"}),
        allowed_endpoints=frozenset({"ticket-api"}),
    ),
    "mail-agent": RuntimeContract(
        agent="mail-agent",
        allowed_intents=frozenset({"draft_reply"}),
        allowed_tools=frozenset({"mail.read", "mail.draft"}),
        allowed_mcp=frozenset({"mcp://mail/read", "mcp://mail/draft"}),
        allowed_processes=frozenset({"mail-agent", "mail-client"}),
        allowed_files=frozenset({"/workspace/mail"}),
        allowed_endpoints=frozenset({"mail-api", "llm-api"}),
    ),
}

AGENTS = tuple(CONTRACTS)


def contract_for(agent: str) -> RuntimeContract:
    return CONTRACTS[agent]
