"""Deterministic plan paraphrase bank. Not an LLM API and not model output."""

from __future__ import annotations

PLAN_COUNT = 4

# Four wording variants per agent. None contain B2 surface tokens.
PLAN_BANK: dict[str, tuple[tuple[str, ...], ...]] = {
    "document-assistant": (
        ("search documents", "read latest architecture note", "summarize"),
        ("locate workspace notes", "open the latest architecture note", "write a short summary"),
        ("query the document index", "load the requested note", "produce a synopsis"),
        ("find matching documents", "read the selected file", "return a condensed brief"),
    ),
    "coding-agent": (
        ("read repository", "apply edit", "run tests"),
        ("open the repository", "write the change", "execute the test suite"),
        ("inspect current sources", "apply the patch", "verify with tests"),
        ("check out the tree", "edit the target file", "run unit tests"),
    ),
    "devops-agent": (
        ("observe cluster", "diagnose pod", "restart workload"),
        ("read cluster status", "inspect the failing pod", "restart the workload"),
        ("list cluster objects", "diagnose the incident", "roll the deployment"),
        ("collect cluster signals", "identify the bad pod", "restart the service"),
    ),
    "database-agent": (
        ("query warehouse", "generate report"),
        ("run the warehouse query", "build the report"),
        ("fetch query results", "render the report"),
        ("execute the analytical query", "assemble the report"),
    ),
    "knowledge-agent": (
        ("search corpus", "lookup embeddings", "answer"),
        ("query the corpus", "retrieve nearest embeddings", "compose an answer"),
        ("search the index", "lookup related vectors", "return the answer"),
        ("find matching passages", "read embedding neighbors", "draft the reply"),
    ),
    "ticket-agent": (
        ("read ticket", "add comment"),
        ("open the ticket", "write a comment"),
        ("load ticket fields", "append a note"),
        ("fetch the ticket", "record a comment"),
    ),
    "mail-agent": (
        ("read inbox", "draft reply"),
        ("open the message", "compose a reply"),
        ("load the thread", "write a draft"),
        ("fetch the mail", "prepare a reply"),
    ),
}


def plan_for(agent: str, plan_id: int = 0) -> tuple[str, ...]:
    bank = PLAN_BANK[agent]
    return bank[plan_id % len(bank)]
