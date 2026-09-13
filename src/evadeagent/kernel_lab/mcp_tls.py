"""Lab MCP over TLS 1.3. Token comes from EVADE_MCP_TOKEN. No secrets in source.

Self-signed ECDSA P-256 / SHA-256 certificates are generated at runtime for
this laboratory only. They are not for public-facing systems.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

TOOLS = {
    "document.search": "mcp://documents/search",
    "document.read": "mcp://documents/read",
}
WORKSPACE_PREFIX = "/workspace/documents"
NOTE_NAME = "note.md"
NOTE_TEXT = "architecture note for the laboratory cell\n"


class McpError(RuntimeError):
    pass


def require_token() -> str:
    token = os.environ.get("EVADE_MCP_TOKEN", "")
    if len(token) < 16:
        raise McpError("EVADE_MCP_TOKEN must be set in the environment (16+ characters)")
    return token


def write_lab_certs(cert_dir: Path, *, reuse: bool = False) -> tuple[Path, Path]:
    """Create a one-day lab certificate. Files are not committed."""
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert = cert_dir / "cert.pem"
    key = cert_dir / "key.pem"
    if reuse and cert.is_file() and key.is_file():
        return cert, key
    cmd = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-sha256",
        "-days",
        "1",
        "-nodes",
        "-keyout",
        str(key),
        "-out",
        str(cert),
        "-subj",
        "/CN=evade-lab-mcp",
        "-addext",
        "subjectAltName=DNS:mcp,DNS:localhost,IP:127.0.0.1",
    ]
    completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise McpError(completed.stderr.strip() or "openssl failed to write lab certificates")
    key.chmod(0o600)
    cert.chmod(0o644)
    return cert, key


def server_tls_context(cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(str(cert), str(key))
    return ctx


def client_tls_context(ca: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(str(ca))
    return ctx


class LabMcp:
    """File-only document tools. Writes an audit JSONL. Does not load BPF."""

    def __init__(self, workspace: Path, audit: Path, token: str) -> None:
        self.workspace = workspace
        self.audit = audit
        self._token = token
        docs = workspace / "workspace" / "documents"
        docs.mkdir(parents=True, exist_ok=True)
        note = docs / NOTE_NAME
        if not note.is_file():
            note.write_text(NOTE_TEXT, encoding="utf-8")
        self.audit.parent.mkdir(parents=True, exist_ok=True)

    def authorized(self, header: str) -> bool:
        prefix = "Bearer "
        if not header.startswith(prefix):
            return False
        offered = header[len(prefix) :]
        return hmac.compare_digest(offered, self._token)

    def call(self, tool: str, args: dict[str, Any], t: int) -> dict[str, Any]:
        if tool not in TOOLS:
            raise McpError(f"unknown tool {tool}")
        if tool == "document.search":
            result = {"hits": [f"{WORKSPACE_PREFIX}/{NOTE_NAME}"]}
        else:
            logical = str(args.get("path") or f"{WORKSPACE_PREFIX}/{NOTE_NAME}")
            if not logical.startswith(WORKSPACE_PREFIX):
                raise McpError("path outside /workspace/documents")
            rel = logical[len(WORKSPACE_PREFIX) :].lstrip("/")
            text = (self.workspace / "workspace" / "documents" / rel).read_text(encoding="utf-8")
            result = {"path": logical, "chars": len(text)}
        row = {"uri": TOOLS[tool], "tool": tool, "t": t, "tls": "TLSv1.3"}
        with self.audit.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, separators=(",", ":")) + "\n")
        return {"ok": True, "tool": tool, "uri": TOOLS[tool], "result": result}

    def handler(self) -> type[BaseHTTPRequestHandler]:
        mcp = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/health":
                    self._send(200, {"ok": True, "tls": "TLSv1.3"})
                    return
                self._send(404, {"error": "not found"})

            def do_POST(self) -> None:  # noqa: N802
                if self.path != "/v1/call":
                    self._send(404, {"error": "not found"})
                    return
                if not mcp.authorized(self.headers.get("Authorization", "")):
                    self._send(401, {"error": "unauthorized"})
                    return
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                try:
                    payload = mcp.call(str(body.get("tool") or ""), dict(body.get("args") or {}), int(body.get("t") or 0))
                except McpError as exc:
                    self._send(400, {"error": str(exc)})
                    return
                self._send(200, payload)

            def _send(self, status: int, payload: dict[str, Any]) -> None:
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        return Handler


class LabMcpServer:
    def __init__(self, mcp: LabMcp, cert: Path, key: Path, host: str = "127.0.0.1", port: int = 0) -> None:
        self._httpd = ThreadingHTTPServer((host, port), mcp.handler())
        self._httpd.socket = server_tls_context(cert, key).wrap_socket(self._httpd.socket, server_side=True)
        self.host, self.port = self._httpd.server_address[:2]
        self.url = f"https://{self.host}:{self.port}"
        self._thread: threading.Thread | None = None

    def start(self) -> "LabMcpServer":
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=2)


def call_tool(url: str, ca: Path, token: str, tool: str, t: int, args: dict[str, Any] | None = None) -> dict[str, Any]:
    body = json.dumps({"tool": tool, "t": t, "args": args or {}}).encode("utf-8")
    request = Request(
        f"{url.rstrip('/')}/v1/call",
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, context=client_tls_context(ca), timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise McpError(f"MCP HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise McpError(str(exc.reason)) from exc


def run_document_session(url: str, ca: Path, token: str, *, extra_read: bool = False) -> list[dict[str, Any]]:
    """One document-assistant tool sequence. Returns the live audit rows."""
    call_tool(url, ca, token, "document.search", 0)
    call_tool(url, ca, token, "document.read", 1, {"path": f"{WORKSPACE_PREFIX}/{NOTE_NAME}"})
    if extra_read:
        call_tool(url, ca, token, "document.read", 5, {"path": f"{WORKSPACE_PREFIX}/{NOTE_NAME}"})
    return []


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    init = sub.add_parser("init-certs")
    init.add_argument("--dir", type=Path, required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--bind", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8443)
    serve.add_argument("--cert-dir", type=Path, default=Path("/certs"))
    serve.add_argument("--workspace", type=Path, default=Path("/lab"))
    serve.add_argument("--audit", type=Path, default=Path("/out/mcp-live.jsonl"))
    args = parser.parse_args()
    if args.cmd == "init-certs":
        cert, key = write_lab_certs(args.dir)
        print(f"wrote {cert} {key}")
        return 0
    token = require_token()
    cert, key = write_lab_certs(args.cert_dir, reuse=True)
    mcp = LabMcp(args.workspace, args.audit, token)
    server = LabMcpServer(mcp, cert, key, host=args.bind, port=args.port)
    print(f"listening {server.url} tls=TLSv1.3", flush=True)
    try:
        server._httpd.serve_forever()
    except KeyboardInterrupt:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
