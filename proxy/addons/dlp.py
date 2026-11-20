import base64
import hashlib
import json
import hmac
import logging
import math
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from mitmproxy import http, tcp
from ruamel.yaml import YAML

POLICY_FILE = Path(__file__).parent / "policy.yaml"
LOG_FILE = Path(os.environ.get("DLP_LOG", "/logs/decisions.jsonl"))
ENFORCE = True             # False = monitor mode: log what would be blocked, block nothing
TOKEN_SECRET = os.environ.get("DLP_TOKEN_SECRET", "").encode()

# The first bytes ("magic bytes") that identify common file types
SIGNATURES = {
    b"\xff\xd8\xff": "JPEG image",
    b"\x89PNG\r\n\x1a\n": "PNG image",
    b"GIF8": "GIF image",
    b"%PDF": "PDF document",
    b"PK\x03\x04": "ZIP archive (also DOCX/XLSX/PPTX)",
    b"\x1f\x8b": "GZIP archive",
    b"7z\xbc\xaf\x27\x1c": "7-Zip archive",
    b"Rar!\x1a\x07": "RAR archive",
}
ENTROPY_LIMIT = 7.5        # bits per byte; 8.0 = perfectly random
ENTROPY_MIN_SIZE = 1024    # too little data to judge below this
BASE64_RUN = re.compile(rb"[A-Za-z0-9+/]{200,}={0,2}")

def detect_file_type(data: bytes) -> str | None:
    """Return the file type if data starts with a known signature, else None."""
    for magic, kind in SIGNATURES.items():
        if data.startswith(magic):
            return kind
    return None

def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte: ~4-5 for text, ~8 for random/compressed/encrypted."""
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())

def scan(data: bytes, depth: int = 0) -> str | None:
    """Return why data must not leave the company, or None if it looks harmless."""
    kind = detect_file_type(data)
    if kind:
        return kind

    if depth < 2:                                        # don't decode forever
        for match in BASE64_RUN.finditer(data):
            run = match.group()
            run = run[: len(run) - len(run) % 4]         # base64 works in blocks of 4
            try:
                decoded = base64.b64decode(run)
            except ValueError:
                continue
            inner = scan(decoded, depth + 1)
            if inner:
                return f"base64-encoded {inner}"

    if len(data) >= ENTROPY_MIN_SIZE and entropy(data) > ENTROPY_LIMIT:
        return f"unidentified high-entropy data ({entropy(data):.2f} bits/byte)"
    return None

def split_multipart(body: bytes, boundary: bytes) -> list[dict]:
    """Split a multipart/form-data body into its parts."""
    parts = []
    delimiter = b"--" + boundary

    for chunk in body.split(delimiter)[1:]:
        if chunk.startswith(b"--"):          # "--boundary--" marks the end
            break
        head, sep, data = chunk.partition(b"\r\n\r\n")
        if not sep:                          # no empty line: not a valid part
            continue
        data = data.removesuffix(b"\r\n")    # this CRLF belongs to the next delimiter

        headers = head.decode("latin-1")
        name = re.search(r'\bname="([^"]*)"', headers)
        filename = re.search(r'filename="([^"]*)"', headers)
        parts.append({
            "name": name.group(1) if name else "?",
            "filename": filename.group(1) if filename else None,
            "data": data,
        })
    return parts

def company_account(req: http.Request, company_domain: str) -> str | None:
    """Return the email of a valid company token in the request, else None."""
    if not TOKEN_SECRET or not company_domain:
        return None                                   # fail closed

    auth = req.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return None

    email, _, signature = auth.removeprefix("Bearer ").rpartition(":")
    expected = hmac.new(TOKEN_SECRET, email.encode(), hashlib.sha256).hexdigest()
    if not email or not hmac.compare_digest(signature, expected):
        return None                                   # forged or tampered token

    if not email.endswith("@" + company_domain):
        return None                                   # real token, but not a company account
    return email

def host_in(host: str, domains: list) -> bool:
    """True if host is one of the domains or a subdomain of one."""
    return any(host == d or host.endswith("." + d) for d in domains)

def login_username(req: http.Request) -> str | None:
    """Read the username field from a login form or JSON body."""
    ctype = req.headers.get("content-type", "")
    if "application/x-www-form-urlencoded" in ctype:
        return req.urlencoded_form.get("username")
    if "application/json" in ctype:
        try:
            data = req.json()
        except ValueError:
            return None
        if isinstance(data, dict):
            return data.get("username")
    return None

def record(verdict: str, client: str, host: str, what: str, reason: str = "", size: int = 0) -> None:
    """Append one decision to the shared log file (one JSON object per line)."""
    entry = {
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": "proxy",
        "verdict": verdict,
        "client": client,
        "host": host,
        "what": what,
        "reason": reason,
        "size": size,
    }
    try:
        with LOG_FILE.open("a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        logging.exception("[DLP] could not write the decision log")

def record_flow(flow: http.HTTPFlow, verdict: str, reason: str = "") -> None:
    """record() for an HTTP request."""
    req = flow.request
    what = f"CONNECT port {req.port}" if req.method == "CONNECT" else f"{req.method} {req.path}"
    record(verdict, flow.client_conn.peername[0], req.pretty_host, what, reason, len(req.content or b""))

def block(flow: http.HTTPFlow, reason: str) -> None:
    """Answer the client ourselves; the request never reaches the server."""
    if not ENFORCE:
        logging.warning(f"[DLP] WOULD BLOCK (monitor mode) {flow.request.pretty_host}{flow.request.path}: {reason}")
        record_flow(flow, "monitor", reason)
        return
    flow.response = http.Response.make(
        403,
        f"Blocked by DLP policy: {reason}\n".encode(),
        {"Content-Type": "text/plain"},
    )
    logging.warning(f"[DLP] BLOCKED {flow.request.pretty_host}{flow.request.path}: {reason}")
    record_flow(flow, "blocked", reason)

class DLP:
    def __init__(self) -> None:
        self.policy: dict = {}
        self.policy_mtime: float | None = None

    def load_policy(self) -> None:
        """(Re)load policy.yaml whenever the file has changed."""
        mtime = POLICY_FILE.stat().st_mtime
        if mtime != self.policy_mtime:
            self.policy = YAML(typ="safe").load(POLICY_FILE.read_text()) or {}
            self.policy_mtime = mtime
            global ENFORCE
            ENFORCE = self.policy.get("enforce", True)
            logging.info(f"[DLP] policy loaded: {self.policy}")

    def is_approved(self, host: str) -> bool:
        """True if host is an approved destination or a subdomain of one."""
        return host_in(host, self.policy.get("approved_destinations", []))
    
    def http_connect(self, flow: http.HTTPFlow) -> None:
        """Only allow tunnels to the ports the policy lists (normally just HTTPS)."""
        self.load_policy()
        port = flow.request.port
        if port not in self.policy.get("tunnel_ports", [443]):
            block(flow, f"tunnel to port {port} is not allowed")

    def tcp_message(self, flow: tcp.TCPFlow) -> None:
        """A tunnel carrying neither HTTP nor TLS can't be inspected, so cut it."""
        flow.messages[-1].content = b""
        if flow.live:
            logging.warning(f"[DLP] BLOCKED raw TCP to {flow.server_conn.address}: not HTTP or TLS")
            host, port = flow.server_conn.address
            record("blocked", flow.client_conn.peername[0], f"{host}:{port}", "raw TCP tunnel", "not HTTP or TLS")
            flow.kill()   
       
    def request(self, flow: http.HTTPFlow) -> None:
        try:
            self.inspect(flow)
        except Exception:
            logging.exception("[DLP] error while inspecting, blocking to be safe")
            block(flow, "internal DLP error")

    def inspect(self, flow: http.HTTPFlow) -> None:
        self.load_policy()
        req = flow.request
        body = req.content or b""
        if not body:
            return
        
        domain = self.policy.get("company_domain", "")
        if host_in(req.pretty_host, self.policy.get("webmail_services", [])) and req.path.startswith("/login"):
            user = login_username(req)
            if not user or not domain or not user.lower().endswith("@" + domain):
                block(flow, f"webmail login with a non-company account ({user!r})")
                return
            logging.info(f"[DLP] allowed webmail login for company account {user}")
            record_flow(flow, "allowed", f"webmail login, company account {user}")
            return
        
        if self.is_approved(req.pretty_host):
            account = company_account(req, self.policy.get("company_domain", ""))
            if account:
                logging.info(f"[DLP] allowed {req.pretty_host}{req.path}: company account {account}")
                record_flow(flow, "allowed", f"approved destination, company account {account}")
                return
            logging.info(f"[DLP] {req.pretty_host} is approved, but no valid company account: checking content")
            record_flow(flow, "allowed", "no sensitive content found")
        
        ctype = req.headers.get("content-type", "")
        m = re.search(r'boundary="?([^";]+)"?', ctype)

        if "multipart/form-data" in ctype and m:
            for part in split_multipart(body, m.group(1).encode()):
                kind = scan(part["data"])
                logging.info(f"[DLP]   part {part['name']!r} file={part['filename']!r} "
                             f"{len(part['data'])} bytes -> {kind or 'looks harmless'}")
                if kind:
                    block(flow, f"{kind} in field '{part['name']}' (filename {part['filename']!r})")
                    return
        else:
            kind = scan(body)
            if kind:
                block(flow, f"{kind} in request body")
                return

        logging.info(f"[DLP] allowed {req.method} {req.pretty_host}{req.path} ({len(body)} bytes)")
        record_flow(flow, "allowed", "no sensitive content found")

addons = [DLP()]