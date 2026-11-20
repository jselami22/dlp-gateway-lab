import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from email import message_from_bytes
from email.utils import parseaddr
from pathlib import Path

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword


COMPANY_DOMAIN = "corp.local"
USERS = {
    "alice@corp.local": "alice123",
    "bob@corp.local": "bob123",
    "carol@corp.local": "carol123",
}
MAILBOXES = Path("/mail")
LOG_FILE = Path(os.environ.get("DLP_LOG", "/logs/decisions.jsonl"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logging.getLogger("mail.log").setLevel(logging.WARNING)   # quiet aiosmtpd's own chatter
log = logging.getLogger("corpmail")

def record(verdict: str, client: str, what: str, reason: str, size: int = 0) -> None:
    """Append one mail decision to the shared decision log."""
    entry = {
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": "mail",
        "verdict": verdict,
        "client": client,
        "host": "mail.corp",
        "what": what,
        "reason": reason,
        "size": size,
    }
    try:
        with LOG_FILE.open("a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        log.exception("[MAIL] could not write the decision log")

def check_password(server, session, envelope, mechanism, auth_data):
    if isinstance(auth_data, LoginPassword):
        user = auth_data.login.decode()
        if USERS.get(user) == auth_data.password.decode():
            log.info(f"[MAIL] login ok: {user}")
            return AuthResult(success=True, auth_data=user)
        log.warning(f"[MAIL] login FAILED for {user}")
        record("blocked", session.peer[0], f"login {user}", "wrong password")
    return AuthResult(success=False, handled=False)


class CompanyMail:
    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        user = session.auth_data
        if address.lower() != user:
            log.warning(f"[MAIL] REJECTED sender {address}: logged in as {user}")
            record("blocked", session.peer[0], f"MAIL FROM {address}", f"logged in as {user}, tried to send as {address}")
            return f"553 5.7.1 You are logged in as {user}, you cannot send as {address}"
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 OK"

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if not address.lower().endswith("@" + COMPANY_DOMAIN):
            log.warning(f"[MAIL] REJECTED recipient {address}: not a company address")
            record("blocked", session.peer[0], f"mail {envelope.mail_from} -> {address}", "recipient is not a company address")
            return "554 5.7.1 Only company recipients are allowed"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        message = message_from_bytes(envelope.content)
        _, header_from = parseaddr(message.get("From", ""))
        if header_from.lower() != envelope.mail_from.lower():
            log.warning(f"[MAIL] REJECTED message: From header {header_from!r} != sender {envelope.mail_from}")
            record("blocked", session.peer[0], f"mail from {envelope.mail_from}", f"From header {header_from!r} does not match the sender")            
            return "554 5.7.1 From header does not match the logged-in sender"

        for rcpt in envelope.rcpt_tos:
            box = MAILBOXES / rcpt.lower()
            box.mkdir(parents=True, exist_ok=True)
            (box / f"{time.time_ns()}.eml").write_bytes(envelope.content)
        log.info(f"[MAIL] delivered {envelope.mail_from} -> {', '.join(envelope.rcpt_tos)} ({len(envelope.content)} bytes)")
        record("allowed", session.peer[0], f"mail {envelope.mail_from} -> {', '.join(envelope.rcpt_tos)}",
               "company to company", len(envelope.content))
        return "250 Message delivered"

if __name__ == "__main__":
    controller = Controller(
        CompanyMail(),
        hostname="0.0.0.0",
        port=587,
        authenticator=check_password,
        auth_required=True,
        auth_require_tls=False,
    )
    controller.start()
    log.info("[MAIL] mail.corp listening on port 587")
    threading.Event().wait()