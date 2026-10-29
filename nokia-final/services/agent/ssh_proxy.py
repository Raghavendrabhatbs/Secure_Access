"""
Nokia NBUC — SSH Session Intelligence Platform
ssh_proxy.py — Synchronous keystroke interceptor using ssh-mitm

Architecture:
  Client → Warpgate (:8888) → [ssh_proxy.py :2223] → Real SSH Target (:22)

This proxy sits INSIDE the SSH byte stream.
handle_client_data() is called SYNCHRONOUSLY before each keystroke chunk
is forwarded to the server, giving us a hard, race-free interception point.

Usage:
  Install:  pip install ssh-mitm
  Run:      python services/agent/ssh_proxy.py
  Env vars: PROXY_LISTEN_PORT, PROXY_TARGET_HOST, PROXY_TARGET_PORT,
            AI_AGENT_URL, AI_AGENT_TOKEN, WARPGATE_URL, WARPGATE_TOKEN
"""

import base64
import logging
import os
import re
import sys
import threading
import time
from typing import Optional
from uuid import UUID

import pyte
import requests
from sshmitm.forwarders.ssh import SSHForwarder
from sshmitm.server import SSHProxyServer

# ─── Configuration ──────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

PROXY_LISTEN_PORT = int(os.getenv("PROXY_LISTEN_PORT", "2223"))
PROXY_TARGET_HOST = os.getenv("PROXY_TARGET_HOST", "127.0.0.1")
PROXY_TARGET_PORT = int(os.getenv("PROXY_TARGET_PORT", "22"))

AI_AGENT_URL   = os.getenv("AI_AGENT_URL", "http://localhost:8000")
API_BASE_URL = AI_AGENT_URL.rstrip("/")
AI_AGENT_TOKEN = os.getenv("AI_AGENT_TOKEN", "")
ALERT_SECRET = os.getenv("ALERT_SECRET", "")

WARPGATE_URL   = os.getenv("WARPGATE_URL", "https://localhost:8888")
WARPGATE_TOKEN = os.getenv("WARPGATE_TOKEN", "")
WARPGATE_CA_BUNDLE = os.getenv("WARPGATE_CA_BUNDLE") or True
WARPGATE_TARGET_NAME = os.getenv("WARPGATE_TARGET_NAME", "wsl-target")
PROXY_SESSION_MODE = os.getenv("PROXY_SESSION_MODE", "warpgate").casefold()

# How long (seconds) we wait for an AI verdict before allowing the keystroke
AI_TIMEOUT_SECONDS = float(os.getenv("AI_TIMEOUT_SECONDS", "12.0"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ssh_proxy] %(levelname)s %(message)s",
)
log = logging.getLogger("ssh_proxy")

# ─── Per-session command buffer ──────────────────────────────────────────────

# Matched against the line as it is typed; bare words are anchored with \b to avoid
# hits like "asphalt" or "reboot.log" prefixes inside longer words.
_PARTIAL_DANGER = re.compile(
    r"(rm\s+-[^\s]*(?:rf|fr)"
    r"|\bmkfs"
    r"|\bdd\s+if="
    r"|(?<![\w./-])(?:shutdown|reboot|halt|poweroff)(?![\w.-])|\binit\s+0\b"
    r"|chmod\s+(?:-\w+\s+)*[0-7]*7[0-7]*\s+/etc"
    r"|/etc/(?:shadow|sudoers)"
    r"|\b(?:wget|curl)\b[^\n]{0,80}\|\s*(?:ba)?sh\b"
    r"|\bnc(?:at)?\b.*\s-e\s+/bin"
    r"|:\(\)\s*\{"
    r"|base64\s+-d.*\|"
    r"|python[23]?\s+-c.*socket"
    r"|>\s*/dev/(?:sd[a-z]|nvme)"
    r"|iptables\s+-F|ufw\s+disable"
    r"|passwd\s+root"
    r"|sudo\s+(?:-i|su)\b"
    r"|>>\s*/etc/(?:passwd|shadow|sudoers)"
    r"|(?:pkill\s+-9\s+-f|killall\s+-9)"
    r"|systemctl\s+(?:stop|disable)\s+ssh"
    r"|\b(?:hydra|hashcat|msfconsole|msfvenom)\b"
    r"|[;&|]\s*(?:rm|dd)\s"
    r"|/bin/(?:ba)?sh\s+-i)",
    re.IGNORECASE,
)

# Splits a line into the separately executed commands inside it.
_SEPARATORS = re.compile(r"&&|\|\||[;&|\n`]|\$\(|\)")
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")


def _rm_recursive_force(part: str) -> bool:
    """True for rm with recursive and force flags in any spelling (-rf, -r -f, -fR, --recursive --force)."""
    tokens = part.split()
    for i, tok in enumerate(tokens):
        if tok.lstrip("\\").rsplit("/", 1)[-1] != "rm":
            continue
        short, long_ = set(), set()
        for flag in tokens[i + 1:]:
            if flag.startswith("--"):
                long_.add(flag)
            elif flag.startswith("-") and len(flag) > 1:
                short.update(flag[1:].lower())
            else:
                break
        if ("r" in short or "--recursive" in long_) and ("f" in short or "--force" in long_):
            return True
    return False


def _decoded_payloads(text: str) -> list[str]:
    """Printable text recovered from base64-looking tokens."""
    found = []
    for tok in _B64_TOKEN.findall(text):
        try:
            raw = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True)
        except Exception:
            continue
        decoded = raw.decode("utf-8", errors="ignore")
        if decoded and sum(c.isprintable() for c in decoded) / len(decoded) > 0.9:
            found.append(decoded)
    return found


def _expand_escapes(text: str) -> Optional[str]:
    """Resolve \\xNN and \\NNN escapes (printf/echo -e/$'...' obfuscation); None if nothing changed."""
    out = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text)
    out = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), out)
    return out if out != text else None


def _warpgate_target_name(session: dict) -> str:
    target = session.get("target")
    if isinstance(target, dict):
        target = target.get("name")
    if isinstance(target, str):
        return target

    target_sessions = session.get("target_sessions")
    if isinstance(target_sessions, list):
        active_names = []
        for target_session in target_sessions:
            if not isinstance(target_session, dict) or target_session.get("ended"):
                continue
            target_data = target_session.get("target")
            name = target_data.get("name") if isinstance(target_data, dict) else None
            if isinstance(name, str):
                active_names.append(name)
        if len(active_names) == 1:
            return active_names[0]
    return ""


# Full-screen programs switch to the alternate screen; tmux/screen do too and would hide a shell.
_ALT_ON = (b"\x1b[?1049h", b"\x1b[?1047h", b"\x1b[?47h")
_ALT_OFF = (b"\x1b[?1049l", b"\x1b[?1047l", b"\x1b[?47l")
_MULTIPLEXER = re.compile(r"^\s*(?:sudo\s+)?(?:tmux|screen|byobu)\b", re.IGNORECASE)


def find_multiplexer(text: str) -> Optional[str]:
    """Terminal multiplexers run an unmonitored shell inside the alternate screen, so they are blocked."""
    for part in _SEPARATORS.split(text):
        if _MULTIPLEXER.match(part):
            return part.strip()
    return None


def find_danger(text: str, _depth: int = 0) -> Optional[str]:
    """Return the offending fragment if the line, any chained part, or a decoded payload is dangerous."""
    # Whole line first: patterns like `curl ... | sh` span a separator.
    if _PARTIAL_DANGER.search(text) or _rm_recursive_force(text):
        return text.strip()
    for part in _SEPARATORS.split(text):
        part = part.strip()
        if part and (_PARTIAL_DANGER.search(part) or _rm_recursive_force(part)):
            return part
    if _depth == 0:
        expanded = _expand_escapes(text)
        if expanded and find_danger(expanded, 1):
            return f"{text.strip()} (expands to: {expanded.strip()[:80]})"
        for decoded in _decoded_payloads(text):
            if find_danger(decoded, 1):
                return f"{text.strip()} (decodes to: {decoded.strip()[:80]})"
    return None


class CommandBuffer:
    """Tracks the line being typed, one character at a time.

    feed() returns the finished command when Enter is seen. If the partially
    typed line already looks dangerous, `danger` is set so the caller can kill
    the session before Enter. The buffer only sees typed characters, so a line
    touched by history, tab completion or line-editing keys is flagged
    `enter_untrusted` and must be read from the terminal screen instead.
    """
    _EDIT_KEYS = frozenset("\t\x12\x01\x05\x0b\x17\x19\x14")

    def __init__(self) -> None:
        self._buf: str = ""
        self._in_escape = False
        self._untrusted = False
        self.enter_untrusted = False
        self.danger: Optional[str] = None

    def feed(self, data: bytes) -> Optional[str]:
        self.danger = None
        self.enter_untrusted = False
        for ch in data.decode("utf-8", errors="ignore"):
            if self._in_escape:
                if ch.isalpha() or ch == "~":
                    self._in_escape = False
                continue
            if ch == "\x1b":
                self._in_escape = True
                self._untrusted = True
                continue
            if ch in self._EDIT_KEYS:
                self._untrusted = True
                continue
            if ch in ("\x7f", "\x08"):
                self._buf = self._buf[:-1]
                continue
            if ch in ("\x03", "\x15"):  # Ctrl-C / Ctrl-U clear the line
                self._buf = ""
                self._untrusted = False
                continue
            if ch in ("\r", "\n"):
                cmd, self._buf = self._buf.strip(), ""
                self.enter_untrusted, self._untrusted = self._untrusted, False
                return cmd
            self._buf += ch
            fragment = find_danger(self._buf)
            if fragment:
                self.danger = fragment
                return None
        return None

    def reset(self) -> None:
        self._buf = ""
        self._in_escape = False
        self._untrusted = False
        self.enter_untrusted = False
        self.danger = None

# ─── AI / Policy check ──────────────────────────────────────────────────────

def ask_ai_agent(command: str, session_id: str, username: str = "unknown") -> dict:
    """
    Ask the Nokia NBUC AI agent whether a command is safe.

    Expected response JSON:
      { "verdict": "allow" | "block",
        "risk_score": 0.0..1.0,
        "reason": "..." }

    On network error or timeout we BLOCK (fail-closed).
    """
    try:
        resp = requests.post(
            f"{AI_AGENT_URL}/ssh/analyze",
            json={
                "command": command,
                "session_id": session_id,
                "username": username,
            },
            headers={"Authorization": f"Bearer {AI_AGENT_TOKEN}"},
            timeout=AI_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        result = resp.json()
        if (
            not isinstance(result, dict)
            or result.get("verdict") not in {"allow", "block"}
        ):
            raise ValueError("verdict service returned an invalid response")
        return result
    except requests.exceptions.Timeout:
        log.warning("AI timeout for command %r — failing closed", command)
        return {
            "verdict": "block",
            "risk_score": 1.0,
            "reason": "verdict service timed out",
            "alert_required": True,
        }
    except Exception as exc:
        log.warning("AI error for command %r: %s — failing closed", command, exc)
        return {
            "verdict": "block",
            "risk_score": 1.0,
            "reason": "verdict service unavailable",
            "alert_required": True,
        }

# ─── Warpgate kill ───────────────────────────────────────────────────────────

def send_heuristic_alert(
    command: str,
    reason: str,
    username: str,
    session_id: str = "",
    severity: str = "CRITICAL",
) -> None:
    """Ask the API to email the security team about a locally detected kill."""
    category_patterns = (
        (r"\b(?:rm|dd|mkfs(?:\.[\w-]+)?|shred|truncate|wipefs)\b", "Destructive Command"),
        (r"\b(?:shutdown|reboot|halt|poweroff)\b|\binit\s+0\b", "System Command"),
        (r"\b(?:curl|wget)\b[^\n]*\|\s*(?:bash|sh|python[23]?|perl|ruby)\b", "Remote Code Execution"),
        (r"\b(?:iptables|ufw|firewall|nftables|firewall-cmd)\b", "Network Tampering"),
        (r"/etc/(?:passwd|shadow|sudoers)\b", "Credential Access"),
        (r"\bchmod\s+[0-7]*7[0-7]{2}\b|\bchown\s+root\b|\bsudo\s+-i\b|\bsu\s+-", "Privilege Escalation"),
    )
    category = next(
        (
            label
            for pattern, label in category_patterns
            if re.search(pattern, command, re.IGNORECASE)
        ),
        "Policy Violation",
    )
    try:
        response = requests.post(
            f"{API_BASE_URL}/ssh/alert",
            json={
                "command": command[:512],
                "reason": reason[:500],
                "username": username,
                "session_id": session_id,
                "category": category,
                "severity": severity,
                "blocked": True,
            },
            headers={"X-Alert-Secret": ALERT_SECRET},
            timeout=5,
        )
        response.raise_for_status()
    except Exception as exc:
        log.error("alert request failed (%s)", type(exc).__name__)


class BlockStatusUnavailable(RuntimeError):
    pass


def is_user_blocked(username: str) -> bool:
    """Check the API-backed block list; never treat an unavailable check as unblocked."""
    if not username or username == "unknown":
        raise BlockStatusUnavailable("Warpgate username could not be determined.")
    try:
        response = requests.get(
            f"{API_BASE_URL}/security/check/{requests.utils.quote(username, safe='')}",
            headers={"X-Alert-Secret": ALERT_SECRET},
            timeout=3,
        )
        response.raise_for_status()
        result = response.json()
        if not isinstance(result, dict) or not isinstance(result.get("blocked"), bool):
            raise ValueError("Block status response has an invalid format.")
        if result.get("database_unavailable"):
            raise BlockStatusUnavailable("The security block database is unavailable.")
        return result["blocked"]
    except BlockStatusUnavailable:
        raise
    except Exception as exc:
        log.error("Block status lookup failed for %s (%s)", username, type(exc).__name__)
        raise BlockStatusUnavailable("Unable to verify security block status.") from exc


def block_user(
    username: str,
    reason: str,
    command: str,
    severity: str,
    session_id: str,
) -> bool:
    """Persist a high-severity block through the authenticated API."""
    if not username or username == "unknown":
        log.error("Cannot persist a security block without a Warpgate username")
        return False
    try:
        response = requests.post(
            f"{API_BASE_URL}/security/block",
            headers={"X-Alert-Secret": ALERT_SECRET},
            json={
                "username": username,
                "reason": reason[:1000],
                "command": command[:4096],
                "severity": severity,
                "session_id": session_id,
            },
            timeout=5,
        )
        response.raise_for_status()
        log.warning("Persisted active security block for Warpgate user %s", username)
        return True
    except Exception as exc:
        log.error("Could not persist security block for %s (%s)", username, type(exc).__name__)
        return False


def kill_warpgate_session(session_id: str) -> bool:
    """Request termination and return True only when Warpgate confirms the session ended."""
    if not WARPGATE_TOKEN:
        log.error("Cannot terminate Warpgate session: WARPGATE_TOKEN is not configured")
        return False
    try:
        normalized_id = str(UUID(session_id))
        session_url = f"{WARPGATE_URL}/@warpgate/admin/api/sessions/{normalized_id}"
        headers = {"X-Warpgate-Token": WARPGATE_TOKEN}
        current = requests.get(
            session_url,
            headers=headers,
            timeout=5,
            verify=WARPGATE_CA_BUNDLE,
        )
        if current.status_code != 200:
            log.error("Cannot verify Warpgate session %s before termination (HTTP %d)", normalized_id, current.status_code)
            return False
        current_data = current.json()
        if not isinstance(current_data, dict) or current_data.get("id") != normalized_id:
            log.error("Warpgate returned an invalid session record for %s", normalized_id)
            return False
        if current_data.get("ended") is not None:
            return True

        response = requests.post(
            f"{session_url}/close",
            headers=headers,
            timeout=5,
            verify=WARPGATE_CA_BUNDLE,
        )
        if response.status_code not in (201, 404):
            log.error("Warpgate termination request failed for session %s (HTTP %d)", normalized_id, response.status_code)
            return False
        verified = requests.get(
            session_url,
            headers=headers,
            timeout=5,
            verify=WARPGATE_CA_BUNDLE,
        )
        if verified.status_code != 200:
            log.error("Warpgate termination status is unverified for session %s (HTTP %d)", normalized_id, verified.status_code)
            return False
        verified_data = verified.json()
        confirmed = (
            isinstance(verified_data, dict)
            and verified_data.get("id") == normalized_id
            and verified_data.get("ended") is not None
        )
        if not confirmed:
            log.error("Warpgate did not confirm termination for session %s", normalized_id)
        return confirmed
    except Exception as exc:
        log.error("Warpgate termination failed or could not be verified (%s)", type(exc).__name__)
        return False

# ─── The intercepting forwarder plugin ───────────────────────────────────────

class NokiaInterceptForwarder(SSHForwarder):
    """
    Subclass of SSHForwarder (from ssh-mitm).

    SSHForwarder.forward_stdin() calls handle_client_data(buf) BEFORE
    calling server_channel.sendall(buf).  Returning b"" from here means
    the bytes are DROPPED — never sent to the server — so the command
    is never executed.  This is the synchronous, race-free interception
    point we need.

    For every keypress:
      1. Feed bytes into the command buffer.
      2. If Enter was NOT pressed yet → pass data through unchanged.
      3. If Enter WAS pressed → ask the AI agent for a verdict.
         - "allow" → forward data normally (the Enter reaches the server).
         - "block" → drop the Enter, kill the Warpgate session, send a
           warning message back to the client terminal.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._cmd_buf = CommandBuffer()
        self._proxy_session_id: str = ""
        self._warpgate_session_id: str = ""
        self._session_username: str = ""
        self._killed = False
        self._screen = pyte.Screen(200, 50)
        self._stream = pyte.ByteStream(self._screen)
        self._in_alt = False
        self._ex = ""

    def _get_session_ids(self) -> None:
        """Lazily resolve session identifiers once the session is established."""
        if self._proxy_session_id:
            return
        try:
            addr = self.session.remote.socket_address
            self._proxy_session_id = f"{addr[0]}:{addr[1]}"
        except Exception:
            self._proxy_session_id = "unknown"

        if PROXY_SESSION_MODE == "direct":
            username = getattr(self.session.auth, "username_provided", None)
            if isinstance(username, str) and username.strip():
                self._session_username = username.strip()
                log.info(
                    "Mapped direct SSH proxy session %s to login %s",
                    self._proxy_session_id,
                    self._session_username,
                )
            else:
                log.warning("Direct SSH session %s has no client login name", self._proxy_session_id)
            return

        self._warpgate_session_id = self._find_warpgate_session()

    def _find_warpgate_session(self) -> str:
        """Query Warpgate API to find the active session UUID for our client."""
        try:
            resp = requests.get(
                f"{WARPGATE_URL}/@warpgate/admin/api/sessions",
                headers={"X-Warpgate-Token": WARPGATE_TOKEN},
                params={"active_only": "true", "logged_in_only": "true", "limit": 100},
                timeout=5,
                verify=WARPGATE_CA_BUNDLE,
            )
            if resp.status_code != 200:
                return ""
            data = resp.json()
            items = data.get("items", []) if isinstance(data, dict) else data
            # Warpgate lists newest first; take the newest session that has not ended
            active = [
                item
                for item in items
                if not item.get("ended")
                and str(item.get("protocol", "")).casefold() == "ssh"
                and _warpgate_target_name(item).casefold()
                == WARPGATE_TARGET_NAME.casefold()
            ]
            if len(active) == 1:
                item = active[0]
                sid = item.get("id", "")
                username = item.get("username") or ""
                if not isinstance(sid, str) or not sid or not username:
                    log.warning("Warpgate session is missing its ID or authenticated username")
                    return ""
                self._session_username = username
                log.info("Mapped proxy session %s → Warpgate session %s (user %s)",
                         self._proxy_session_id, sid, self._session_username)
                return sid
            if len(active) > 1:
                log.warning(
                    "Cannot safely map proxy session %s: %d active Warpgate sessions "
                    "match target %s",
                    self._proxy_session_id,
                    len(active),
                    WARPGATE_TARGET_NAME,
                )
        except Exception as exc:
            log.warning("Could not find Warpgate session: %s", exc)
        return ""

    def _send_warning_to_client(self, command: str, reason: str) -> None:
        """Write a red warning message back to the client's terminal."""
        msg = (
            f"\r\n\033[1;31m"
            f"[Nokia Session Kill] '{command}' — Session terminated: {reason}"
            f"\033[0m\r\n"
        ).encode()
        try:
            if self.client_channel is not None:
                self.client_channel.sendall(msg)
        except Exception:
            pass

    def _terminate(
        self,
        command: str,
        reason: str,
        send_alert: bool,
        severity: str = "CRITICAL",
    ) -> None:
        """Tell the user, close the Warpgate session, and tear down both SSH legs."""
        self._killed = True
        self._send_warning_to_client(command, reason)

        username = self._username()
        block_thread = None
        if severity in {"CRITICAL", "HIGH"}:
            if self._session_username:
                block_thread = threading.Thread(
                    target=block_user,
                    args=(
                        self._session_username,
                        reason,
                        command,
                        severity,
                        self._warpgate_session_id,
                    ),
                    daemon=True,
                )
                block_thread.start()
            else:
                log.error("Cannot persist the security block; Warpgate username is unavailable")

        if PROXY_SESSION_MODE == "warpgate" and self._warpgate_session_id:
            threading.Thread(
                target=kill_warpgate_session,
                args=(self._warpgate_session_id,),
                daemon=True,
            ).start()
        elif PROXY_SESSION_MODE == "warpgate":
            log.warning("No Warpgate session ID — cannot kill session")
        else:
            log.info("Closing direct SSH session %s through its proxy transport", self._proxy_session_id)

        if send_alert:
            threading.Thread(
                target=send_heuristic_alert,
                args=(
                    command,
                    reason,
                    username,
                    self._warpgate_session_id,
                    severity,
                ),
                daemon=True,
            ).start()

        time.sleep(0.2)  # let the kill message flush before the transport closes
        for chan in (self.server_channel, self.client_channel):
            try:
                if chan is not None:
                    chan.close()
            except Exception:
                pass
        for chan in (self.server_channel, self.client_channel):
            try:
                if chan is not None:
                    chan.get_transport().close()
            except Exception:
                pass
        if block_thread is not None:
            block_thread.join(timeout=6)

    def _deny_before_forward(self, message: str, reason: str) -> None:
        self._killed = True
        try:
            if self.client_channel is not None:
                self.client_channel.sendall(message.encode("utf-8"))
        except Exception:
            pass
        log.warning("Refusing SSH forwarding for %s: %s", self._username(), reason)
        for channel in (self.client_channel, self.server_channel):
            try:
                if channel is None:
                    continue
                channel.close()
                transport = channel.get_transport()
                if transport is not None:
                    transport.close()
            except Exception:
                pass

    def forward(self) -> None:
        """Reject blocked users before opening the remote shell."""
        self._get_session_ids()
        if PROXY_SESSION_MODE == "warpgate" and not self._session_username:
            self._warpgate_session_id = (
                self._find_warpgate_session() or self._warpgate_session_id
            )
        elif PROXY_SESSION_MODE == "direct" and not self._session_username:
            self._get_session_ids()
        username = self._session_username
        try:
            blocked = is_user_blocked(username)
        except BlockStatusUnavailable as exc:
            self._deny_before_forward(
                "\r\n*** ACCESS DENIED ***\r\n"
                "Security block status could not be verified. Contact the administrator.\r\n",
                str(exc),
            )
            return
        if blocked:
            self._deny_before_forward(
                "\r\n*** ACCESS DENIED ***\r\n"
                "Your account is blocked by a security policy. Contact the security team.\r\n",
                "user has an active security block",
            )
            return
        super().forward()

    def _username(self) -> str:
        # Never substitute the target-system account for the Warpgate identity.
        if PROXY_SESSION_MODE == "warpgate" and not self._session_username:
            self._warpgate_session_id = (
                self._find_warpgate_session() or self._warpgate_session_id
            )
        elif PROXY_SESSION_MODE == "direct" and not self._session_username:
            self._get_session_ids()
        return self._session_username or "unknown"

    def handle_server_data(self, data: bytes) -> bytes:
        try:
            self._stream.feed(data)
        except Exception:
            pass
        # Full-screen apps (vim, less, tmux) switch to the alternate screen buffer.
        on = max(data.rfind(s) for s in _ALT_ON)
        off = max(data.rfind(s) for s in _ALT_OFF)
        if on > off:
            self._in_alt, self._ex = True, ""
            self._cmd_buf.reset()
        elif off > on:
            self._in_alt = False
            self._cmd_buf.reset()
        return data

    def _drain_echo(self) -> None:
        """Read the server's echo into the screen (and on to the client) before judging a line."""
        end = time.monotonic() + 0.3
        last = time.monotonic()
        while time.monotonic() < end:
            if self.server_channel.recv_ready():
                buf = self.handle_server_data(self.server_channel.recv(self.BUF_LEN))
                if self.client_channel is not None:
                    self.client_channel.sendall(buf)
                last = time.monotonic()
            elif time.monotonic() - last > 0.05:
                break
            else:
                time.sleep(0.005)

    def _handle_alt_screen(self, data: bytes) -> bytes:
        """Inside vim/less the typed text is not a shell line; only watch for `:!cmd` shell escapes."""
        for ch in data.decode("utf-8", errors="ignore"):
            if ch == "\x1b":
                self._ex = ""
            elif ch == ":":
                self._ex = ":"
            elif ch in ("\r", "\n"):
                ex, self._ex = self._ex, ""
                frag = self._ex_danger(ex)
                if frag:
                    self._terminate(frag, "dangerous shell escape from editor", send_alert=True)
                    return b""
            elif self._ex:
                self._ex += ch
                frag = self._ex_danger(self._ex)
                if frag:
                    self._terminate(frag, "dangerous shell escape from editor", send_alert=True)
                    return b""
        return data

    @staticmethod
    def _ex_danger(ex: str) -> Optional[str]:
        m = re.match(r":\s*[\w%,.$]*\s*!(.*)", ex)
        return find_danger(m.group(1)) if m else None

    def _screen_command(self) -> str:
        """Text on the cursor line after the prompt, as the server has echoed it."""
        try:
            line = self._screen.display[self._screen.cursor.y].rstrip()
        except Exception:
            return ""
        return re.sub(r"^.*?[$#>%]\s", "", line, count=1).strip()

    # ── The hook ────────────────────────────────────────────────────────────────────────────
    def handle_client_data(self, data: bytes) -> bytes:
        """
        Called by SSHForwarder.forward_stdin() for every chunk of bytes the
        client sends.  Returns the data to forward, or b"" to drop it.
        """
        if self._killed:
            return b""

        self._get_session_ids()

        if self._in_alt:
            return self._handle_alt_screen(data)

        # Judge each line separately so a pasted "ls\nrm -rf /\n" is not hidden by its first line.
        for seg in re.split(rb"(?<=[\r\n])", data):
            if seg and not self._process_segment(seg):
                break
        # Allowed bytes were already forwarded by _process_segment
        return b""

    def _process_segment(self, seg: bytes) -> bool:
        """Check one chunk (ends at Enter at most). Forwards it if allowed; returns False if the session was killed."""
        cmd = self._cmd_buf.feed(seg)

        # Dangerous pattern seen while typing — kill before Enter
        if self._cmd_buf.danger:
            danger = self._cmd_buf.danger
            log.warning("[%s] dangerous pattern while typing: %r", self._proxy_session_id, danger)
            self._terminate(danger, "dangerous pattern detected while typing", send_alert=True)
            return False

        # No Enter yet — pass keystrokes through immediately
        if cmd is None:
            self.server_channel.sendall(seg)
            return True

        enter = seg[-1:]
        if self._cmd_buf.enter_untrusted:
            # History/tab/line-editing was used: let the server echo the line, then read it from the screen.
            # Enter is held back until the verdict, so the recalled text cannot run.
            if len(seg) > 1:
                self.server_channel.sendall(seg[:-1])
            self._drain_echo()
            cmd = self._screen_command() or cmd
        else:
            enter = seg

        if not cmd:
            self.server_channel.sendall(enter)
            return True

        log.info("[%s] command typed: %r", self._proxy_session_id, cmd)

        # Instant local check of the finished line (chains, split flags, encoded payloads)
        fragment = find_danger(cmd) or find_multiplexer(cmd)
        if fragment:
            self._terminate(fragment, "dangerous command detected", send_alert=True)
            return False

        # Ask AI
        username = self._username()
        verdict_data = ask_ai_agent(
            cmd,
            self._warpgate_session_id or self._proxy_session_id,
            username,
        )
        verdict     = verdict_data.get("verdict", "block")
        risk_score  = verdict_data.get("risk_score", 0.0)
        reason      = verdict_data.get("reason", "")

        log.info(
            "[%s] verdict=%s risk=%.2f reason=%s",
            self._proxy_session_id, verdict, risk_score, reason,
        )

        if verdict == "block":
            # The API already emails on block, so no separate alert here
            try:
                risk_score = float(risk_score)
            except (TypeError, ValueError):
                risk_score = 1.0
            severity = (
                "CRITICAL" if risk_score >= 0.9 else "HIGH" if risk_score >= 0.7 else "MEDIUM"
            )
            self._terminate(
                cmd,
                reason,
                send_alert=bool(verdict_data.get("alert_required")),
                severity=severity,
            )
            return False

        # Safe command — forward normally
        self.server_channel.sendall(enter)
        return True

# ─── Entry point ─────────────────────────────────────────────────────────────

def main() -> None:
    log.info(
        "Nokia NBUC SSH Proxy starting on 0.0.0.0:%d → %s:%d",
        PROXY_LISTEN_PORT, PROXY_TARGET_HOST, PROXY_TARGET_PORT,
    )

    # ssh-mitm modules read their options from sys.argv; default remote is 127.0.0.1:22.
    sys.argv = [
        sys.argv[0],
        "--remote-host", PROXY_TARGET_HOST,
        "--remote-port", str(PROXY_TARGET_PORT),
    ]

    server = SSHProxyServer(
        listen_address="0.0.0.0",
        listen_port=PROXY_LISTEN_PORT,
        ssh_interface=NokiaInterceptForwarder,
    )
    server.start()

if __name__ == "__main__":
    main()
