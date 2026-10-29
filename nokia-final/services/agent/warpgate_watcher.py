"""
warpgate_watcher.py — Pre-Execution Session Kill Watchdog
Nokia SSH Session Intelligence Platform
"""

import os, time, json, re, logging, threading, base64
import requests
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, Optional, Set
from uuid import UUID

try:
    from .email_alerter import send_alert
except ImportError:
    from email_alerter import send_alert

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parents[2] / ".env")
except ImportError:
    pass  # python-dotenv not installed; rely on shell environment

WARPGATE_URL      = os.getenv("WARPGATE_URL", "https://localhost:8888")
WARPGATE_TOKEN    = os.getenv("WARPGATE_TOKEN", "")
WARPGATE_CA_BUNDLE = os.getenv("WARPGATE_CA_BUNDLE") or True
RECORDINGS_PATH   = os.getenv("WARPGATE_RECORDINGS_PATH", "/data/recordings")
POLL_INTERVAL_MS  = int(os.getenv("POLL_INTERVAL_MS", "500"))

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
log = logging.getLogger("PreExecKill")

DANGER_PATTERNS: Dict[str, re.Pattern] = {
    "rm_rf_root":         re.compile(r"rm\s+-[rf]{1,2}\s+/\s*$"),
    "rm_rf_root_slash":   re.compile(r"rm\s+-[rf]{1,2}\s+/"),
    "rm_rf_star":         re.compile(r"rm\s+-[rf]{1,2}\s+\*"),
    "rm_rf_home":         re.compile(r"rm\s+-[rf]{1,2}\s+~/"),
    "dd_urandom_disk":    re.compile(r"dd\s+if=/dev/(urandom|zero)\s+of=/dev/[sh]d[a-z]"),
    "dd_dev_disk":        re.compile(r"dd\s+.*of=/dev/(sda|sdb|sdc|nvme)"),
    "mkfs_disk":          re.compile(r"mkfs\s+/dev/"),
    "shred_disk":         re.compile(r"shred\s+/dev/"),
    "fork_bomb":          re.compile(r":\s*\(\s*\)\s*\{"),
    "cat_shadow":         re.compile(r"cat\s+/etc/shadow"),
    "cat_passwd":         re.compile(r"cat\s+/etc/passwd"),
    "cat_sudoers":        re.compile(r"cat\s+/etc/sudoers"),
    "chmod_777_etc":      re.compile(r"chmod\s+777\s+/etc/"),
    "chmod_777_passwd":   re.compile(r"chmod\s+777\s+/etc/(passwd|shadow|sudoers)"),
    "sudo_minus_i":       re.compile(r"sudo\s+-i\b"),
    "sudo_su":            re.compile(r"sudo\s+su\b"),
    "history_clear":      re.compile(r"history\s+-c"),
    "unset_histfile":     re.compile(r"unset\s+HISTFILE"),
    "bash_dev_tcp":       re.compile(r"bash\s+-i\s+>&\s*/dev/tcp/"),
    "nc_reverse_shell":   re.compile(r"nc\s+-[enl]*e\s+/bin/(ba)?sh"),
    "crontab_write":      re.compile(r"crontab\s+-[le]"),
    "etc_cron":           re.compile(r"echo\s+.*>>\s*/etc/cron"),
    "scp_etc":            re.compile(r"scp\s+/etc/"),
    "curl_pipe_bash":     re.compile(r"curl\s+.*\|\s*(bash|sh)\b"),
    "wget_pipe_bash":     re.compile(r"wget\s+.*-O\s+-\s+\|\s*(bash|sh)\b"),
}

SEVERITY_MAP = {
    "rm_rf_root": "CRITICAL", "rm_rf_root_slash": "CRITICAL",
    "rm_rf_star": "CRITICAL", "rm_rf_home": "HIGH",
    "dd_urandom_disk": "CRITICAL", "dd_dev_disk": "CRITICAL",
    "mkfs_disk": "CRITICAL", "shred_disk": "CRITICAL",
    "fork_bomb": "CRITICAL", "cat_shadow": "HIGH",
    "cat_passwd": "HIGH", "cat_sudoers": "HIGH",
    "chmod_777_etc": "HIGH", "chmod_777_passwd": "CRITICAL",
    "sudo_minus_i": "HIGH", "sudo_su": "HIGH",
    "history_clear": "MEDIUM", "unset_histfile": "MEDIUM",
    "bash_dev_tcp": "CRITICAL", "nc_reverse_shell": "CRITICAL",
    "crontab_write": "MEDIUM", "etc_cron": "HIGH",
    "scp_etc": "HIGH", "curl_pipe_bash": "CRITICAL",
    "wget_pipe_bash": "HIGH",
}

MITRE_MAP = {
    "rm_rf_root": ("T1485","Data Destruction"),
    "rm_rf_root_slash": ("T1485","Data Destruction"),
    "rm_rf_star": ("T1485","Data Destruction"),
    "rm_rf_home": ("T1485","Data Destruction"),
    "dd_urandom_disk": ("T1561","Disk Wipe"),
    "dd_dev_disk": ("T1561","Disk Wipe"),
    "mkfs_disk": ("T1561","Disk Wipe"),
    "shred_disk": ("T1561","Disk Wipe"),
    "fork_bomb": ("T1499","Endpoint DoS"),
    "cat_shadow": ("T1003","Credential Dumping"),
    "cat_passwd": ("T1003","Credential Dumping"),
    "cat_sudoers": ("T1003","Credential Dumping"),
    "chmod_777_etc": ("T1222","File Permissions Modification"),
    "chmod_777_passwd": ("T1222","File Permissions Modification"),
    "sudo_minus_i": ("T1548","Privilege Escalation"),
    "sudo_su": ("T1548","Privilege Escalation"),
    "history_clear": ("T1070","Indicator Removal"),
    "unset_histfile": ("T1070","Indicator Removal"),
    "bash_dev_tcp": ("T1059","Command Interpreter"),
    "nc_reverse_shell": ("T1059","Command Interpreter"),
    "crontab_write": ("T1053","Scheduled Task"),
    "etc_cron": ("T1053","Scheduled Task"),
    "scp_etc": ("T1041","Exfiltration"),
    "curl_pipe_bash": ("T1059","Command Interpreter"),
    "wget_pipe_bash": ("T1059","Command Interpreter"),
}

@dataclass
class SessionState:
    session_id: str
    username: str = "unknown"
    command_buffer: str = ""
    last_offset: int = 0
    killed: bool = False
    kill_reason: Optional[str] = None

@dataclass
class ThreatMatch:
    pattern_name: str
    severity: str
    mitre_id: str
    mitre_name: str
    partial_command: str
    matched_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

def kill_session(session_id: str) -> bool:
    if not WARPGATE_TOKEN:
        log.error("WARPGATE_TOKEN not set")
        return False
    try:
        normalized_id = str(UUID(session_id))
        endpoint = f"{WARPGATE_URL}/@warpgate/admin/api/sessions/{normalized_id}"
        headers = {"X-Warpgate-Token": WARPGATE_TOKEN}
        current = requests.get(endpoint, headers=headers, timeout=5, verify=WARPGATE_CA_BUNDLE)
        if current.status_code != 200:
            log.error("Unable to verify Warpgate session before termination (HTTP %s)", current.status_code)
            return False
        current_data = current.json()
        if not isinstance(current_data, dict) or current_data.get("id") != normalized_id:
            log.error("Warpgate returned an invalid session record for %s", normalized_id)
            return False
        if current_data.get("ended") is not None:
            log.warning("Warpgate session %s is not confirmed active; not terminating it", normalized_id)
            return False

        response = requests.post(
            f"{endpoint}/close",
            headers=headers,
            timeout=5,
            verify=WARPGATE_CA_BUNDLE,
        )
        if response.status_code not in (201, 404):
            log.error("Warpgate termination request failed (HTTP %s)", response.status_code)
            return False

        verified = requests.get(endpoint, headers=headers, timeout=5, verify=WARPGATE_CA_BUNDLE)
        if verified.status_code != 200:
            log.error("Warpgate termination status could not be verified (HTTP %s)", verified.status_code)
            return False
        verified_data = verified.json()
        confirmed = (
            verified_data.get("id") == normalized_id
            and verified_data.get("ended") is not None
        )
        if confirmed:
            log.info("Warpgate confirmed termination for session %s", normalized_id)
            return True
        log.error("Warpgate did not confirm termination for session %s", normalized_id)
        return False
    except (requests.RequestException, ValueError, TypeError, AttributeError) as exc:
        log.error("Warpgate session termination failed or could not be verified (%s)", type(exc).__name__)
        return False

def send_kill_email(
    state: SessionState,
    threat: ThreatMatch,
    termination_confirmed: bool,
) -> None:
    sent = send_alert(
        command=threat.partial_command,
        severity=threat.severity,
        username=state.username,
        session_id=state.session_id,
        category=threat.pattern_name,
        reason=f"{threat.mitre_id} - {threat.mitre_name}",
        recommended_action=(
            "The Warpgate API confirmed that the session ended."
            if termination_confirmed
            else "Warpgate termination could not be confirmed; verify the session immediately."
        ),
        termination_requested=True,
        termination_confirmed=termination_confirmed,
    )
    if not sent:
        log.error("Security email delivery failed for session %s", state.session_id)

def decode_keystroke(raw: str) -> str:
    try:
        return base64.b64decode(raw).decode("utf-8", errors="replace")
    except Exception:
        return raw

def _is_b64(s: str) -> bool:
    return bool(s and re.match(r'^[A-Za-z0-9+/]+=*$', s) and len(s) <= 256)

def parse_keystroke_line(line: str) -> Optional[str]:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if isinstance(obj, list) and len(obj) == 3:
        _, stream, data = obj
        if str(stream).lower() in ("i", "input"):
            return decode_keystroke(data) if _is_b64(data) else data
        return None
    if isinstance(obj, dict) and "stream" in obj:
        if obj["stream"].lower() in ("input", "i", "stdin"):
            data = obj.get("data", "")
            return decode_keystroke(data) if _is_b64(data) else data
        return None
    if isinstance(obj, dict) and "k" in obj:
        return obj["k"]
    return None

def update_buffer(buf: str, ch: str) -> str:
    if ch in ("\x7f", "\x08"): return buf[:-1]
    if ch == "\x03": return ""
    if ch in ("\r", "\n"): return ""
    return buf + ch

def check_patterns(buffer: str) -> Optional[ThreatMatch]:
    buf = buffer.strip()
    if len(buf) < 4:
        return None
    for name, pattern in DANGER_PATTERNS.items():
        if pattern.search(buf):
            sev = SEVERITY_MAP.get(name, "HIGH")
            mid, mname = MITRE_MAP.get(name, ("T0000", "Unknown"))
            return ThreatMatch(name, sev, mid, mname, buf)
    return None

class SessionWatcher:
    def __init__(self, filepath: Path, session_id: str, username: str = "unknown"):
        self.filepath = filepath
        self.state = SessionState(session_id=session_id, username=username)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self): self._thread.start()
    def stop(self): self._stop.set()

    def _run(self):
        while not self._stop.is_set():
            try: self._tick()
            except Exception as e: log.error(f"Tick error: {e}")
            time.sleep(POLL_INTERVAL_MS / 1000.0)

    def _tick(self):
        if not self.filepath.exists() or self.state.killed:
            return
        with open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
            f.seek(self.state.last_offset)
            lines = f.readlines()
            self.state.last_offset = f.tell()
        for line in lines:
            ch = parse_keystroke_line(line)
            if ch is None: continue
            for c in ch:
                self.state.command_buffer = update_buffer(self.state.command_buffer, c)
            threat = check_patterns(self.state.command_buffer)
            if threat and threat.severity in ("CRITICAL", "HIGH"):
                self._kill(threat)
                return

    def _kill(self, threat: ThreatMatch):
        log.warning(f"\n{'='*60}\n🚨 PRE-EXECUTION KILL\n   Session : {self.state.session_id}\n   User    : {self.state.username}\n   Command : {threat.partial_command}\n   Pattern : {threat.pattern_name}\n   Severity: {threat.severity}\n   MITRE   : {threat.mitre_id} — {threat.mitre_name}\n{'='*60}")
        killed = kill_session(self.state.session_id)
        threading.Thread(
            target=send_kill_email,
            args=(self.state, threat, killed),
            daemon=True,
        ).start()
        self.state.killed = True
        self.state.kill_reason = threat.pattern_name
        if not killed:
            log.error(f"❌ Kill API failed — session may still be active")

class WarpgateWatchdog:
    def __init__(self):
        self.recordings_dir = Path(RECORDINGS_PATH)
        self.watchers: Dict[str, SessionWatcher] = {}
        self._seen: Set[str] = set()

    def run(self):
        log.info(f"🛡 WarpgateWatchdog started | path={self.recordings_dir} | poll={POLL_INTERVAL_MS}ms | patterns={len(DANGER_PATTERNS)}")
        if not self.recordings_dir.exists():
            log.error(f"Recordings dir not found: {self.recordings_dir}")
            return
        while True:
            try: self._scan()
            except Exception as e: log.error(f"Scan error: {e}")
            time.sleep(POLL_INTERVAL_MS / 1000.0)

    def _scan(self):
        for fpath in self.recordings_dir.rglob("*.ndjson"):
            key = str(fpath)
            if key in self._seen: continue
            self._seen.add(key)
            session_id = fpath.parent.parent.name
            w = SessionWatcher(fpath, session_id)
            self.watchers[session_id] = w
            w.start()
            log.info(f"📂 New session: {session_id}")
        for sid in [s for s, w in self.watchers.items() if w.state.killed]:
            self.watchers[sid].stop()
            del self.watchers[sid]

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        tests = [
            ("rm -rf /",                          True),
            ("rm -rf /etc/",                      True),
            ("ls -la",                            False),
            ("cat /etc/shadow",                   True),
            ("dd if=/dev/urandom of=/dev/sda",    True),
            (":(){:|:& };:",                      True),
            ("echo hello",                        False),
            ("chmod 777 /etc/passwd",             True),
        ]
        passed = 0
        for cmd, expect in tests:
            result = check_patterns(cmd)
            ok = (result is not None) == expect
            print(f"  {'✅ PASS' if ok else '❌ FAIL'}  '{cmd}'  →  {result.pattern_name if result else 'none'}")
            if ok: passed += 1
        print(f"\n{passed}/{len(tests)} tests passed")
        sys.exit(0 if passed == len(tests) else 1)
    WarpgateWatchdog().run()
