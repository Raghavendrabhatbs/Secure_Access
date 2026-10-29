from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from app.services.query_understanding_service import is_current_datetime_question

TRAILING_FILLER_RE = re.compile(
    r"\s+(?:please|indetail|in\s+detail|in-detail|briefly|shortly|"
    r"explain(?:\s+me)?(?:\s+in\s+detail)?|"
    r"tell\s+me|describe(?:\s+it)?|meaning|mean|means|does|do|work|works|"
    r"actually|really)\b.*$",
    re.IGNORECASE,
)
LEADING_FILLER_RE = re.compile(
    r"^(?:please\s+)?(?:briefly\s+|shortly\s+|in\s+brief\s+)?"
    r"(?:explain(?:\s+me)?(?:\s+the)?|"
    r"what\s+(?:is|does)|"
    r"tell\s+me\s+about|"
    r"give\s+me\s+(?:a\s+)?(?:brief|short|quick)?\s*(?:on|about)|"
    r"brief\s+(?:me\s+)?on|"
    r"describe|"
    r"how\s+(?:does|do\s+you\s+use|to\s+use)|"
    r"meaning\s+of|"
    r"purpose\s+of|"
    r"what\s+is\s+the\s+purpose\s+of)\s+"
    r"(?:the\s+)?(?:command\s+)?",
    re.IGNORECASE,
)
COMMAND_DOES_RE = re.compile(
    r"\b(?:the\s+)?command\s+(.+?)\s+does\b",
    re.IGNORECASE,
)
THE_COMMAND_SUFFIX_RE = re.compile(
    r"^(.+?)\s+command$",
    re.IGNORECASE,
)
KNOWLEDGE_STOP_WORDS = {
    "the", "a", "an", "this", "that", "it", "me", "linux", "command", "commands",
    "work", "used", "use", "does", "do", "what", "is", "explain", "indetail",
    "detail", "please", "about", "tell", "how", "meaning", "briefly", "shortly",
    "brief", "give", "on", "purpose", "quick", "short",
}
SHELL_ARG_RE = re.compile(r"^[-+/~.]|^[A-Za-z0-9._@:=/-]+$")
UNKNOWN_COMMAND_TOKEN_RE = re.compile(r"^[a-z][a-z0-9._-]*$")
WRAPPER_COMMANDS = {"sudo", "env", "nice", "nohup", "time", "stdbuf", "doas", "runuser"}

COMPOUND_EXPLANATIONS = {
    "sudo -n true": (
        "`sudo -n true` checks whether the current user can run commands as root "
        "without being prompted for a password.\n\n"
        "- `sudo` runs a command with elevated (root) privileges.\n"
        "- `-n` (non-interactive) makes sudo fail immediately instead of asking for a password.\n"
        "- `true` is a command that always succeeds and does nothing.\n\n"
        "If it succeeds, this session already has cached sudo rights or passwordless sudo. "
        "That is why it is treated as a privilege-escalation check."
    ),
    "sudo -n": (
        "`sudo -n` runs sudo in non-interactive mode: if a password would be required, "
        "sudo fails immediately instead of prompting."
    ),
    "chmod 777": (
        "`chmod 777` sets read, write, and execute permissions for owner, group, and everyone else. "
        "On sensitive files this is high-risk because any user can modify or replace them."
    ),
    "chmod 600": (
        "`chmod 600` gives read/write only to the file owner and no permissions to anyone else. "
        "This is a common secure setting for private keys and secrets."
    ),
    "chmod +x": (
        "`chmod +x` adds the execute permission to a file so it can be run as a program or script."
    ),
    "chmod -x": (
        "`chmod -x` removes the execute permission from a file."
    ),
    "history -c": (
        "`history -c` clears the current shell command history. "
        "It is often treated as an anti-forensics action because it hides what was run."
    ),
    "sudo su -": (
        "`sudo su -` uses sudo to start a login shell as root. "
        "That is a full privilege-escalation to the root account."
    ),
    "sudo su": (
        "`sudo su` uses sudo to switch to the root shell (without `-`, environment variables of the original user may be preserved)."
    ),
    "rm -rf": (
        "`rm -rf` recursively (`-r`) and force-fully (`-f`) deletes files and directories without prompting. "
        "It is highly destructive — a stray path such as `/` can wipe the system."
    ),
    "rm -rf /": (
        "`rm -rf /` recursively force-deletes starting at the root filesystem. "
        "This is the classic destructive command — it attempts to erase the entire system."
    ),
    "ls -la": (
        "`ls -la` lists **all** files (including hidden dotfiles) in **long** format, "
        "showing permissions, owner, size, and modification time."
    ),
    "ls -l": "`ls -l` lists files in long format with permissions, owner, size, and modification time.",
    "ls -a": "`ls -a` lists all files including hidden dotfiles.",
    "ls -lh": "`ls -lh` lists files in long format with human-readable sizes (K, M, G).",
    "ps aux": (
        "`ps aux` shows a snapshot of **all** running processes on the system (`a` = every user, `u` = detailed user-oriented format, `x` = include processes not attached to a terminal). "
        "Columns include USER, PID, %CPU, %MEM, VSZ, RSS, TTY, STAT, START, TIME, and COMMAND."
    ),
    "ps -ef": (
        "`ps -ef` shows every process on the system in a full listing that includes the parent PID (PPID)."
    ),
    "grep -r": "`grep -r` searches recursively through a directory tree for a pattern.",
    "grep -i": "`grep -i` searches case-insensitively.",
    "grep -v": "`grep -v` inverts the match — prints lines that do NOT match.",
    "grep -n": "`grep -n` prefixes each match with its line number.",
    "grep -rn": "`grep -rn` searches recursively and prints line numbers for each match.",
    "mkdir -p": "`mkdir -p` creates a directory and any missing parent directories, without error if it exists.",
    "cp -r": "`cp -r` copies directories recursively.",
    "cp -a": "`cp -a` copies while preserving all attributes (permissions, timestamps, links).",
    "kill -9": "`kill -9` sends SIGKILL to a process — an unblockable, immediate termination.",
    "kill -15": "`kill -15` sends SIGTERM, asking the process to terminate gracefully.",
    "tar -xvf": "`tar -xvf archive` extracts (`-x`) the archive, prints filenames (`-v`), from file (`-f`).",
    "tar -czvf": "`tar -czvf archive.tar.gz files` creates (`-c`) a gzip-compressed (`-z`), verbose (`-v`) archive to file (`-f`).",
    "tar -xzvf": "`tar -xzvf archive.tar.gz` extracts (`-x`) a gzip (`-z`) archive verbosely (`-v`) from file (`-f`).",
    "uname -a": "`uname -a` prints all system info in one line: kernel name, hostname, kernel release, kernel version, machine, processor, hardware platform, and OS.",
    "ip a": "`ip a` (short for `ip addr show`) lists all network interfaces with their IP addresses and states.",
    "ip r": "`ip r` (short for `ip route show`) displays the kernel routing table.",
    "ss -tulpen": "`ss -tulpen` lists listening TCP (`-t`) and UDP (`-u`) sockets with process owners (`-p`), extended info (`-e`), numeric ports (`-n`), and listening state (`-l`).",
    "dd if=/dev/zero of=/dev/sda": (
        "`dd if=/dev/zero of=/dev/sda` writes zeros to the raw disk `/dev/sda`, wiping every partition on it. "
        "This is destructive and irreversible."
    ),
}

FLAG_HINTS = {
    "ls": {
        "l": "long listing (permissions, owner, size, mtime)",
        "a": "include hidden entries starting with `.`",
        "A": "like -a but exclude `.` and `..`",
        "h": "human-readable sizes",
        "R": "recursive",
        "t": "sort by modification time",
        "S": "sort by size",
        "r": "reverse sort order",
        "F": "append classifier characters (`/`, `*`, `@`, `|`)",
    },
    "rm": {
        "r": "recursive (into directories)",
        "R": "recursive",
        "f": "force, ignore missing files",
        "i": "interactive: ask before each removal",
        "v": "verbose",
    },
    "cp": {
        "r": "recursive",
        "R": "recursive",
        "a": "archive (preserve links, timestamps, permissions)",
        "p": "preserve permissions and timestamps",
        "u": "only copy when the source is newer",
        "v": "verbose",
        "f": "force overwrite",
    },
    "mv": {
        "i": "interactive: prompt before overwrite",
        "f": "force overwrite",
        "n": "never overwrite",
        "v": "verbose",
    },
    "grep": {
        "r": "recursive search",
        "R": "recursive search following symlinks",
        "i": "case-insensitive match",
        "n": "show line numbers",
        "v": "invert: print non-matching lines",
        "l": "list only filenames with matches",
        "c": "print count of matches per file",
        "E": "extended regular expressions",
        "w": "match whole words",
        "H": "always print filename with matches",
        "o": "print only the matching part",
    },
    "ps": {
        "a": "show processes for all users",
        "u": "user-oriented format (USER, %CPU, %MEM columns)",
        "x": "include processes without a controlling terminal",
        "e": "show every process",
        "f": "full-format listing (adds PPID etc.)",
        "l": "long format",
    },
    "chmod": {
        "R": "apply recursively",
        "v": "verbose (report every change)",
        "c": "report only when a change is made",
    },
    "tar": {
        "c": "create a new archive",
        "x": "extract from an archive",
        "t": "list archive contents",
        "z": "gzip compression",
        "j": "bzip2 compression",
        "J": "xz compression",
        "v": "verbose",
        "f": "use the following filename as the archive",
    },
    "kill": {
        "9": "SIGKILL (immediate, unblockable termination)",
        "15": "SIGTERM (graceful termination — default)",
        "1": "SIGHUP (reload configuration)",
        "2": "SIGINT (Ctrl-C interrupt)",
    },
    "ssh": {
        "i": "identity file (private key)",
        "p": "remote port",
        "L": "local port forwarding",
        "R": "remote port forwarding",
        "N": "do not execute a remote command",
        "T": "disable pseudo-terminal allocation",
        "v": "verbose (add more v's for more detail)",
    },
    "scp": {
        "r": "recursive (copy directories)",
        "i": "identity file",
        "P": "remote port (uppercase — different from ssh)",
        "p": "preserve modification times and modes",
        "v": "verbose",
    },
    "rsync": {
        "a": "archive mode (preserve everything)",
        "v": "verbose",
        "z": "compress during transfer",
        "n": "dry run (no changes made)",
        "P": "show progress and keep partial files",
        "r": "recursive",
    },
    "wget": {
        "c": "continue a partial download",
        "r": "recursive download",
        "O": "write to a specific output file",
        "q": "quiet",
    },
    "curl": {
        "X": "explicit HTTP method (e.g., -X POST)",
        "o": "write output to a file",
        "O": "save with the remote filename",
        "H": "add a request header",
        "d": "send POST data",
        "L": "follow redirects",
        "s": "silent (no progress meter)",
        "k": "insecure (skip TLS verification)",
        "u": "user:password for authentication",
    },
    "find": {
        "name": "match by filename pattern",
        "type": "filter by file type (f, d, l, ...)",
        "size": "filter by size",
        "mtime": "modified in the last N days",
        "exec": "run a command against each match",
        "delete": "delete matching entries (destructive)",
    },
    "history": {
        "c": "clear the current shell history (anti-forensics)",
        "w": "write current history to the history file",
        "r": "read the history file into memory",
    },
    "systemctl": {
        "start": "start a unit now",
        "stop": "stop a unit now",
        "restart": "stop then start a unit",
        "reload": "ask the service to reload its config",
        "status": "show current status of a unit",
        "enable": "start this unit at boot",
        "disable": "do not start this unit at boot",
        "mask": "prevent a unit from being started at all",
    },
    "docker": {
        "ps": "list running containers",
        "run": "start a new container",
        "exec": "run a command inside a running container",
        "logs": "show a container's logs",
        "build": "build an image from a Dockerfile",
        "pull": "download an image",
        "push": "upload an image",
        "stop": "stop a running container",
        "rm": "delete a container",
        "rmi": "delete an image",
    },
    "kubectl": {
        "get": "list resources (pods, deployments, etc.)",
        "describe": "detailed information about a resource",
        "apply": "apply a manifest",
        "delete": "delete a resource",
        "logs": "print container logs",
        "exec": "execute a command inside a container",
        "port-forward": "forward a local port to a pod",
        "rollout": "manage a deployment rollout",
    },
    "git": {
        "clone": "copy a remote repository locally",
        "pull": "fetch and merge remote changes",
        "push": "publish local commits",
        "commit": "record staged changes",
        "add": "stage changes for the next commit",
        "status": "show the working tree state",
        "log": "show commit history",
        "checkout": "switch branches or restore files",
        "branch": "list, create, or delete branches",
        "merge": "merge branches",
        "rebase": "reapply commits on top of another base",
        "stash": "temporarily shelve local changes",
    },
    "apt": {
        "install": "install packages",
        "remove": "remove packages",
        "purge": "remove packages and their config files",
        "update": "refresh the package index",
        "upgrade": "upgrade installed packages",
        "autoremove": "remove packages installed as dependencies but no longer needed",
    },
    "pip": {
        "install": "install a Python package",
        "uninstall": "remove a Python package",
        "list": "list installed packages",
        "show": "show details about an installed package",
        "freeze": "print packages in a requirements format",
    },
}

ARGUMENT_HINTS = {
    "mkdir": "In this case it creates a directory named `{args}`.",
    "rmdir": "In this case it removes the directory `{args}`.",
    "cd": "In this case it changes directory to `{args}`.",
    "rm": "In this case it removes `{args}`.",
    "chmod": "In this case it changes permissions on `{args}`.",
    "chown": "In this case it changes ownership of `{args}`.",
    "touch": "In this case it creates or updates the file `{args}`.",
    "cat": "In this case it displays the contents of `{args}`.",
    "less": "In this case it opens `{args}` for interactive paging.",
    "more": "In this case it displays `{args}` one screen at a time.",
    "ls": "In this case it lists `{args}`.",
    "echo": "In this case it prints `{args}`.",
    "wget": "In this case it downloads from `{args}`.",
    "curl": "In this case it requests `{args}`.",
    "grep": "In this case it searches for the pattern `{args}`.",
    "find": "In this case it searches under `{args}`.",
    "ping": "In this case it pings `{args}`.",
    "ssh": "In this case it connects to `{args}`.",
    "scp": "In this case it operates on `{args}`.",
    "kill": "In this case it targets PID `{args}`.",
    "which": "In this case it locates the binary `{args}`.",
    "whereis": "In this case it locates `{args}`.",
    "man": "In this case it opens the manual page for `{args}`.",
}


SUDO_FLAG_HINTS = {
    "-n": "non-interactive (do not prompt for a password; fail if one is required)",
    "-i": "start a login shell as the target user (usually root)",
    "-s": "start a shell as the target user",
    "-u": "run the command as a specific user",
    "-l": "list allowed sudo commands for the current user",
    "-k": "invalidate any cached sudo credentials",
    "-v": "refresh the cached sudo credentials",
    "-E": "preserve the invoking user's environment",
}

DETAILED_EXPLANATIONS = {
    "ssh": (
        "SSH (Secure Shell) is both a protocol and a command used to log in to a remote computer securely.\n\n"
        "What it does:\n"
        "- Encrypts the connection so passwords, commands, and data cannot be read in transit.\n"
        "- Authenticates the user (password or SSH key) and the server (host key).\n"
        "- Opens a remote shell. Related tools like `scp` and `sftp` copy files over the same protocol.\n\n"
        "Typical use: `ssh user@hostname`\n\n"
        "Security notes:\n"
        "- Stolen keys or weak passwords can give an attacker full remote access.\n"
        "- In this assistant, SSH also refers to the recorded Warpgate sessions you are analyzing."
    ),
}


@lru_cache(maxsize=1)
def _load_command_knowledge() -> dict[str, str]:
    current = Path(__file__).resolve()
    for parent in current.parents:
        candidate = parent / "shared" / "knowledge" / "commands.json"
        if candidate.exists():
            with candidate.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
            return {str(key).strip().lower(): str(value).strip() for key, value in payload.items()}
    return {}


def _wants_detail(question: str) -> bool:
    question_lower = (question or "").strip().lower()
    return any(
        term in question_lower
        for term in ("in detail", "indetail", "in-detail", "detailed", "explain me")
    )


def _wants_brief(question: str) -> bool:
    question_lower = (question or "").strip().lower()
    return any(term in question_lower for term in ("briefly", "shortly", "in brief", "one line", "one-liner"))


def _normalize_extracted_command(raw: str) -> str:
    cleaned = (raw or "").strip().strip("`'\"")
    cleaned = re.sub(r"^the\s+", "", cleaned, flags=re.IGNORECASE)
    cleaned = TRAILING_FILLER_RE.sub("", cleaned)
    cleaned = re.sub(r"\s+(?:command|do|does)$", "", cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.strip("?.!,;:")
    return " ".join(cleaned.split())


def _looks_like_shell_token(token: str) -> bool:
    if not token or token.lower() in KNOWLEDGE_STOP_WORDS:
        return False
    return bool(SHELL_ARG_RE.match(token)) and token.lower() not in {
        "explain", "detail", "indetail", "please", "about", "tell", "what", "does",
        "briefly", "shortly", "brief", "give", "quick", "short",
    }


def _looks_like_command_name(token: str) -> bool:
    """Best-effort check that a token could be a command name we don't have offline docs for."""
    if not token:
        return False
    if token.lower() in KNOWLEDGE_STOP_WORDS:
        return False
    return bool(UNKNOWN_COMMAND_TOKEN_RE.match(token))


class SSHKnowledgeService:
    """Offline SSH/Linux command encyclopedia."""

    def __init__(self, entries: dict[str, str] | None = None):
        self._entries = entries if entries is not None else _load_command_knowledge()

    def lookup(self, command: str | None) -> str | None:
        normalized = (command or "").strip().lower()
        if not normalized:
            return None
        if normalized.startswith("/"):
            normalized = normalized.rsplit("/", 1)[-1]
        return self._entries.get(normalized)

    def has(self, command: str | None) -> bool:
        return self.lookup(command) is not None

    def extract_command_from_question(self, question: str) -> str | None:
        question_text = (question or "").strip()
        if not question_text:
            return None

        command_does = COMMAND_DOES_RE.search(question_text)
        if command_does:
            candidate = _normalize_extracted_command(command_does.group(1))
            if candidate:
                return candidate

        remainder = LEADING_FILLER_RE.sub("", question_text, count=1)
        remainder = _normalize_extracted_command(remainder)

        # Handle trailing "the X command" pattern: "the netcat command" -> "netcat"
        trailing = THE_COMMAND_SUFFIX_RE.match(remainder)
        if trailing:
            remainder = trailing.group(1).strip()

        tokens = remainder.split()
        if not tokens:
            return None

        known = {name.lower() for name in self._entries}
        start = 0
        while start < len(tokens) and tokens[start].lower() in KNOWLEDGE_STOP_WORDS:
            start += 1
        if start >= len(tokens):
            return None

        first = tokens[start].lower().strip("`'\"?.!,;:")

        # If the first token is a known command, greedily collect argument-like tokens.
        if first in known:
            selected = [first]
            wrapper = first in WRAPPER_COMMANDS
            for token in tokens[start + 1:]:
                cleaned_token = token.strip("`'\"?.!,;:")
                if not cleaned_token:
                    break
                # For a known base, accept short single/two-letter sub-arguments (e.g., `ip a`, `ps ef`)
                # even if they'd be classified as stop-words in isolation.
                is_shell_like = _looks_like_shell_token(cleaned_token)
                short_sub_arg = (
                    len(cleaned_token) <= 2
                    and bool(re.match(r"^[A-Za-z0-9]+$", cleaned_token))
                )
                if not is_shell_like and not short_sub_arg:
                    break
                if cleaned_token.lower() in known and not cleaned_token.startswith(("-", "+")) and not wrapper:
                    break
                selected.append(cleaned_token)
            return " ".join(selected)

        # If the first token is not known but looks like a command name (lowercase, alnum),
        # still return it so the caller can hand it to the LLM or heuristic fallback.
        if _looks_like_command_name(first):
            selected = [first]
            for token in tokens[start + 1:]:
                cleaned_token = token.strip("`'\"?.!,;:")
                if not _looks_like_shell_token(cleaned_token):
                    break
                selected.append(cleaned_token)
            return " ".join(selected)

        # Otherwise, look for any known command anywhere later in the tokens.
        for token in tokens[start:]:
            normalized = token.lower().strip("`'\"?.!,;:")
            if normalized in known:
                return normalized
        return None

    def explain(self, command: str | None, *, detailed: bool = False, brief: bool = False) -> str | None:
        normalized = _normalize_extracted_command(command or "")
        if not normalized:
            return None

        key = normalized.lower()
        if key in COMPOUND_EXPLANATIONS:
            text = COMPOUND_EXPLANATIONS[key]
            return _first_sentence(text) if brief else text

        if detailed and key in DETAILED_EXPLANATIONS:
            return DETAILED_EXPLANATIONS[key]

        exact = self.lookup(key)
        if exact is not None:
            if detailed and key in DETAILED_EXPLANATIONS:
                return DETAILED_EXPLANATIONS[key]
            return _first_sentence(exact) if brief else exact

        parts = key.split()
        if len(parts) == 1:
            if detailed and parts[0] in DETAILED_EXPLANATIONS:
                return DETAILED_EXPLANATIONS[parts[0]]
            entry = self.lookup(parts[0])
            if entry is not None:
                return _first_sentence(entry) if brief else entry
            return None

        base = parts[0]
        args = parts[1:]
        if base == "sudo":
            text = self._explain_sudo(normalized, args)
            return _first_sentence(text) if brief else text

        base_text = self.lookup(base)
        if base_text is None:
            return None

        flags, targets = self._split_flags_and_targets(base, args)
        text = self._compose_flag_argument_explanation(normalized, base, base_text, flags, targets)
        return _first_sentence(text) if brief else text

    def _split_flags_and_targets(self, base: str, args: list[str]) -> tuple[list[str], list[str]]:
        flags: list[str] = []
        targets: list[str] = []
        for token in args:
            if token.startswith(("-", "+")):
                flags.append(token)
            else:
                # Some commands take sub-commands (git clone, systemctl start, docker run) instead of flags.
                sub = FLAG_HINTS.get(base, {})
                if not flags and token.lower() in sub and not targets:
                    flags.append(token)
                else:
                    targets.append(token)
        return flags, targets

    def _compose_flag_argument_explanation(
        self,
        full_command: str,
        base: str,
        base_text: str,
        flags: list[str],
        targets: list[str],
    ) -> str:
        lines = [f"`{full_command}`: {base_text.rstrip('.')}"]

        flag_explanations = [self._describe_flag(base, flag) for flag in flags]
        flag_explanations = [item for item in flag_explanations if item]
        if flag_explanations:
            lines.append("Flag(s): " + "; ".join(flag_explanations) + ".")

        if targets:
            targets_text = " ".join(targets)
            hint_template = ARGUMENT_HINTS.get(base)
            if hint_template:
                lines.append(hint_template.format(args=targets_text))
            else:
                lines.append(f"Target: `{targets_text}`.")

        if not flag_explanations and not targets and flags:
            joined = " ".join(flags)
            lines.append(f"Arguments: `{joined}`.")

        return " ".join(lines)

    def _describe_flag(self, base: str, flag: str) -> str | None:
        table = FLAG_HINTS.get(base, {})
        if not flag:
            return None

        # `--long-form`
        if flag.startswith("--"):
            long_key = flag[2:]
            hint = table.get(long_key)
            if hint:
                return f"`{flag}` = {hint}"
            return f"`{flag}` (option to `{base}`)"

        # Sub-command style (`kubectl get`, `git clone`) — value stored without dash prefix.
        stripped = flag.lstrip("-+")
        if stripped in table and not flag.startswith(("-", "+")):
            return f"`{flag}` = {table[stripped]}"

        # `+x` style
        if flag.startswith("+"):
            return f"`{flag}` = add {flag[1:]} (see `chmod` docs)"

        # Combined short flags like `-la`, `-rf`, `-czvf`.
        bare = flag[1:]
        if not bare:
            return None
        if len(bare) == 1:
            hint = table.get(bare)
            if hint:
                return f"`-{bare}` = {hint}"
            return f"`{flag}` (option to `{base}`)"

        parts: list[str] = []
        for char in bare:
            hint = table.get(char)
            if hint:
                parts.append(f"`-{char}` = {hint}")
            else:
                # Not a recognized single-letter flag; give up on decomposition.
                return f"`{flag}` (option to `{base}`)"
        return " + ".join(parts)

    def _explain_sudo(self, full_command: str, args: list[str]) -> str:
        flags: list[str] = []
        command_parts: list[str] = []
        for token in args:
            if token.startswith("-") and not command_parts:
                flags.append(token)
            else:
                command_parts.append(token)

        lines = [f"`{full_command}` uses sudo to run a command with elevated (root) privileges."]
        if flags:
            flag_bits = []
            for flag in flags:
                meaning = SUDO_FLAG_HINTS.get(flag, "a sudo option")
                flag_bits.append(f"`{flag}` means {meaning}")
            lines.append("Flags: " + "; ".join(flag_bits) + ".")
        if command_parts:
            target = " ".join(command_parts)
            target_text = self.lookup(command_parts[0])
            if target_text:
                lines.append(f"The command being run is `{target}`: {target_text}")
            else:
                lines.append(f"The command being run as root is `{target}`.")
        else:
            sudo_text = self.lookup("sudo")
            if sudo_text:
                lines.append(sudo_text)
        return " ".join(lines)

    def answer_question(self, question: str) -> str | None:
        if is_current_datetime_question(question):
            return None
        command = self.extract_command_from_question(question)
        if command is None:
            return None
        return self.explain(
            command,
            detailed=_wants_detail(question),
            brief=_wants_brief(question),
        )

    def known_commands(self) -> list[str]:
        return sorted(self._entries.keys())


def _first_sentence(text: str) -> str:
    """Return the first sentence of a multi-sentence explanation, keeping code fences intact."""
    if not text:
        return text
    # Do not truncate compound multi-line explanations aggressively.
    first_line = text.split("\n", 1)[0].strip()
    match = re.match(r"^(.+?[.!?])(\s|$)", first_line)
    if match:
        return match.group(1)
    return first_line
