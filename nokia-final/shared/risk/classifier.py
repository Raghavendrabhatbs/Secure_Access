from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class RiskFinding:
    category: str
    severity: str
    rule: str


def classify_command_risks(command: str) -> list[RiskFinding]:
    normalized_command = _normalize_command(command)
    if not normalized_command:
        return []

    findings: list[RiskFinding] = []

    if _is_sudo_command(normalized_command):
        findings.append(
            RiskFinding(
                category="PRIVILEGE_ESCALATION",
                severity="HIGH",
                rule="SUDO",
            )
        )

    if _matches_chmod_777(normalized_command):
        findings.append(
            RiskFinding(
                category="PERMISSION_MODIFICATION",
                severity="HIGH",
                rule="CHMOD_777",
            )
        )

    if _matches_passwd_command(normalized_command):
        findings.append(
            RiskFinding(
                category="CREDENTIAL_OPERATION",
                severity="MEDIUM",
                rule="PASSWD",
            )
        )

    if _matches_useradd_command(normalized_command):
        findings.append(
            RiskFinding(
                category="ACCOUNT_MODIFICATION",
                severity="MEDIUM",
                rule="USERADD",
            )
        )

    if _references_shadow_file(normalized_command):
        findings.append(
            RiskFinding(
                category="CREDENTIAL_FILE_ACCESS",
                severity="HIGH",
                rule="ETC_SHADOW",
            )
        )

    if _matches_rm_rf(normalized_command):
        findings.append(
            RiskFinding(
                category="DESTRUCTIVE_OPERATION",
                severity="HIGH",
                rule="RM_RF",
            )
        )

    if _matches_history_clear(normalized_command):
        findings.append(
            RiskFinding(
                category="ANTI_FORENSICS",
                severity="HIGH",
                rule="HISTORY_CLEAR",
            )
        )

    if _references_passwd_file(normalized_command):
        findings.append(
            RiskFinding(
                category="CREDENTIAL_FILE_ACCESS",
                severity="HIGH",
                rule="ETC_PASSWD",
            )
        )

    if _matches_network_transfer_command(normalized_command):
        findings.append(
            RiskFinding(
                category="NETWORK_TRANSFER",
                severity="MEDIUM",
                rule="NETWORK_TRANSFER",
            )
        )

    return findings


def _normalize_command(command: str) -> str:
    return (command or "").strip().lower()


def _tokenize(command: str) -> list[str]:
    return re.findall(r'"[^"]*"|\'[^\']*\'|\S+', command)


def _unquote(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"}:
        return token[1:-1]
    return token


def _command_tokens(command: str) -> list[str]:
    return [_unquote(token) for token in _tokenize(command)]


def _is_sudo_command(command: str) -> bool:
    tokens = _command_tokens(command)
    return bool(tokens) and tokens[0] == "sudo"


def _matches_chmod_777(command: str) -> bool:
    tokens = _command_tokens(command)
    if not tokens:
        return False

    if tokens[0] == "sudo":
        tokens = tokens[1:]

    if len(tokens) < 3 or tokens[0] != "chmod":
        return False

    return "777" in tokens[1:]


def _matches_passwd_command(command: str) -> bool:
    tokens = _command_tokens(command)
    if not tokens:
        return False

    if tokens[0] == "sudo":
        tokens = tokens[1:]

    return bool(tokens) and tokens[0] == "passwd"


def _matches_useradd_command(command: str) -> bool:
    tokens = _command_tokens(command)
    if not tokens:
        return False

    if tokens[0] == "sudo":
        tokens = tokens[1:]

    return bool(tokens) and tokens[0] in {"useradd", "adduser"}


def _references_shadow_file(command: str) -> bool:
    tokens = _command_tokens(command)
    return any(token == "/etc/shadow" for token in tokens)


def _matches_rm_rf(command: str) -> bool:
    tokens = _command_tokens(command)
    if not tokens:
        return False

    if tokens[0] == "sudo":
        tokens = tokens[1:]

    if len(tokens) < 3 or tokens[0] != "rm":
        return False

    flags = tokens[1:-1]
    return any(flag in {"-rf", "-fr"} for flag in flags)


def _matches_history_clear(command: str) -> bool:
    return "history -c" in command


def _references_passwd_file(command: str) -> bool:
    tokens = _command_tokens(command)
    return any(token == "/etc/passwd" for token in tokens)


def _matches_network_transfer_command(command: str) -> bool:
    tokens = _command_tokens(command)
    if not tokens:
        return False
    if tokens[0] == "sudo":
        tokens = tokens[1:]
    if not tokens:
        return False
    return tokens[0] in {"wget", "curl", "scp", "rsync"}
