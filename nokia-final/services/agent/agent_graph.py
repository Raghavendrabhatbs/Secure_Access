"""LangGraph orchestration for Nokia SSH threat and anomaly handling."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, TypedDict

from dotenv import load_dotenv
from langgraph.graph import END, START, StateGraph

AGENT_ROOT = os.path.dirname(__file__)
PROJECT_ROOT = os.path.dirname(os.path.dirname(AGENT_ROOT))
API_ROOT = os.path.join(PROJECT_ROOT, "services", "api")
for path in (PROJECT_ROOT, API_ROOT, AGENT_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

from anomaly_detector import load_model, score_live_session
from email_alerter import is_configured, send_alert
from threat_classifier import classify_command, get_recommended_action

load_dotenv()


class AgentState(TypedDict, total=False):
    command: str
    username: str
    session_id: str
    timestamp: str
    hour: int
    day_of_week: int
    duration_seconds: float
    total_commands: int
    sudo_count: int
    has_history_clear: int
    has_dangerous_cmd: int
    commands_per_minute: float
    threat: dict[str, Any]
    anomaly: dict[str, Any]
    decision: dict[str, Any]
    incident_id: int | None
    email_sent: bool
    published: bool
    response: dict[str, Any]


ThreatState = AgentState
anomaly_model = None


def classify_threat(state: AgentState) -> AgentState:
    threat = classify_command(state.get("command", ""))
    state["threat"] = threat
    state["has_dangerous_cmd"] = int(
        str(threat.get("severity", "LOW")).upper() in {"CRITICAL", "HIGH", "MEDIUM"}
    )
    return state


def check_anomaly(state: AgentState) -> AgentState:
    global anomaly_model
    if anomaly_model is None:
        anomaly_model = load_model()
    model = anomaly_model
    timestamp = state.get("timestamp")
    if timestamp:
        try:
            event_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            event_time = datetime.now(timezone.utc)
    else:
        event_time = datetime.now(timezone.utc)

    state["anomaly"] = score_live_session(
        model,
        hour=state.get("hour", event_time.hour),
        day_of_week=state.get("day_of_week", event_time.weekday()),
        duration_seconds=state.get("duration_seconds", 0.0),
        total_commands=state.get("total_commands", 1),
        sudo_count=state.get("sudo_count", 0),
        has_history_clear=state.get("has_history_clear", 0),
        has_dangerous_cmd=state.get("has_dangerous_cmd", 0),
        commands_per_minute=state.get("commands_per_minute", 0.0),
    )
    return state


def decide_action(state: AgentState) -> AgentState:
    threat = state.get("threat", {})
    anomaly = state.get("anomaly", {})
    severity = str(threat.get("severity", "LOW")).upper()
    anomaly_detected = bool(anomaly.get("is_anomaly", False))
    actionable = severity in {"CRITICAL", "HIGH", "MEDIUM"} or anomaly_detected
    reasons = [str(threat.get("reason", ""))]
    if anomaly_detected:
        reasons.append(f"Anomaly detected: {anomaly.get('label', 'ANOMALOUS')}")

    state["decision"] = {
        "record_incident": actionable,
        "send_email": actionable and severity in {"CRITICAL", "HIGH"},
        "publish_event": actionable,
        "severity": severity,
        "reason": "; ".join(reason for reason in reasons if reason),
        "action_taken": get_recommended_action(severity) if severity != "LOW" else (
            "Investigate anomalous session." if anomaly_detected else "No action required."
        ),
    }
    return state


def _insert_incident(state: AgentState) -> int | None:
    import psycopg2

    connection = psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=os.getenv("POSTGRES_PORT", "5432"),
        dbname=os.getenv("POSTGRES_DB", "nokia_ssh"),
        user=os.getenv("POSTGRES_USER", "nokia"),
        password=os.getenv("POSTGRES_PASSWORD", "nokia123"),
    )
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO incidents
                    (command, severity, username, session_id, detected_at,
                     anomaly_score, is_anomaly, action_taken, email_sent, notes)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    state.get("command", ""),
                    state.get("decision", {}).get("severity", "LOW"),
                    state.get("username"),
                    state.get("session_id"),
                    state.get("timestamp"),
                    state.get("anomaly", {}).get("score"),
                    state.get("anomaly", {}).get("is_anomaly", False),
                    state.get("decision", {}).get("action_taken"),
                    state.get("email_sent", False),
                    state.get("decision", {}).get("reason"),
                ),
            )
            incident_id = cursor.fetchone()[0]
        connection.commit()
        return int(incident_id)
    finally:
        connection.close()


def _publish_event(state: AgentState) -> bool:
    import redis

    client = redis.Redis(
        host=os.getenv("VALKEY_HOST", "localhost"),
        port=int(os.getenv("VALKEY_PORT", "6379")),
        decode_responses=True,
    )
    payload = {
        "incident_id": state.get("incident_id"),
        "command": state.get("command"),
        "username": state.get("username"),
        "session_id": state.get("session_id"),
        "threat": state.get("threat", {}),
        "anomaly": state.get("anomaly", {}),
        "decision": state.get("decision", {}),
    }
    client.publish("nokia:ssh:incidents", json.dumps(payload, default=str))
    return True


def execute_response(state: AgentState) -> AgentState:
    decision = state.get("decision", {})
    errors: dict[str, str] = {}
    state["incident_id"] = None
    state["email_sent"] = False
    state["published"] = False

    if decision.get("record_incident"):
        try:
            state["incident_id"] = _insert_incident(state)
        except Exception as exc:
            errors["incident"] = str(exc)

    if decision.get("send_email") and is_configured():
        state["email_sent"] = send_alert(
            command=state.get("command", ""),
            severity=decision.get("severity", "LOW"),
            username=state.get("username", "unknown"),
            session_id=state.get("session_id", "unknown"),
            timestamp=state.get("timestamp"),
            category=state.get("threat", {}).get("category", ""),
            reason=decision.get("reason", ""),
            anomaly_score=state.get("anomaly", {}).get("score"),
            is_anomaly=state.get("anomaly", {}).get("is_anomaly", False),
            recommended_action=decision.get("action_taken", ""),
        )

    if decision.get("publish_event"):
        try:
            state["published"] = _publish_event(state)
        except Exception as exc:
            errors["publish"] = str(exc)

    state["response"] = {
        "command": state.get("command"),
        "severity": decision.get("severity"),
        "threat": state.get("threat", {}),
        "anomaly": {
            **state.get("anomaly", {}),
            "is_anomaly": bool(state.get("anomaly", {}).get("is_anomaly", False)),
        },
        "action_taken": decision.get("action_taken"),
        "incident_id": state.get("incident_id"),
        "email_sent": state.get("email_sent", False),
        "published": state.get("published", False),
    }
    if errors:
        state["response"]["errors"] = errors
    return state


def build_agent_graph():
    graph = StateGraph(AgentState)
    graph.add_node("classify_threat", classify_threat)
    graph.add_node("check_anomaly", check_anomaly)
    graph.add_node("decide_action", decide_action)
    graph.add_node("execute_response", execute_response)
    graph.add_edge(START, "classify_threat")
    graph.add_edge("classify_threat", "check_anomaly")
    graph.add_edge("check_anomaly", "decide_action")
    graph.add_edge("decide_action", "execute_response")
    graph.add_edge("execute_response", END)
    return graph.compile()


def build_agent():
    """Build and compile the LangGraph pipeline."""
    return build_agent_graph()


def initialize():
    """Load the anomaly model and build the agent once at startup."""
    global anomaly_model
    print("[AGENT] Loading anomaly detection model...")
    anomaly_model = load_model()
    print("[AGENT] Building LangGraph pipeline...")
    agent = build_agent()
    print("[AGENT] Agent ready!")
    return agent


AGENT = build_agent()


def create_initial_state(
    command: str,
    session_id: str = "unknown",
    username: str = "admin",
    timestamp: str | None = None,
    login_hour: int | None = None,
    day_of_week: int | None = None,
    duration_sec: float = 0.0,
    total_commands: int = 1,
    sudo_count: int = 0,
) -> AgentState:
    now = datetime.now(timezone.utc)
    return {
        "command": command,
        "session_id": session_id[:8] if len(session_id) > 8 else session_id,
        "username": username,
        "timestamp": timestamp or now.strftime("%Y-%m-%d %H:%M:%S"),
        "hour": login_hour if login_hour is not None else now.hour,
        "day_of_week": day_of_week if day_of_week is not None else now.weekday(),
        "duration_seconds": duration_sec,
        "total_commands": total_commands,
        "sudo_count": sudo_count,
        "has_history_clear": int("history -c" in command.lower()),
        "has_dangerous_cmd": 0,
        "commands_per_minute": total_commands / max(duration_sec / 60, 1) if duration_sec > 0 else 0.0,
    }


def process_command(agent_or_command, command: str | None = None, **session_context: Any) -> dict[str, Any]:
    """Run one command through the complete threat/anomaly pipeline."""
    if isinstance(agent_or_command, str):
        agent = AGENT
        command_text = agent_or_command
    else:
        agent = agent_or_command
        command_text = command or ""
    state = create_initial_state(command_text, **session_context)
    return agent.invoke(state)


if __name__ == "__main__":
    print("Nokia SSH LangGraph Agent - Self Test")
    print("=" * 55)
    agent = initialize()
    test_commands = [
        ("ls -la", "LOW", "normal command"),
        ("whoami", "LOW", "normal command"),
        ("sudo useradd hacker123", "HIGH", "user creation"),
        ("history -c", "HIGH", "log tampering"),
        ("rm -rf /data", "CRITICAL", "file destruction"),
        ("chmod 777 /etc/passwd", "CRITICAL", "sensitive file"),
        ("wget http://malicious.com", "MEDIUM", "download"),
        ("nmap -sV 192.168.1.0/24", "MEDIUM", "network scan"),
    ]
    passed = 0
    for command, expected_severity, description in test_commands:
        result = process_command(agent, command, session_id="test1234", username="admin")
        success = result.get("threat", {}).get("severity") == expected_severity
        passed += int(success)
        status = "PASS" if success else "WARN"
        print(f"[{status}] [{result.get('threat', {}).get('severity', 'UNKNOWN'):8s}] {command[:40]:<40} ({description})")
        print(f"   Layer: {result.get('threat', {}).get('layer')} | Action: {result.get('decision', {}).get('action_taken')} | Anomaly: {result.get('anomaly', {}).get('label')}")
        if result.get("incident_id"):
            print(f"   Incident ID: {result['incident_id']}")
    print("\n" + "=" * 55)
    print(f"Results: {passed}/{len(test_commands)} passed")
    if not is_configured():
        print("Email not configured - set SMTP_USER/SMTP_PASS/ALERT_EMAIL in .env")
    print("Self test complete!")