from __future__ import annotations

import argparse
import sys
from pathlib import Path


API_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = API_ROOT.parents[1]

for path in (PROJECT_ROOT, API_ROOT):
    path_text = str(path)
    if path_text not in sys.path:
        sys.path.insert(0, path_text)

from app.db.database import SessionLocal
from app.core.config import settings
from app.services.chatbot_service import ChatbotQueryService
from app.services.conversation_context_service import ConversationContextService
from app.services.conversation_service import ConversationService


def _check_ollama_status() -> str:
    import json
    import urllib.error
    import urllib.request

    tags_url = f"{settings.ollama_host.rstrip('/')}/api/tags"
    try:
        with urllib.request.urlopen(tags_url, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
        model_names = [
            model.get("model") or model.get("name")
            for model in payload.get("models", [])
            if model.get("model") or model.get("name")
        ]
        if settings.ollama_model in model_names:
            return f"connected ({settings.ollama_model})"
        if model_names:
            return (
                f"connected, but configured model `{settings.ollama_model}` not found. "
                f"Available: {', '.join(model_names)}"
            )
        return "connected, but no models are installed"
    except urllib.error.URLError as exc:
        return f"not connected ({exc.reason})"
    except Exception as exc:
        return f"not connected ({exc})"


def _print_result(result: dict) -> None:
    print()
    print("AI:", result.get("answer", ""))
    print()
    print("INTENT:", result.get("intent"))
    print("MODE:", result.get("retrieval_mode"))
    print("EVIDENCE:", result.get("evidence_available"))
    print("SUMMARY:", result.get("evidence_summary"))


def _answer_once(question: str, session_id: str | None) -> None:
    db = SessionLocal()
    try:
        service = ChatbotQueryService(db)
        _print_result(service.answer_question(question, session_id=session_id))
    finally:
        db.close()


def _run_interactive(session_id: str | None, conversation_id: str | None) -> None:
    db = SessionLocal()
    try:
        service = ChatbotQueryService(db)
        conversation_service = ConversationService(db)
        conversation = conversation_service.get_or_create(conversation_id)
        context_service = ConversationContextService()
        history = conversation_service.history(conversation.id)
        session_count = service._session_query_service.count_unique_sessions()

        print("=" * 56)
        print("       NOKIA SSH SECURITY AI ASSISTANT")
        print("=" * 56)
        print("Engine: v2.7 (Phase 3 audit export, anomaly detection, knowledge base)")
        print(f"Sessions available: {session_count}")
        print(f"Ollama: {_check_ollama_status()}")
        print(f"Conversation ID: {conversation.id}")
        if session_id:
            print(f"Session context: {session_id}")
        print("Type 'exit' or 'quit' to leave.")

        while True:
            question = input("\nYou: ").strip()
            if question.lower() in {"exit", "quit"}:
                print("=" * 56)
                return
            if not question:
                continue

            resolved = context_service.resolve(question, history)
            effective_session_id = session_id or resolved.session_id
            result = service.answer_question(
                resolved.question,
                session_id=effective_session_id,
                resolved_command=resolved.command,
                followup_type=resolved.followup_type,
            )
            conversation_service.add_message(
                conversation.id,
                "user",
                question,
                {
                    "session_id": effective_session_id,
                    "resolved_command": resolved.command,
                    "followup_type": resolved.followup_type,
                    "entities": {
                        "commands": ([{"command": resolved.command}] if resolved.command else []),
                    },
                },
            )
            conversation_service.add_message(
                conversation.id,
                "assistant",
                result["answer"],
                {
                    "intent": result.get("intent"),
                    "retrieval_mode": result.get("retrieval_mode"),
                    "session_id": result.get("session_id"),
                    "evidence_available": result.get("evidence_available", False),
                    "entities": result.get("conversation_entities", {}),
                },
            )
            db.commit()
            history = conversation_service.history(conversation.id)
            _print_result(result)
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Nokia SSH security chatbot CLI")
    parser.add_argument("--question", "-q", help="Ask one question and exit")
    parser.add_argument("--session-id", help="Optional session ID context")
    parser.add_argument("--conversation-id", help="Resume an existing conversation")
    args = parser.parse_args()

    if args.question:
        _answer_once(args.question, args.session_id)
        return

    _run_interactive(args.session_id, args.conversation_id)


if __name__ == "__main__":
    main()