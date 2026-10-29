import { useEffect, useState } from "react";
import {
  Bot,
  CircleAlert,
  LoaderCircle,
  Plus,
  Send,
  ShieldCheck,
  Sparkles,
  UserRound,
  X,
} from "lucide-react";
import { useSearchParams } from "react-router-dom";
import DashboardLayout from "../layouts/DashboardLayout";
import AssistantMessage from "../components/AssistantMessage";
import {
  askGroqAssistant,
  askAssistant,
  getAssistantConversation,
  getAssistantSession,
} from "../api/aiAssistant";
import "../styles/AdminPages.css";

const SUGGESTIONS = [
  "Analyze all finalized Web recordings",
  "How many distinct sessions are recorded?",
  "Show sessions with existing high-risk findings",
  "Summarize the most recent SSH session",
];

const STORAGE_KEY = "secureaccess-ai-conversation-id";
const SESSION_ID_PATTERN = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
const WELCOME_MESSAGE = {
  id: "welcome",
  sender: "assistant",
  text: "Ask about recorded SSH sessions, commands, recordings, or stored risk findings.",
};
const GROQ_WELCOME_MESSAGE = {
  id: "groq-welcome",
  sender: "assistant",
  text: "Groq AI is selected. Ask about authorized SSH sessions, Web recordings, commands, or system activity. The Groq add-on must be running to answer.",
};

function formatTimestamp(value) {
  if (!value) return "Not recorded";
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.getTime()) ? "Not recorded" : timestamp.toLocaleString();
}

function AIAssistantPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const sessionId = searchParams.get("session_id");
  const [messages, setMessages] = useState([WELCOME_MESSAGE]);
  const [conversationId, setConversationId] = useState(() =>
    window.localStorage.getItem(STORAGE_KEY),
  );
  const [question, setQuestion] = useState("");
  const [aiProvider, setAiProvider] = useState("secure-access");
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState("");
  const [retryQuestion, setRetryQuestion] = useState("");
  const [retryDelaySeconds, setRetryDelaySeconds] = useState(0);
  const [sessionState, setSessionState] = useState({
    sessionId: null,
    session: null,
    loading: false,
    error: "",
  });
  const session = sessionState.sessionId === sessionId ? sessionState.session : null;
  const sessionLoading = sessionId && sessionState.sessionId === sessionId
    ? sessionState.loading
    : Boolean(sessionId);
  const sessionError = sessionState.sessionId === sessionId ? sessionState.error : "";

  useEffect(() => {
    if (retryDelaySeconds <= 0) return undefined;
    const timer = window.setTimeout(() => {
      setRetryDelaySeconds((remaining) => Math.max(0, remaining - 1));
    }, 1000);
    return () => window.clearTimeout(timer);
  }, [retryDelaySeconds]);

  useEffect(() => {
    if (!conversationId) return undefined;
    let current = true;

    getAssistantConversation(conversationId)
      .then((history) => {
        if (!current || !Array.isArray(history) || history.length === 0) return;
        setMessages(
          history.map((message) => ({
            id: message.id,
            sender: message.role,
            text: message.content,
            meta: message.metadata_json,
          })),
        );
      })
      .catch(() => {
        if (!current) return;
        window.localStorage.removeItem(STORAGE_KEY);
        setConversationId(null);
        setMessages([WELCOME_MESSAGE]);
      });

    return () => {
      current = false;
    };
  }, [conversationId]);

  useEffect(() => {
    if (!sessionId) return undefined;

    let current = true;
    Promise.resolve()
      .then(() => {
        if (current) {
          setSessionState({ sessionId, session: null, loading: true, error: "" });
        }
        return getAssistantSession(sessionId);
      })
      .then((record) => {
        if (current) {
          setSessionState({ sessionId, session: record, loading: false, error: "" });
        }
      })
      .catch(() => {
        if (current) {
          setSessionState({
            sessionId,
            session: null,
            loading: false,
            error: "Session details could not be loaded.",
          });
        }
      })

    return () => {
      current = false;
    };
  }, [sessionId]);

  function scopeToSession(nextSessionId) {
    setSearchParams(nextSessionId ? { session_id: nextSessionId } : {});
  }

  async function sendQuestion(value = question, isRetry = false) {
    const trimmed = value.trim();
    if (!trimmed || isSending) return;

    setError("");
    setRetryQuestion("");
    setRetryDelaySeconds(0);
    setQuestion("");
    setIsSending(true);
    if (!isRetry) {
      setMessages((current) => [
        ...current,
        { id: crypto.randomUUID(), sender: "user", text: trimmed },
      ]);
    }

    try {
      const scopedQuestion = sessionId
        ? `${trimmed}\n\nFocus on the selected Secure Access session ID: ${sessionId}.`
        : trimmed;
      const result = aiProvider === "groq"
        ? await askGroqAssistant({ question: scopedQuestion })
        : await askAssistant({
          question: trimmed,
          conversationId,
          sessionId,
        });
      setMessages((current) => [
        ...current,
        {
          id: crypto.randomUUID(),
          sender: "assistant",
          text: result.answer,
          meta: {
            intent: result.intent,
            mode: result.retrieval_mode,
            evidence: result.evidence_available,
            summary: result.evidence_summary,
          },
        },
      ]);
      if (result.conversation_id && result.conversation_id !== conversationId) {
        setConversationId(result.conversation_id);
        window.localStorage.setItem(STORAGE_KEY, result.conversation_id);
      } else if (!result.conversation_id && conversationId) {
        setConversationId(null);
        window.localStorage.removeItem(STORAGE_KEY);
      }
    } catch (requestError) {
      const retryDelay = requestError?.retryAfterSeconds;
      const canRetry = aiProvider === "groq" && requestError?.status === 429;
      setError(
        canRetry && Number.isFinite(retryDelay)
          ? `Groq is rate-limited. You can retry this question in about ${Math.ceil(retryDelay)} seconds.`
          : requestError instanceof Error
          ? requestError.message
          : "The assistant request failed. Try again.",
      );
      if (canRetry) {
        setRetryQuestion(trimmed);
        setQuestion(trimmed);
        if (Number.isFinite(retryDelay) && retryDelay > 0) {
          setRetryDelaySeconds(Math.ceil(retryDelay));
        }
      }
    } finally {
      setIsSending(false);
    }
  }

  function startNewConversation() {
    setMessages([aiProvider === "groq" ? GROQ_WELCOME_MESSAGE : WELCOME_MESSAGE]);
    setConversationId(null);
    setError("");
    setRetryQuestion("");
    setRetryDelaySeconds(0);
    if (aiProvider === "secure-access") {
      window.localStorage.removeItem(STORAGE_KEY);
    }
  }

  function toggleAiProvider() {
    if (isSending) return;
    const nextProvider = aiProvider === "groq" ? "secure-access" : "groq";
    setAiProvider(nextProvider);
    setMessages([nextProvider === "groq" ? GROQ_WELCOME_MESSAGE : WELCOME_MESSAGE]);
    setQuestion("");
    setError("");
    setRetryQuestion("");
    setRetryDelaySeconds(0);
    setConversationId(
      nextProvider === "groq" ? null : window.localStorage.getItem(STORAGE_KEY),
    );
  }

  return (
    <DashboardLayout>
      <div className="ai-assistant-page">
        <div className="admin-page-header">
          <div>
            <h1>AI Assistant</h1>
            <p>Session answers are grounded in records available to the assistant API.</p>
          </div>
          <button className="secondary-action-button" onClick={startNewConversation} type="button">
            <Plus size={15} />
            New conversation
          </button>
        </div>

        <section className="ai-assistant-panel">
          {sessionId ? (
            <aside className="ai-session-context" aria-label="Selected session">
              <div className="ai-session-context-heading">
                <div>
                  <span>SESSION CONTEXT</span>
                  <strong title={sessionId}>{session?.session_id || sessionId}</strong>
                </div>
                <button
                  aria-label="Clear selected session"
                  onClick={() => scopeToSession(null)}
                  title="Clear selected session"
                  type="button"
                >
                  <X size={16} />
                </button>
              </div>
              {sessionLoading ? (
                <p className="ai-session-loading">Loading session details...</p>
              ) : sessionError ? (
                <p className="ai-session-error" role="status">{sessionError}</p>
              ) : session ? (
                <dl>
                  <div><dt>User</dt><dd>{session.username || "Not recorded"}</dd></div>
                  <div><dt>Target</dt><dd>{session.target || "Not recorded"}</dd></div>
                  <div><dt>Protocol</dt><dd>{session.protocol || session.session_type || "Not recorded"}</dd></div>
                  <div><dt>Started</dt><dd>{formatTimestamp(session.started_at || session.login_time)}</dd></div>
                  <div><dt>Recording</dt><dd>{session.recording_id ? "Available" : "Not recorded"}</dd></div>
                </dl>
              ) : null}
            </aside>
          ) : null}

          <div className="ai-chat-toolbar">
            <span><ShieldCheck size={15} /> Evidence-aware answers</span>
            <span><Sparkles size={15} /> Analyst support</span>
            <button
              aria-label={aiProvider === "groq" ? "Switch to current Secure Access AI" : "Switch to Groq AI"}
              aria-pressed={aiProvider === "groq"}
              className={`ai-model-switch${aiProvider === "groq" ? " is-groq" : ""}`}
              disabled={isSending}
              onClick={toggleAiProvider}
              type="button"
            />
          </div>

          <div className="ai-message-list" aria-live="polite" aria-relevant="additions">
            {messages.map((message) => {
              const references = message.sender === "assistant"
                ? [...new Set(message.text.match(SESSION_ID_PATTERN) || [])]
                : [];
              return (
                <article className={`ai-message ${message.sender}`} key={message.id}>
                  <span className="ai-message-avatar" aria-hidden="true">
                    {message.sender === "assistant" ? <Bot size={17} /> : <UserRound size={17} />}
                  </span>
                  <div className="ai-message-content">
                    <div className="ai-message-label">
                      {message.sender === "assistant" ? (aiProvider === "groq" ? "Groq AI" : "Assistant") : "You"}
                    </div>
                    {message.sender === "assistant" ? (
                      <AssistantMessage text={message.text} />
                    ) : (
                      <p>{message.text}</p>
                    )}
                    {references.length > 0 ? (
                      <div className="ai-session-references">
                        {references.map((reference) => (
                          <button key={reference} onClick={() => scopeToSession(reference)} type="button">
                            Inspect session {reference.slice(0, 8)}
                          </button>
                        ))}
                      </div>
                    ) : null}
                    {message.meta ? (
                      <div className="ai-evidence-meta">
                        <span>{message.meta.intent || "Analysis"}</span>
                        <span>{message.meta.mode || "rule-based"}</span>
                        <span>{message.meta.evidence ? "Evidence found" : "Evidence unavailable"}</span>
                        {message.meta.summary ? <small>{message.meta.summary}</small> : null}
                      </div>
                    ) : null}
                  </div>
                </article>
              );
            })}
            {isSending ? (
              <div className="ai-chat-loading" role="status">
                <LoaderCircle size={17} className="ai-spinner" />
                {aiProvider === "groq" ? "Checking records with Groq AI..." : "Checking records..."}
              </div>
            ) : null}
          </div>

          {messages.length === 1 && !sessionId ? (
            <div className="ai-assistant-suggestions" aria-label="Suggested questions">
              {SUGGESTIONS.map((suggestion) => (
                <button key={suggestion} onClick={() => void sendQuestion(suggestion)} type="button">
                  {suggestion}
                </button>
              ))}
            </div>
          ) : null}

          {error ? (
            <div className="ai-chat-error" role="alert">
              <CircleAlert size={16} />
              <span>{error}</span>
              {retryQuestion ? (
                <button
                  className="ai-chat-retry"
                  disabled={isSending || retryDelaySeconds > 0}
                  onClick={() => void sendQuestion(retryQuestion, true)}
                  type="button"
                >
                  {retryDelaySeconds > 0
                    ? `Retry in ${retryDelaySeconds}s`
                    : "Retry question"}
                </button>
              ) : null}
            </div>
          ) : null}

          <form
            className="ai-assistant-composer"
            onSubmit={(event) => {
              event.preventDefault();
              void sendQuestion();
            }}
          >
            <label className="sr-only" htmlFor="assistant-question">Ask the assistant</label>
            <textarea
              id="assistant-question"
              maxLength={4000}
              onChange={(event) => {
                setQuestion(event.target.value);
                setRetryQuestion("");
                setRetryDelaySeconds(0);
              }}
              onKeyDown={(event) => {
                if (event.key === "Enter" && !event.shiftKey) {
                  event.preventDefault();
                  void sendQuestion();
                }
              }}
              placeholder={sessionId ? "Ask about this session..." : "Ask about sessions, commands, recordings, or risk findings..."}
              rows={2}
              value={question}
            />
            <div className="ai-composer-footer">
              <span>{question.length}/4000</span>
              <button aria-label="Send question" disabled={isSending || !question.trim()} type="submit">
                <Send size={16} />
                Ask
              </button>
            </div>
          </form>

          <p className="ai-review-note">
            Verify security conclusions against source records before taking action.
          </p>
        </section>
      </div>
    </DashboardLayout>
  );
}

export default AIAssistantPage;
