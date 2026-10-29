const API_BASE_URL = (import.meta.env?.VITE_AI_API_BASE_URL || "/ai-api").replace(/\/+$/, "");
const GROQ_API_BASE_URL = (import.meta.env?.VITE_GROQ_AI_API_BASE_URL || "/groq-ai-api").replace(/\/+$/, "");
const REQUEST_TIMEOUT_MS = 120_000;
const CHAT_REQUEST_TIMEOUT_MS = 300_000;

async function request(path, options = {}, baseUrl = API_BASE_URL, timeoutMs = REQUEST_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(`${baseUrl}${path}`, {
      ...options,
      credentials: "include",
      signal: controller.signal,
    });
    if (!response.ok) {
      let detail;
      try {
        const payload = await response.json();
        detail = typeof payload?.detail === "string" ? payload.detail : undefined;
      } catch {
        detail = undefined;
      }
      if (
        baseUrl === GROQ_API_BASE_URL &&
        !detail &&
        [502, 503, 504].includes(response.status)
      ) {
        throw new Error(
          "The Groq AI add-on is not responding. Start it on port 8890 and retry; if it is running elsewhere, check GROQ_AI_API_TARGET and restart Vite.",
        );
      }
      const requestError = new Error(
        detail || `Assistant service returned HTTP ${response.status}.`,
      );
      requestError.status = response.status;
      const retryAfterSeconds = Number(response.headers.get("Retry-After"));
      if (Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0) {
        requestError.retryAfterSeconds = retryAfterSeconds;
      }
      throw requestError;
    }
    return response.json();
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error("The assistant request timed out after five minutes. Try again.", { cause: error });
    }
    if (error instanceof TypeError) {
      throw new Error(
        "The assistant service is unavailable. Check its connection and try again.",
        { cause: error },
      );
    }
    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
}

export async function askAssistant({ question, conversationId, sessionId }) {
  const payload = await request("/chat/query", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      message: question,
      ...(conversationId ? { conversation_id: conversationId } : {}),
      ...(sessionId ? { session_id: sessionId } : {}),
    }),
  }, API_BASE_URL, CHAT_REQUEST_TIMEOUT_MS);

  if (typeof payload.answer !== "string") {
    throw new Error("The assistant returned an invalid response.");
  }
  return payload;
}

export async function askGroqAssistant({ question }) {
  const payload = await request(
    "/api/chat",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: question }),
    },
    GROQ_API_BASE_URL,
    CHAT_REQUEST_TIMEOUT_MS,
  );

  if (typeof payload.answer !== "string" || typeof payload.model !== "string") {
    throw new Error("The Groq assistant returned an invalid response.");
  }
  return {
    answer: payload.answer,
    intent: payload.model,
    retrieval_mode: payload.retrieval_mode,
    evidence_available: payload.evidence_available,
    evidence_summary: payload.evidence_summary,
  };
}

export async function getAssistantConversation(conversationId) {
  return request(`/chat/conversations/${encodeURIComponent(conversationId)}/messages`);
}

export async function getAssistantSession(sessionId) {
  return request(`/sessions/${encodeURIComponent(sessionId)}`);
}
