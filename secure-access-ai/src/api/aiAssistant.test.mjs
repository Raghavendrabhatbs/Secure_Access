import assert from "node:assert/strict";
import test from "node:test";

import { askAssistant, askGroqAssistant } from "./aiAssistant.js";

globalThis.window = globalThis;

const originalFetch = globalThis.fetch;

test.afterEach(() => {
  globalThis.fetch = originalFetch;
});

test("sends a grounded chat request with session and conversation context", async () => {
  let capturedRequest;
  globalThis.fetch = async (url, options) => {
    capturedRequest = { url, options };
    return {
      ok: true,
      status: 200,
      json: async () => ({ answer: "Two sessions.", intent: "SESSION_COUNT" }),
    };
  };

  const response = await askAssistant({
    question: "How many sessions are recorded?",
    conversationId: "conversation-1",
    sessionId: "session-1",
  });

  assert.equal(response.answer, "Two sessions.");
  assert.equal(capturedRequest.url, "/ai-api/chat/query");
  assert.equal(capturedRequest.options.credentials, "include");
  assert.deepEqual(JSON.parse(capturedRequest.options.body), {
    message: "How many sessions are recorded?",
    conversation_id: "conversation-1",
    session_id: "session-1",
  });
});

test("allows both assistant chat providers up to five minutes to answer", async () => {
  const timeoutDurations = [];
  const originalSetTimeout = window.setTimeout;
  window.setTimeout = (callback, delay, ...args) => {
    timeoutDurations.push(delay);
    return originalSetTimeout(callback, delay, ...args);
  };
  globalThis.fetch = async (url) => ({
    ok: true,
    status: 200,
    json: async () => url.startsWith("/groq-ai-api")
      ? { answer: "Sessions found.", model: "openai/gpt-oss-120b" }
      : { answer: "Sessions found." },
  });

  try {
    await askAssistant({ question: "How many sessions?" });
    await askGroqAssistant({ question: "How many sessions?" });
    assert.deepEqual(timeoutDurations, [300_000, 300_000]);
  } finally {
    window.setTimeout = originalSetTimeout;
  }
});

test("shows the API's safe error detail on HTTP failure", async () => {
  globalThis.fetch = async () => ({
    ok: false,
    status: 503,
    json: async () => ({ detail: "Database is unavailable. Please retry shortly." }),
  });

  await assert.rejects(
    askAssistant({ question: "status" }),
    { message: "Database is unavailable. Please retry shortly." },
  );
});

test("does not invent a conversation ID before the first assistant request", async () => {
  let capturedRequest;
  globalThis.fetch = async (url, options) => {
    capturedRequest = { url, options };
    return {
      ok: true,
      status: 200,
      json: async () => ({ answer: "One web session." }),
    };
  };

  await askAssistant({ question: "How many web sessions?" });

  assert.deepEqual(JSON.parse(capturedRequest.options.body), {
    message: "How many web sessions?",
  });
});

test("rejects responses without an answer", async () => {
  globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({ detail: "internal exception" }),
  });

  await assert.rejects(
    askAssistant({ question: "status" }),
    { message: "The assistant returned an invalid response." },
  );
});

test("routes Groq requests through its proxy and forwards the Secure Access cookie", async () => {
  let capturedRequest;
  globalThis.fetch = async (url, options) => {
    capturedRequest = { url, options };
    return {
      ok: true,
      status: 200,
      json: async () => ({
        answer: "Three sessions.",
        model: "openai/gpt-oss-120b",
        retrieval_mode: "groq-grounded",
        evidence_available: true,
        evidence_summary: "Live session data retrieved.",
      }),
    };
  };

  const response = await askGroqAssistant({
    question: "How many sessions are recorded?",
  });

  assert.equal(response.answer, "Three sessions.");
  assert.equal(response.intent, "openai/gpt-oss-120b");
  assert.equal(capturedRequest.url, "/groq-ai-api/api/chat");
  assert.equal(capturedRequest.options.credentials, "include");
  assert.deepEqual(JSON.parse(capturedRequest.options.body), {
    message: "How many sessions are recorded?",
  });
});

test("rejects malformed Groq responses", async () => {
  globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({ answer: "Missing model" }),
  });

  await assert.rejects(
    askGroqAssistant({ question: "status" }),
    { message: "The Groq assistant returned an invalid response." },
  );
});

test("explains when the Groq add-on proxy target is unavailable", async () => {
  globalThis.fetch = async () => ({
    ok: false,
    status: 502,
    json: async () => {
      throw new Error("proxy response is not JSON");
    },
  });

  await assert.rejects(
    askGroqAssistant({ question: "How many sessions?" }),
    {
      message:
        "The Groq AI add-on is not responding. Start it on port 8890 and retry; if it is running elsewhere, check GROQ_AI_API_TARGET and restart Vite.",
    },
  );
});

test("preserves actionable errors returned by the Groq add-on", async () => {
  globalThis.fetch = async () => ({
    ok: false,
    status: 502,
    json: async () => ({ detail: "Groq model access is unavailable." }),
  });

  await assert.rejects(
    askGroqAssistant({ question: "How many sessions?" }),
    { message: "Groq model access is unavailable." },
  );
});
