import type { FormEvent } from 'react'
import { useEffect, useRef, useState } from 'react'
import { Bot, CheckCircle2, Loader2, Plus, Send, ShieldAlert, UserRound } from 'lucide-react'
import './App.css'

type Sender = 'user' | 'assistant'

type ChatSource = {
  title: string
  url: string
  published_at?: string | null
}

type ChatMessage = {
  id: string
  sender: Sender
  text: string
  meta?: {
    intent?: string
    mode?: string
    evidence?: boolean
    summary?: string
  }
  sources?: ChatSource[]
}

type ChatResponse = {
  answer: string
  intent: string
  mode?: string
  retrieval_mode?: string
  evidence_available: boolean
  evidence_summary: string
  conversation_id?: string
  sources?: ChatSource[]
}

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || `${window.location.protocol}//${window.location.hostname}:8765`
const CONVERSATION_STORAGE_KEY = 'nokia-ai-conversation-id'

const EXAMPLE_PROMPTS = [
  'What suspicious activity did admin perform?',
  'What risky commands did admin execute?',
  'Who accessed today?',
  'How many sessions have high risk?',
  'What are the latest cybersecurity developments?',
  'What technology events are coming up?',
]

const initialMessages: ChatMessage[] = [
  {
    id: 'welcome',
    sender: 'assistant',
    text: 'Ask about authorized SSH and web sessions, commands, recordings, security findings, or current public events. I use application evidence for session questions and live sources for current information.',
    meta: {
      intent: 'READY',
      mode: 'grounded',
      evidence: true,
      summary: 'Connected to the Nokia SSH intelligence backend.',
    },
  },
]

function App() {
  const [messages, setMessages] = useState<ChatMessage[]>(initialMessages)
  const [conversationId, setConversationId] = useState(() => window.localStorage.getItem(CONVERSATION_STORAGE_KEY))
  const [input, setInput] = useState('')
  const [isSending, setIsSending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const messageEndRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    messageEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, isSending])

  useEffect(() => {
    if (!conversationId) {
      return
    }

    async function restoreConversation() {
      try {
        const response = await fetch(`${API_BASE_URL}/chat/conversations/${conversationId}/messages`, {
          credentials: 'include',
        })
        if (!response.ok) {
          throw new Error(`Conversation history returned ${response.status}`)
        }
        const history = (await response.json()) as Array<{
          id: string
          role: Sender
          content: string
          metadata_json?: {
            intent?: string
            retrieval_mode?: string
            evidence_available?: boolean
            evidence_summary?: string
            sources?: ChatSource[]
          }
        }>
        if (history.length > 0) {
          setMessages(
            history.map((message) => ({
              id: message.id,
              sender: message.role,
              text: message.content,
              meta: message.metadata_json
                ? {
                    intent: message.metadata_json.intent,
                    mode: message.metadata_json.retrieval_mode,
                    evidence: message.metadata_json.evidence_available,
                    summary: message.metadata_json.evidence_summary,
                  }
                : undefined,
              sources: message.metadata_json?.sources,
            })),
          )
        }
      } catch {
        window.localStorage.removeItem(CONVERSATION_STORAGE_KEY)
        setConversationId(null)
      }
    }

    void restoreConversation()
  }, [conversationId])

  async function sendMessage(messageText: string) {
    const trimmed = messageText.trim()
    if (!trimmed || isSending) {
      return
    }

    setError(null)
    setInput('')
    setIsSending(true)
    setMessages((current) => [
      ...current,
      {
        id: crypto.randomUUID(),
        sender: 'user',
        text: trimmed,
      },
    ])

    try {
      const response = await fetch(`${API_BASE_URL}/chat/query`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ message: trimmed, conversation_id: conversationId }),
      })

      if (!response.ok) {
        throw new Error(`Chat API returned ${response.status}`)
      }

      const payload = (await response.json()) as ChatResponse
      setMessages((current) => [
        ...current,
        {
          id: crypto.randomUUID(),
          sender: 'assistant',
          text: payload.answer,
          meta: {
            intent: payload.intent,
            mode: payload.mode || payload.retrieval_mode,
            evidence: payload.evidence_available,
            summary: payload.evidence_summary,
          },
          sources: payload.sources,
        },
      ])
      if (payload.conversation_id && payload.conversation_id !== conversationId) {
        setConversationId(payload.conversation_id)
        window.localStorage.setItem(CONVERSATION_STORAGE_KEY, payload.conversation_id)
      }
    } catch (caughtError) {
      const message = caughtError instanceof Error ? caughtError.message : 'Unable to reach chat API'
      setError(message)
      setMessages((current) => [
        ...current,
        {
          id: crypto.randomUUID(),
          sender: 'assistant',
          text: 'I could not reach the chatbot API. Check that FastAPI is running and try again.',
          meta: {
            intent: 'API_ERROR',
            mode: 'offline',
            evidence: false,
            summary: message,
          },
        },
      ])
    } finally {
      setIsSending(false)
    }
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    void sendMessage(input)
  }

  return (
    <main className="app-shell">
      <aside className="sidebar" aria-label="Conversation navigation">
        <div className="brand-block">
          <div className="brand-mark">
            <ShieldAlert size={22} aria-hidden="true" />
          </div>
          <div>
            <p className="eyebrow">Nokia</p>
            <h1>SSH Intelligence</h1>
          </div>
        </div>

        <button
          className="new-chat"
          type="button"
          onClick={() => {
            setMessages(initialMessages)
            setConversationId(null)
            window.localStorage.removeItem(CONVERSATION_STORAGE_KEY)
          }}
        >
          <Plus size={16} aria-hidden="true" />
          New Chat
        </button>

        <div className="conversation-list">
          <p className="section-label">Today</p>
          <button type="button">SSH Risk Analysis</button>
          <button type="button">Admin Investigation</button>
          <p className="section-label">Recent</p>
          <button type="button">High-risk sessions</button>
        </div>

        <div className="status-panel">
          <CheckCircle2 size={16} aria-hidden="true" />
          <span>Connected to chat API</span>
        </div>
      </aside>

      <section className="chat-panel" aria-label="Nokia Secure Access Assistant chat">
        <header className="chat-header">
          <div>
            <p className="eyebrow">Grounded in PostgreSQL evidence</p>
            <h2>Nokia Secure Access Assistant</h2>
          </div>
          <div className="connection-pill">
            <span aria-hidden="true" />
            {API_BASE_URL.replace(/^https?:\/\//, '')}
          </div>
        </header>

        <div className="prompt-strip" aria-label="Example prompts">
          {EXAMPLE_PROMPTS.map((prompt) => (
            <button key={prompt} type="button" onClick={() => void sendMessage(prompt)}>
              {prompt}
            </button>
          ))}
        </div>

        <div className="message-list" aria-live="polite">
          {messages.map((message) => (
            <article className={`message ${message.sender}`} key={message.id}>
              <div className="avatar" aria-hidden="true">
                {message.sender === 'assistant' ? <Bot size={18} /> : <UserRound size={18} />}
              </div>
              <div className="bubble">
                <div className="sender-label">{message.sender === 'assistant' ? 'Nokia AI' : 'You'}</div>
                <p>{message.text}</p>
                {message.sources?.length ? (
                  <div className="source-list" aria-label="Answer sources">
                    <strong>Sources</strong>
                    {message.sources.map((source) => (
                      <a key={source.url} href={source.url} target="_blank" rel="noopener noreferrer">
                        {source.title}
                        {source.published_at ? ` (published/updated: ${source.published_at})` : ''}
                      </a>
                    ))}
                  </div>
                ) : null}
                {message.meta ? (
                  <div className="evidence-card">
                    <span>{message.meta.intent}</span>
                    <span>{message.meta.mode}</span>
                    <span>{message.meta.evidence ? 'Evidence found' : 'No evidence'}</span>
                    {message.meta.summary ? <small>{message.meta.summary}</small> : null}
                  </div>
                ) : null}
              </div>
            </article>
          ))}
          {isSending ? (
            <article className="message assistant">
              <div className="avatar" aria-hidden="true">
                <Bot size={18} />
              </div>
              <div className="bubble typing">
                <Loader2 size={16} aria-hidden="true" />
                Retrieving evidence and generating an answer...
              </div>
            </article>
          ) : null}
          <div ref={messageEndRef} />
        </div>

        {error ? <div className="error-banner">{error}</div> : null}

        <form className="composer" onSubmit={handleSubmit}>
          <label htmlFor="chat-input">Ask the Secure Access assistant</label>
          <div className="composer-row">
            <textarea
              id="chat-input"
              value={input}
              onChange={(event) => setInput(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter' && !event.shiftKey) {
                  event.preventDefault()
                  void sendMessage(input)
                }
              }}
              placeholder="Ask about SSH/web sessions, recordings, security activity, or current events..."
              rows={1}
            />
            <button type="submit" disabled={isSending || !input.trim()} aria-label="Send message">
              <Send size={18} aria-hidden="true" />
            </button>
          </div>
        </form>
      </section>
    </main>
  )
}

export default App
