const form = document.querySelector('#chat-form')
const input = document.querySelector('#message-input')
const messages = document.querySelector('#messages')
const error = document.querySelector('#error')
const sendButton = document.querySelector('#send-button')
const toggle = document.querySelector('#mode-toggle')
const chatView = document.querySelector('#chat-view')
const normalView = document.querySelector('#normal-view')
const modeState = document.querySelector('#mode-state')

function addMessage(role, text, metadata) {
  const article = document.createElement('article')
  article.className = `message ${role}`
  const label = document.createElement('strong')
  label.textContent = role === 'user' ? 'You' : 'Groq AI'
  const body = document.createElement('p')
  body.textContent = text
  article.append(label, body)
  if (metadata) {
    const evidence = document.createElement('small')
    evidence.textContent = `${metadata.retrieval_mode}: ${metadata.evidence_summary}`
    article.append(evidence)
  }
  messages.append(article)
  article.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
}

toggle.addEventListener('click', () => {
  const enabled = toggle.getAttribute('aria-pressed') !== 'true'
  toggle.setAttribute('aria-pressed', String(enabled))
  modeState.textContent = enabled ? 'On' : 'Off'
  chatView.hidden = !enabled
  normalView.hidden = enabled
})

form.addEventListener('submit', async (event) => {
  event.preventDefault()
  const message = input.value.trim()
  if (!message || sendButton.disabled) return
  error.hidden = true
  addMessage('user', message)
  input.value = ''
  sendButton.disabled = true
  sendButton.textContent = 'Working…'
  try {
    const response = await fetch('/api/chat', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message }),
    })
    const payload = await response.json()
    if (!response.ok) throw new Error(payload.detail || `Chat request failed (${response.status})`)
    addMessage('assistant', payload.answer, payload)
  } catch (cause) {
    error.textContent = cause instanceof Error ? cause.message : 'The addon could not complete the request.'
    error.hidden = false
  } finally {
    sendButton.disabled = false
    sendButton.textContent = 'Send'
    input.focus()
  }
})
