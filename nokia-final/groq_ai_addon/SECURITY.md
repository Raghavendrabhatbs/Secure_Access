# Security and Privacy

- Keep `GROQ_API_KEY` in the addon backend environment. Never place it in
  browser code, URLs, chat messages, or logs.
- Every chat request must carry a valid signed Warpgate cookie. The addon checks
  its identity and allowed application role before querying data.
- Data calls use the existing authenticated API and forward only the validated
  session cookie. Developer access is restricted to that developer's username.
- Tool names are allow-listed; Pydantic schemas reject extra keys and invalid
  bounds. No model-supplied SQL, shell command, or write operation is executed.
- Session details, commands, and events are looked up only after the session
  has passed the authenticated user's visibility filter.
- Audit events are fetched only for admin and auditor roles, matching the
  existing Warpgate audit API authorization. Developers cannot use the add-on
  to bypass that restriction.
- The optional incident reader uses fixed SQL, bound parameters, a read-only
  transaction, a statement timeout, row limits, and an explicit read-only
  database URL. Grant that database role `SELECT` only on the required table.
- Credential-like fields and common inline secrets are redacted before evidence
  is sent to Groq. Do not use the addon with data that organizational policy
  prohibits transmitting to the configured external model provider.
- Retrieved session/log content is untrusted and cannot request additional
  tool access or override the system prompt.
- The standalone frontend is not a security boundary. Do not configure
  permissive CORS or expose the addon to the public internet without an
  approved authenticated reverse proxy and TLS.
