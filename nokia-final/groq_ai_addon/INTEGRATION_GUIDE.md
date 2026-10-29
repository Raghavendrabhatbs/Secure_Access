# Integration and Deployment Guide

The Secure Access development UI includes a blank toolbar toggle for this
Groq-backed assistant. Its Vite dev-server proxy forwards `/groq-ai-api` to the
standalone add-on and preserves the browser's Secure Access cookie.

For a production deployment:

1. Run the addon backend on an internal address behind the same authenticated
   Secure Access reverse proxy, or proxy a new path to it. Preserve the signed
   Warpgate cookie; do not add a bypass token or anonymous endpoint.
2. Configure TLS and an origin allowlist at the proxy. Keep the Groq API key
   server-side. Do not expose this service directly to the public internet.
3. Route `/groq-ai-api` from the UI's production origin to the add-on and strip
   the `/groq-ai-api` prefix before forwarding to its API. Keep authentication
   enabled and verify that the Warpgate cookie is forwarded.
4. Configure the add-on API and Warpgate URLs and trusted CA certificate.
5. If agent incident alerts are needed, provision a separate PostgreSQL role with
   SELECT-only access to `incidents`, then set `AUDIT_DATABASE_URL`. Do not
   reuse the application write credentials.
6. Verify role scoping and cookie behavior with admin, auditor, and developer
   accounts before deployment.

The existing audit page combines Secure Access UI audit events and Warpgate
gateway audit events; the add-on reads both using the logged-in admin or auditor
identity. The current endpoints each cap results at the 500 most recent
matching records. Current SSH sessions are retrieved from Warpgate's role-scoped
feed and combined with the PostgreSQL archive. Authorized finalized Web
recordings are read on demand, summarized locally, and never sent to Groq as
raw rrweb payloads; DOM text and input values are excluded.
