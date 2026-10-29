# React + Vite

## Optional Groq assistant

The AI Assistant page has a small blank toggle at the right end of its toolbar.
It switches between the existing Secure Access assistant (the default) and the
Groq-backed assistant. Vite proxies `/groq-ai-api` to the add-on so the browser
can forward the Secure Access login cookie without a cross-origin request.
When Vite runs on Windows, it automatically detects the WSL host gateway; when
Vite runs inside WSL, it uses the WSL default gateway.

Start the Groq add-on with its own `.env` and server-side `GROQ_API_KEY` as
described in `C:\SecureAccess\nokia-final\groq_ai_addon\README.md`. Then restart
the Vite dev server after changing `vite.config.js`. If the add-on is hosted
elsewhere, set `GROQ_AI_API_TARGET` for the Vite server. Production deployments
must configure their reverse proxy to forward `/groq-ai-api` to the add-on and
preserve Secure Access authentication; the Vite proxy only applies in
development.

If the UI reports that the Groq add-on is not responding, check
`http://localhost:5173/groq-ai-api/health` and start the add-on if that endpoint
is unavailable. If the response instead names a Groq provider/model error, verify
`GROQ_API_KEY` and model access in the add-on's private `.env`; restart the
add-on after changing that file.

This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.
Assistant chat requests may take up to five minutes before the UI reports a timeout.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Oxc](https://oxc.rs)
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/)

## React Compiler

The React Compiler is not enabled on this template because of its impact on dev & build performances. To add it, see [this documentation](https://react.dev/learn/react-compiler/installation).

## Expanding the ESLint configuration

If you are developing a production application, we recommend using TypeScript with type-aware lint rules enabled. Check out the [TS template](https://github.com/vitejs/vite/tree/main/packages/create-vite/template-react-ts) for information on how to integrate TypeScript and [`typescript-eslint`](https://typescript-eslint.io) in your project.
