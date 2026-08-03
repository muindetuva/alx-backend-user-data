# Session Authentication

This project builds a FastAPI session-authentication flow from secure token
generation through Redis-backed persistence, protected routes, secure cookies,
absolute and idle expiry, logout, and concurrent-session management.

## Run locally

1. Start Redis on `localhost:6379`.
2. Create and activate a Python virtual environment.
3. Install dependencies with `pip install -r requirements.txt`.
4. Run `uvicorn main:app --reload`.

The included demonstration account is `demo` with password `demo-password`.
Public status routes remain accessible at `/status` and `/health`. Log in with
`POST /login`, then use `/profile`, `/sessions`, the per-session revoke route,
and `POST /logout` to exercise the full flow.

Production deployments should provide a monitored Redis service and should
serve the API over HTTPS because the session cookie is marked `Secure`,
`HttpOnly`, and `SameSite=Lax`.
