# Working with Middlewares

This FastAPI project demonstrates function- and class-based middleware,
request timing, correlation IDs, CORS, response compression, trusted host
validation, async external-service calls, and deliberate stack ordering.

## Run locally

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

Use `/status` and `/health` for basic responses, `/whoami` to inspect the
request ID, and `/large-response` to observe GZip compression when the client
sends an appropriate `Accept-Encoding` header.
