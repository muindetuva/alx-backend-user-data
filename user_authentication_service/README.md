# User Authentication Service

This FastAPI application demonstrates a testable authentication service layer,
validated registration and login schemas, password hashing, JWT issuance and
validation, active-user resolution, role checks, and fine-grained permissions.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn main:app --reload
```

Public endpoints are `/status`, `/health`, `/register`, and `/login`.
Authenticated endpoints include `/me`, administrator user deletion, and a
report update route demonstrating both permissions and resource ownership.
