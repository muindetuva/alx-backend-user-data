# Basic Authentication

This FastAPI project demonstrates the mechanics and appropriate scope of HTTP
Basic Authentication. It includes Base64 credential helpers, FastAPI's
`HTTPBasic` dependency, Argon2 password verification, timing-safe static-token
comparison, individually protected routes, and router-level protection.

Install the dependencies with `python3 -m pip install -r requirements.txt`,
then start the app from this directory with `uvicorn main:app --reload`. The
sample credential is `admin` / `s3cret-password`. Basic Auth must only be used
over HTTPS and is generally insufficient for modern production session
management.
