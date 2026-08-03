# Background Tasks

This project demonstrates two levels of asynchronous work in a FastAPI photo
service. Small in-process follow-up actions use FastAPI `BackgroundTasks`,
while durable moderation work is dispatched to Celery through a Redis broker.

## Project contents

- `main.py` exposes upload, processing, and moderation endpoints.
- `decision.py` identifies when work requires a durable task queue.
- `celery_app.py` configures the Celery worker and Redis result backend.
- `tasks.py` implements retry/backoff, dead-letter recording, and task signals.

## Run locally

Install the dependencies and start Redis before launching the API and worker:

```bash
pip install -r requirements.txt
uvicorn main:app --reload
celery -A celery_app.celery_app worker --loglevel=info
```

FastAPI background tasks run after the response in the application process.
Celery jobs are queued independently, retried with exponential backoff when
the moderation service times out, and recorded after retry exhaustion.
