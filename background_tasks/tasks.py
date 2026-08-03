"""Durable Celery tasks with retry, monitoring, and dead-letter handling."""
from typing import Any

from celery.signals import task_failure, task_success

from celery_app import celery_app


dead_letter_jobs: list[dict[str, Any]] = []
task_events: list[dict[str, Any]] = []


class ModerationServiceTimeoutError(Exception):
    """Signal that the external photo moderation service timed out."""

    pass


def record_dead_letter(task_name: str, args: list, error: str) -> None:
    """Record a task that exhausted retries for later investigation."""
    dead_letter_jobs.append(
        {"task_name": task_name, "args": args, "error": error}
    )


def perform_moderation_scan(filename: str) -> None:
    """Represent the external moderation-service operation."""
    return None


@celery_app.task(bind=True, max_retries=5)
def scan_photo_for_moderation(self, filename: str) -> None:
    """Scan a photo and retry transient moderation-service timeouts."""
    try:
        perform_moderation_scan(filename)
    except ModerationServiceTimeoutError as error:
        if self.request.retries >= self.max_retries:
            record_dead_letter(self.name, [filename], str(error))
            return
        backoff_seconds = 2 ** self.request.retries
        raise self.retry(exc=error, countdown=backoff_seconds)


@task_success.connect
def on_task_success(sender=None, **kwargs) -> None:
    """Record successful Celery task completions for monitoring."""
    task_events.append(
        {
            "status": "success",
            "task": getattr(sender, "name", str(sender)),
        }
    )


@task_failure.connect
def on_task_failure(sender=None, exception=None, **kwargs) -> None:
    """Record failed Celery tasks and their exceptions for monitoring."""
    task_events.append(
        {
            "status": "failure",
            "task": getattr(sender, "name", str(sender)),
            "error": str(exception),
        }
    )
