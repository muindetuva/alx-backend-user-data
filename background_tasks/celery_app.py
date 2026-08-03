"""Celery application configured with Redis as broker and result backend."""
from celery import Celery


celery_app = Celery(
    'worker',
    broker='redis://localhost:6379/0',
    backend='redis://localhost:6379/0',
)
