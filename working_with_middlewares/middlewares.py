"""Reusable class-based middleware for the sample FastAPI application."""
import time

import httpx
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware


class TimingMiddleware(BaseHTTPMiddleware):
    """Attach request processing time using a configurable header name."""

    def __init__(
        self, app, header_name: str = "X-Process-Time"
    ) -> None:
        """Initialize the middleware and remember its response header."""
        super().__init__(app)
        self.header_name = header_name

    async def dispatch(self, request: Request, call_next):
        """Measure the downstream request and annotate its response."""
        started_at = time.perf_counter()
        response = await call_next(request)
        response.headers[self.header_name] = str(
            time.perf_counter() - started_at
        )
        return response


class FraudCheckMiddleware(BaseHTTPMiddleware):
    """Notify an external fraud service without blocking the event loop."""

    def __init__(
        self,
        app,
        service_url: str = "https://fraud-check.example.com/notify",
    ) -> None:
        """Initialize the middleware with its fraud-service URL."""
        super().__init__(app)
        self.service_url = service_url

    async def dispatch(self, request: Request, call_next):
        """Send an asynchronous notification and continue the request."""
        # A synchronous call here would block every concurrent request because
        # middleware executes for the app, not one isolated route.
        try:
            async with httpx.AsyncClient(timeout=0.25) as client:
                await client.post(
                    self.service_url,
                    json={"path": request.url.path},
                )
        except httpx.HTTPError:
            # The notification is best-effort; API availability comes first.
            pass
        return await call_next(request)
