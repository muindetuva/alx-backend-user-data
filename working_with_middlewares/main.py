"""FastAPI application demonstrating a deliberate middleware stack."""
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from middlewares import FraudCheckMiddleware, TimingMiddleware


app = FastAPI(title="Middleware Demonstration")


@app.get("/status")
def status():
    """Return the application's public status."""
    return {"status": "OK"}


@app.get("/health")
def health():
    """Return the application's public health signal."""
    return {"health": "alive"}


@app.get("/whoami")
def whoami(request: Request):
    """Return the request ID attached by middleware."""
    return {"request_id": request.state.request_id}


@app.get("/large-response")
def large_response():
    """Return enough content to demonstrate automatic GZip compression."""
    return {"content": "middleware-data-" * 200}


@app.middleware("http")
async def add_timing_header(request: Request, call_next):
    """Measure downstream processing time with the decorator form."""
    started_at = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Process-Time"] = str(
        time.perf_counter() - started_at
    )
    return response


# Registration dependency: Starlette's later decorator registration is the
# outer request layer. Therefore require_request_id_present is declared first,
# then add_request_id is declared so it runs first and initializes state.
@app.middleware("http")
async def require_request_id_present(request: Request, call_next):
    """Assert that an outer middleware already attached a request ID."""
    assert hasattr(request.state, "request_id"), "request_id must be set first"
    return await call_next(request)


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Attach or preserve a request ID for downstream request handling."""
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


@app.middleware("http")
async def log_execution_order(request: Request, call_next):
    """Log entry and exit to expose the real middleware execution order."""
    print("log_execution_order: request")
    response = await call_next(request)
    print("log_execution_order: response")
    return response


# Observed request-side order (outer to inner): FraudCheck, TrustedHost, GZip,
# CORS, TimingMiddleware, log_execution_order, add_request_id,
# require_request_id_present, add_timing_header, route handler.
# Response processing unwinds in the exact reverse order. In particular,
# add_request_id stays outside require_request_id_present so state exists.
app.add_middleware(TimingMiddleware, header_name="X-Class-Process-Time")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://frontend.example.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "testserver", "api.example.com"],
)
app.add_middleware(FraudCheckMiddleware)
