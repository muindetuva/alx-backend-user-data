"""Caching strategies ranging from local memoization to Redis."""
import json
import time
from functools import lru_cache
from typing import Any, Awaitable, Callable, Optional, TypeVar

import redis.asyncio as redis


T = TypeVar("T")
CACHE_TTL_SECONDS = 300
FEATURED_BOOKS_TTL_SECONDS = 900

_book_metadata_cache: dict[str, tuple[float, dict]] = {}

redis_client = redis.Redis(
    host='localhost', port=6379, decode_responses=True
)


def is_worth_caching(
    expensive: bool, frequent: bool, staleness: bool
) -> bool:
    """Return whether a result satisfies all three caching criteria."""
    return expensive and frequent and staleness


def is_wrong_fix_for_slow_query(missing_index: bool) -> bool:
    """Return whether caching would hide a known missing database index."""
    return missing_index


@lru_cache(maxsize=128)
def get_book_recommendation_score(user_id: str) -> float:
    """Return a deterministic stand-in for an expensive recommendation."""
    return float(sum(ord(character) for character in user_id) % 100) / 100


def reset_recommendation_cache() -> None:
    """Clear all memoized recommendation scores."""
    get_book_recommendation_score.cache_clear()


async def fetch_book_metadata_from_api(isbn: str) -> dict:
    """Represent an asynchronous metadata lookup from an external API."""
    return {
        "isbn": isbn,
        "title": f"Book {isbn}",
        "source": "external-api",
    }


async def get_book_metadata(isbn: str) -> dict:
    """Return locally cached book metadata until its TTL expires."""
    cached = _book_metadata_cache.get(isbn)
    now = time.monotonic()
    if cached is not None and now - cached[0] < CACHE_TTL_SECONDS:
        return cached[1]

    metadata = await fetch_book_metadata_from_api(isbn)
    _book_metadata_cache[isbn] = (time.monotonic(), metadata)
    return metadata


async def cache_set(key: str, value: Any, ttl_seconds: int) -> None:
    """Serialize and cache a value in Redis for a bounded lifetime."""
    await redis_client.setex(key, ttl_seconds, json.dumps(value))


async def cache_get(key: str) -> Optional[Any]:
    """Return a deserialized Redis value, or ``None`` for a cache miss."""
    cached_value = await redis_client.get(key)
    if cached_value is None:
        return None
    return json.loads(cached_value)


async def cache_or_compute(
    key: str,
    ttl_seconds: int,
    compute_fn: Callable[[], Awaitable[T]],
) -> T:
    """Return a cached value or compute, store, and return a fresh one."""
    cached_value = await cache_get(key)
    if cached_value is not None:
        return cached_value

    computed_value = await compute_fn()
    await cache_set(key, computed_value, ttl_seconds)
    return computed_value


async def get_book_metadata_cached(isbn: str) -> dict:
    """Return metadata through the reusable Redis cache-aside helper."""
    key = f"book:{isbn}:metadata"
    return await cache_or_compute(
        key,
        CACHE_TTL_SECONDS,
        lambda: fetch_book_metadata_from_api(isbn),
    )


async def compute_featured_books() -> list[dict]:
    """Represent the expensive computation of a featured-book collection."""
    return [
        {"isbn": "9780140328721", "title": "Featured Book"},
    ]


async def get_featured_books_cached() -> list[dict]:
    """Cache the shared featured-books result under a fixed key and TTL."""
    return await cache_or_compute(
        "featured_books",
        FEATURED_BOOKS_TTL_SECONDS,
        compute_featured_books,
    )
