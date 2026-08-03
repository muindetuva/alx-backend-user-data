"""FastAPI routes demonstrating cache-aside reads and invalidation."""
from fastapi import FastAPI

from cache import (
    CACHE_TTL_SECONDS,
    cache_or_compute,
    fetch_book_metadata_from_api,
    redis_client,
)


app = FastAPI(title="Caching Book Service")


async def update_book_in_db(book_id: str, book_data: dict) -> dict:
    """Represent an asynchronous database update for a book record."""
    return {"id": book_id, **book_data}


@app.get("/books/{book_id}")
async def get_book(book_id: str):
    """Fetch one book through the shared cache-aside helper."""
    cache_key = f"book:{book_id}:metadata"
    return await cache_or_compute(
        cache_key,
        CACHE_TTL_SECONDS,
        lambda: fetch_book_metadata_from_api(book_id),
    )


@app.put("/books/{book_id}")
async def update_book(book_id: str, book_data: dict):
    """Update a book, invalidate its cache entry, and confirm the write."""
    updated_book = await update_book_in_db(book_id, book_data)
    cache_key = f"book:{book_id}:metadata"
    await redis_client.delete(cache_key)
    return {
        "message": "Book updated successfully",
        "book": updated_book,
    }
