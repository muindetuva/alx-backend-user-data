# Caching

This project demonstrates when caching is appropriate, local memoization with
`functools.lru_cache`, in-process time-to-live caching, asynchronous Redis
serialization, a generic cache-aside helper, and invalidation after writes.

## Run the API

Start a Redis server on `localhost:6379`, then install and run the service:

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

`GET /books/{book_id}` caches metadata under an ISBN-derived key. A matching
`PUT /books/{book_id}` updates the record and deletes that exact cache key so
the next read cannot return stale data.
