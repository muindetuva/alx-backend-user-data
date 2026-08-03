"""FastAPI endpoints demonstrating local and durable background work."""
from fastapi import BackgroundTasks, FastAPI

from tasks import scan_photo_for_moderation


app = FastAPI(title="Photo Background Tasks")


def log_upload_event(filename: str) -> None:
    """Append a completed photo upload event to the local upload log."""
    with open("uploads.log", "a", encoding="utf-8") as log_file:
        log_file.write(f"Uploaded: {filename}\n")


def generate_thumbnail(filename: str) -> None:
    """Represent generating a thumbnail for an uploaded photo."""
    return None


def notify_user_photo_processed(user_email: str, filename: str) -> None:
    """Represent notifying a user that photo processing has completed."""
    return None


@app.post("/photos")
async def create_photo(filename: str, background_tasks: BackgroundTasks):
    """Accept a photo and defer writing its upload audit event."""
    background_tasks.add_task(log_upload_event, filename)
    return {"filename": filename, "status": "uploaded"}


@app.post("/photos/{filename}/process")
async def process_photo(
    filename: str,
    user_email: str,
    background_tasks: BackgroundTasks,
):
    """Queue thumbnail generation followed by user notification."""
    background_tasks.add_task(generate_thumbnail, filename)
    background_tasks.add_task(
        notify_user_photo_processed,
        user_email,
        filename,
    )
    return {
        "filename": filename,
        "status": "processing scheduled",
    }


@app.post("/photos/{filename}/scan")
async def scan_photo(filename: str):
    """Dispatch durable moderation work to the Celery queue."""
    scan_photo_for_moderation.delay(filename)
    return {
        "filename": filename,
        "status": "moderation scan queued",
    }
