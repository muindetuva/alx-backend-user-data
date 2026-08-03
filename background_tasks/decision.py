"""Decision helpers for choosing an appropriate background-work tool."""


def needs_real_task_queue(
    requires_durability: bool,
    requires_retry: bool,
    is_resource_intensive: bool,
) -> bool:
    """Return whether any requirement calls for a durable task queue."""
    return any(
        (requires_durability, requires_retry, is_resource_intensive)
    )


def is_appropriate_for_background_tasks(
    requires_durability: bool,
    requires_retry: bool,
    is_resource_intensive: bool,
) -> bool:
    """Return whether none of the requirements need a real task queue."""
    return not any(
        (requires_durability, requires_retry, is_resource_intensive)
    )
