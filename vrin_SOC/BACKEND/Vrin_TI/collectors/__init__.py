"""Feed collectors.

``FeedManager`` is imported lazily so ``from Vrin_TI.collectors import
CollectedItem`` does not pull every feed implementation (and their optional
HTTP/file dependencies) at package import time.
"""

from .base import CollectedItem, CollectionBatch, FeedCollector

__all__ = ["CollectedItem", "CollectionBatch", "FeedCollector", "FeedManager"]


def __getattr__(name: str):
    if name == "FeedManager":
        from .feed_manager import FeedManager
        return FeedManager
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
