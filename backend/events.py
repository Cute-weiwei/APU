from __future__ import annotations

import queue
import threading
from typing import Any

from .db import Database


class SubscriberQueue(queue.Queue):
    """A bounded SSE subscriber queue that records overflow explicitly.

    Silently dropping events when a slow client falls behind makes the client
    believe it saw a contiguous stream.  Instead the queue is marked overflowed;
    the SSE handler then ends the response so the client reconnects with
    ``Last-Event-ID`` and replays from the database.
    """

    def __init__(self, maxsize: int = 2000):
        super().__init__(maxsize=maxsize)
        self.overflowed = threading.Event()


class EventBus:
    """Persist job events and fan them out to SSE subscribers."""

    def __init__(self, database: Database):
        self.database = database
        self._subscribers: dict[str, set[SubscriberQueue]] = {}
        self._lock = threading.Lock()

    def publish(
        self,
        job_id: str,
        kind: str,
        message: str = "",
        data: dict[str, Any] | None = None,
        level: str = "info",
    ) -> dict[str, Any]:
        event = self.database.append_event(job_id, kind, message, data, level)
        with self._lock:
            subscribers = list(self._subscribers.get(job_id, ()))
        for subscriber in subscribers:
            try:
                subscriber.put_nowait(event)
            except queue.Full:
                # Do not drop silently: the stream is closed and the client
                # resumes from the last sequence id it actually received.
                subscriber.overflowed.set()
        return event

    def subscribe(self, job_id: str, maxsize: int = 2000) -> SubscriberQueue:
        subscriber = SubscriberQueue(maxsize=maxsize)
        with self._lock:
            self._subscribers.setdefault(job_id, set()).add(subscriber)
        return subscriber

    def unsubscribe(self, job_id: str, subscriber: SubscriberQueue) -> None:
        with self._lock:
            subscribers = self._subscribers.get(job_id)
            if subscribers:
                subscribers.discard(subscriber)
                if not subscribers:
                    self._subscribers.pop(job_id, None)
