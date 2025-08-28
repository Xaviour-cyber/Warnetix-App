# backend/watcher.py — v3.2.5 (clean, Pylance-safe, ASCII)
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import (
    Callable,
    Dict,
    List,
    Optional,
    TypedDict,
    Final,
    TYPE_CHECKING,
)

# Runtime import for actual observer instance
from watchdog.observers import Observer as _ObserverRuntime
from watchdog.events import FileSystemEventHandler, FileSystemEvent

# For type checking only (prevents "variable in type expression" warning)
if TYPE_CHECKING:
    # This name exists only for annotations (string forward-ref will resolve)
    from watchdog.observers import Observer  # noqa: F401

# ---------- Types ----------
class SseEvent(TypedDict, total=False):
    type: str            # "created" | "modified" | "watch_started" | "watch_stopped"
    path: str            # file path (not present for watch_started/stopped)
    paths: List[str]     # used by watch_started
    ts: float            # epoch seconds


class ScanJob(TypedDict):
    type: str            # always "scan_file"
    path: str
    ts: float


JSONStr: Final = str
EventPublisher = Callable[[JSONStr], None]
JobPublisher = Callable[[ScanJob], None]


# ---------- Debounced handler ----------
class _DebouncedHandler(FileSystemEventHandler):
    """Coalesce noisy FS events; publish SSE + autoscan job."""

    def __init__(
        self,
        emit_event: Callable[[SseEvent], None],
        emit_job: Optional[JobPublisher],
        debounce: float = 0.25,
    ) -> None:
        super().__init__()
        self._emit_event = emit_event
        self._emit_job = emit_job
        self._debounce = debounce
        self._last_seen: Dict[str, float] = {}

    def _should_emit(self, p: str) -> bool:
        now = time.time()
        last = self._last_seen.get(p, 0.0)
        if now - last < self._debounce:
            return False
        self._last_seen[p] = now
        return True

    def _publish(self, typ: str, path: str) -> None:
        payload: SseEvent = {"type": typ, "path": path, "ts": time.time()}
        self._emit_event(payload)
        if self._emit_job is not None and typ in ("created", "modified"):
            job: ScanJob = {"type": "scan_file", "path": path, "ts": payload["ts"]}
            self._emit_job(job)

    # watchdog callbacks
    def on_created(self, e: FileSystemEvent) -> None:
        if not e.is_directory and self._should_emit(e.src_path):
            self._publish("created", e.src_path)

    def on_modified(self, e: FileSystemEvent) -> None:
        if not e.is_directory and self._should_emit(e.src_path):
            self._publish("modified", e.src_path)


# ---------- Public API ----------
class FileWatcher:
    """
    Watch directories with watchdog:
      - Publish JSON string to SSE queue
      - Optionally push 'scan_file' job to AutoScan worker
    """

    def __init__(
        self,
        events_put: EventPublisher,
        jobs_put: Optional[JobPublisher] = None,
        debounce: float = 0.25,
    ) -> None:
        # Use forward-ref string for the type; real instance uses _ObserverRuntime
        self._observer: Optional["Observer"] = None  # type: ignore[valid-type]
        self._paths: List[Path] = []
        self._running: bool = False

        self._events_put: EventPublisher = events_put
        self._jobs_put: Optional[JobPublisher] = jobs_put
        self._debounce: float = debounce

    # lifecycle
    def start(self, paths: List[str], recursive: bool = True) -> List[str]:
        """Start watching; returns the list of valid directories being watched."""
        self.stop()

        obs = _ObserverRuntime()
        handler = _DebouncedHandler(
            emit_event=lambda obj: self._safe_pub(obj),
            emit_job=(lambda job: self._safe_job(job)) if self._jobs_put else None,
            debounce=self._debounce,
        )

        valid: List[str] = []
        self._paths = []
        for p in paths:
            pp = Path(os.path.expanduser(p)).resolve()
            if pp.exists() and pp.is_dir():
                obs.schedule(handler, str(pp), recursive=recursive)
                valid.append(str(pp))
                self._paths.append(pp)

        if not valid:
            raise RuntimeError("Tidak ada direktori valid untuk dipantau.")

        obs.start()
        self._observer = obs
        self._running = True
        self._safe_pub({"type": "watch_started", "paths": valid, "ts": time.time()})
        return valid

    def stop(self) -> None:
        """Stop watching (idempotent)."""
        if self._observer is not None:
            try:
                self._observer.stop()
                self._observer.join(timeout=2.0)
            except Exception:
                pass
        self._observer = None
        if self._running:
            self._safe_pub({"type": "watch_stopped", "ts": time.time()})
        self._running = False
        self._paths = []

    # status
    def status(self) -> Dict[str, object]:
        return {"running": self._running, "paths": [str(p) for p in self._paths]}

    # safe publishers
    def _safe_pub(self, obj: SseEvent) -> None:
        try:
            self._events_put(json.dumps(obj))
        except Exception:
            # never let publish error kill the watcher
            pass

    def _safe_job(self, job: ScanJob) -> None:
        try:
            assert self._jobs_put is not None
            self._jobs_put(job)
        except Exception:
            pass
