"""Source adapter Protocol.

Each external feed (vendor status page, RSS feed, stock ticker, etc.) is
encapsulated as a ``Source`` implementation. The pipeline calls
``poll(item)`` to fetch and ``matches_trigger(signal, item)`` to apply
the watchlist row's per-item trigger DSL.

Invariants every adapter MUST uphold:

1. **Read-only** — no writes to upstream systems. The whole monitoring
   subsystem is observation-only; surfacing happens through the alert
   pipeline, never via a direct upstream side-effect.
2. **Deterministic dedup_key** — two polls of the same source returning
   the same underlying event MUST produce the same ``dedup_key``. The
   UNIQUE constraint on ``external_signals.dedup_key`` is the cheap
   anti-replay guard; adapters do the work upstream of it.
3. **Provenance URL is always set** — every surfaced signal must let
   the principal click through to the source in one tap.
4. **Bounded fetch** — adapters consult
   ``settings.external_monitor_max_fetch_bytes`` and stop reading past
   it. Defends against runaway feeds and XML-bomb shapes.
"""
from __future__ import annotations

import calendar
import logging
import math
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from openexecutive.config import MAX_FUTURE_SKEW_HOURS, get_settings
from openexecutive.monitoring.models import Signal, WatchlistItem

logger = logging.getLogger(__name__)


class Source(Protocol):
    """Adapter contract — see module docstring for invariants."""

    kind: str  # matches WatchlistItem.signal_type

    default_poll_interval_minutes: int
    # True for feed-listing sources (rss, edgar) whose poll returns the
    # feed's whole back-catalogue, not just what changed: on the FIRST poll
    # of a row the pipeline records every entry as seen (outcome
    # ``suppressed_baseline``) and promotes nothing, so the watch reports
    # what changes from now on. False for point-in-time sources (stock,
    # query) and for page_watch, which keeps its own baseline.
    seed_on_first_poll: bool

    async def poll(
        self, item: WatchlistItem, *, db_path: Path | None = None
    ) -> list[Signal]:
        """Fetch the source, normalize into Signals, return them.

        Implementations should:
          - clamp body size via settings.external_monitor_max_fetch_bytes
          - return [] on any transient failure (logged inside the
            adapter) rather than raising — the pipeline tolerates a bad
            tick on one source without poisoning the others

        ``db_path`` is the database the current scan is using. Stateless
        adapters ignore it; STATEFUL adapters (e.g. page_watch, which stores
        the last-seen content hash) MUST thread it into their store calls so
        their state lands in the same DB as the signals — never the default.
        """
        ...

    def matches_trigger(self, signal: Signal, item: WatchlistItem) -> bool:
        """Apply the watchlist row's trigger_json to a candidate signal.

        Default is True. Trigger is an opt-in filter — most v1 use cases
        (vendor status incident posted = always alert) don't need one.
        """
        ...


# Re-export Signal so adapter code can ``from .base import Signal``.
__all__ = ["Signal", "Source"]


# A feed claiming an item was published more than this far in the future is
# lying (or has a broken clock). The parser prefers another date key when
# one is plausible; when every key is implausible the value is still kept
# — the pipeline then defers the entry (see ``monitoring.pipeline._is_future``)
# rather than letting an undated entry bypass the age gate.
MAX_FUTURE_SKEW = timedelta(days=1)


def is_implausibly_future(
    dt: datetime, now: datetime | None = None, *, skew: timedelta = MAX_FUTURE_SKEW,
) -> bool:
    """True when ``dt`` is more than ``skew`` ahead of ``now``.

    Both the adapters (choosing between an entry's date keys) and the
    pipeline (deciding to defer) pass the configured
    ``EXTERNAL_MONITOR_MAX_FUTURE_SKEW_HOURS``; the constant is only the
    fallback default.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt > (now or datetime.now(UTC)) + skew


def feed_entry_published_at(
    entry: Mapping[str, Any],
    *,
    now: datetime | None = None,
    skew: timedelta = MAX_FUTURE_SKEW,
) -> str | None:
    """ISO 8601 UTC publish timestamp of a feedparser entry, or None.

    feedparser normalises ``<pubDate>`` / ``<published>`` / ``<updated>``
    into ``*_parsed`` ``time.struct_time`` values already converted to
    UTC; we prefer ``published`` (when the item first appeared) over
    ``updated`` (last edit), and a plausible key over one dated past
    ``skew`` (a non-positive ``skew`` turns that preference off, for feeds
    that legitimately date entries ahead). Entries with no parseable date
    return None: the
    pipeline's age gate then can't judge them, and only the first-poll
    baseline protects against replaying them as new. An entry whose every
    key is implausibly future keeps that value, so the pipeline can defer
    it instead of waving an undated entry through.
    """
    fallback: str | None = None
    # Only read keys the entry actually has: feedparser aliases a missing
    # ``updated_parsed`` to ``published_parsed`` with a DeprecationWarning.
    present = set(entry.keys())
    for key in ("published_parsed", "updated_parsed"):
        st = entry.get(key) if key in present else None
        if not st:
            continue
        try:
            # struct_time is already UTC (feedparser normalises), so timegm —
            # never mktime, which would apply the host's local offset.
            dt = datetime.fromtimestamp(calendar.timegm(st), tz=UTC)
        except (TypeError, ValueError, OverflowError, OSError):
            continue
        if skew <= timedelta(0) or not is_implausibly_future(dt, now, skew=skew):
            return dt.isoformat()
        fallback = fallback or dt.isoformat()
    return fallback


def _valid_skew_hours(raw: Any) -> float | None:
    """``raw`` as hours if it is a finite number in 0..MAX_FUTURE_SKEW_HOURS,
    else None. Booleans are rejected (``False`` is not "off"; JSON ``true``
    is not one hour), as is anything unparseable or non-finite — JSON can
    carry ``1e999`` → inf."""
    if isinstance(raw, bool):
        return None
    try:
        hours = float(raw)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(hours) or not 0 <= hours <= MAX_FUTURE_SKEW_HOURS:
        return None
    return hours


def future_skew_for(item: WatchlistItem) -> timedelta:
    """The row's future-date tolerance: a valid ``config_json``
    ``["max_future_skew_hours"]`` (0 .. MAX_FUTURE_SKEW_HOURS; 0 = off for
    this row), else ``EXTERNAL_MONITOR_MAX_FUTURE_SKEW_HOURS``.

    An out-of-range or malformed override is ignored with a warning rather
    than coerced: a negative typo must not silently switch the gate off,
    and a huge one must not overflow the date arithmetic and wedge the row.
    The global value goes through the same check (the env var is
    bounds-checked, but a Settings copy is not); if it is invalid the
    ceiling is used.
    """
    global_hours = _valid_skew_hours(
        get_settings().external_monitor_max_future_skew_hours
    )
    if global_hours is None:
        global_hours = float(MAX_FUTURE_SKEW_HOURS)
    raw = item.config_json.get("max_future_skew_hours")
    if raw is None:
        return timedelta(hours=global_hours)
    hours = _valid_skew_hours(raw)
    if hours is None:
        logger.warning(
            "monitoring: watchlist %r has an invalid max_future_skew_hours %s "
            "(want 0..%d) — using the global setting",
            item.slug, repr(raw)[:64], MAX_FUTURE_SKEW_HOURS,
        )
        return timedelta(hours=global_hours)
    return timedelta(hours=hours)


def collapse_whitespace(text: str) -> str:
    """Fold runs of whitespace (including newlines) into single spaces.

    Feed titles reach ``normalized_summary``, which is the FIRST line of
    the alert body the triage prompt reads as labeled lines; an embedded
    newline would let a feed forge its own ``Severity hint:`` /
    ``Published:`` line. Collapsing at the adapter boundary closes that.
    """
    return " ".join((text or "").split())
