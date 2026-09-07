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
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Protocol

from openexecutive.monitoring.models import Signal, WatchlistItem


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
# lying (or has a broken clock). Such a value would never age out and would
# render as a huge "ago", so it's treated as no timestamp at all.
_MAX_FUTURE_SKEW = timedelta(days=1)


def _as_published_at(dt: datetime, now: datetime | None) -> str | None:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    if dt > (now or datetime.now(UTC)) + _MAX_FUTURE_SKEW:
        return None
    return dt.isoformat()


def feed_entry_published_at(
    entry: Mapping[str, Any], *, now: datetime | None = None
) -> str | None:
    """ISO 8601 UTC publish timestamp of a feedparser entry, or None.

    feedparser normalises ``<pubDate>`` / ``<published>`` / ``<updated>``
    into ``*_parsed`` ``time.struct_time`` values already converted to
    UTC; we prefer ``published`` (when the item first appeared) over
    ``updated`` (last edit). Entries with no parseable date — or a date
    past ``_MAX_FUTURE_SKEW`` — return None: the pipeline's age gate then
    can't judge them, and only the first-poll baseline protects against
    replaying them as new.
    """
    for key in ("published_parsed", "updated_parsed"):
        st = entry.get(key)
        if not st:
            continue
        try:
            # struct_time is already UTC (feedparser normalises), so timegm —
            # never mktime, which would apply the host's local offset.
            dt = datetime.fromtimestamp(calendar.timegm(st), tz=UTC)
        except (TypeError, ValueError, OverflowError, OSError):
            continue
        return _as_published_at(dt, now)
    return None


def iso_published_at(value: str, *, now: datetime | None = None) -> str | None:
    """Parse a raw ``<updated>`` (ISO 8601) or ``<pubDate>`` (RFC 822) string.

    For adapters that parse XML by hand (vendor_status) rather than via
    feedparser. Same contract as ``feed_entry_published_at``: ISO 8601 UTC
    or None when the value is empty, unparseable, or implausibly future.
    """
    value = (value or "").strip()
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        try:
            dt = parsedate_to_datetime(value)
        except (TypeError, ValueError, IndexError, OverflowError, OSError):
            # OverflowError: absurd numeric zone offsets; a poisoned entry
            # must not take the whole feed's poll down with it.
            return None
    return _as_published_at(dt, now)


def collapse_whitespace(text: str) -> str:
    """Fold runs of whitespace (including newlines) into single spaces.

    Feed titles reach ``normalized_summary``, which is the FIRST line of
    the alert body the triage prompt reads as labeled lines; an embedded
    newline would let a feed forge its own ``Severity hint:`` /
    ``Published:`` line. Collapsing at the adapter boundary closes that.
    """
    return " ".join((text or "").split())
