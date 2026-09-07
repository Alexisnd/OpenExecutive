"""Vendor status-page adapter.

Polls Statuspage-compatible Atom history feeds for vendors a company
depends on (AWS, Stripe, Twilio, GitHub, Cloudflare, etc.) and emits one
``Signal`` per new incident. The Atom 1.0 history feed each vendor
publishes is the same shape — entry/id, entry/title, entry/updated,
entry/link — so a single adapter handles them all.

Watchlist row shape this adapter expects:

  - ``signal_type``: ``"vendor_status"``
  - ``target``: the full Atom URL (e.g. ``https://status.aws.amazon.com/rss/all.rss``)
  - ``config_json``: optional ``{"vendor_label": "AWS"}`` — used as a
    prefix in the normalized summary; falls back to a host-derived label
    when missing so legacy rows still render readably.
  - ``trigger_json``: optional ``{"keywords": ["payment", "us-east-1"]}``
    — when present, only entries whose title/summary contain at least one
    keyword match. Otherwise every new entry surfaces.

Severity hint: defaults to ``HIGH`` for any new incident. The triage
pipeline downstream still has final say — a HIGH hint with a low-trust
score from the watchlist (configured in PR-B's tuning loop) gets damped
before the principal sees it.

Freshness (issue #90): a history feed replays its whole archive on the
first poll, so a new watch used to promote up to 100 resolved incidents
at HIGH. The fix is one change with three consequences: the ``dedup_key``
is keyed on ``(entry id, <updated>)`` rather than the entry id alone.
Statuspage bumps ``<updated>`` on every incident update, so a state
change mints a new key and re-fires while an identical poll still dedups
— and because a suppressed insert now burns only ONE state of an
incident, both #80 freshness gates become safe here:

  - the row is seeded on its first poll (``seed_on_first_poll``), with
    the incidents that are still OPEN exempted from the baseline by
    ``promote_on_baseline`` so a live outage surfaces immediately while
    the resolved archive is recorded and never promoted;
  - ``published_at`` is parsed from ``<updated>`` / ``<pubDate>``, so the
    age gate and the future-date deferral judge vendor incidents the same
    way they judge ``rss`` and ``edgar`` entries.
"""
from __future__ import annotations

import hashlib
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse
from xml.etree.ElementTree import Element, ParseError

import httpx

# defusedxml hardens the stdlib ElementTree parser against billion-laughs
# / quadratic-blowup / external-entity attacks. Adapters fetch arbitrary
# URLs from user-supplied watchlist rows, so the parser sees attacker-
# controlled XML in the wild — defusedxml is the right default.
from defusedxml.ElementTree import fromstring as defused_fromstring

from openexecutive.alerts.models import AlertSeverity
from openexecutive.config import get_settings
from openexecutive.monitoring.models import (
    SOURCE_KIND_VENDOR_STATUS,
    Signal,
    WatchlistItem,
)
from openexecutive.monitoring.sources._http import (
    FetchOverflowError,
    fetch_bounded,
    strip_url_query,
    validate_target_url,
)
from openexecutive.monitoring.sources.base import (
    collapse_whitespace,
    feed_text_published_at,
)

logger = logging.getLogger(__name__)

# Atom namespace. Most Statuspage instances publish a pure Atom 1.0 feed
# at /history.atom; a few publish RSS 2.0 at /rss/all.rss. We support
# both: see _parse_feed.
_ATOM_NS = "{http://www.w3.org/2005/Atom}"
# RSS feeds that carry HTML bodies use content:encoded; ElementTree needs
# the expanded name (a bare "content:encoded" raises on the unknown prefix).
_CONTENT_ENCODED = "{http://purl.org/rss/1.0/modules/content/}encoded"

# The documented Statuspage history feed is bounded (~25 entries) — a
# runaway count here means the feed is malformed and we should stop
# reading rather than process megabytes of garbage.
_MAX_ENTRIES_PER_FEED = 100

# Incident status vocabulary. Statuspage renders each update in the entry
# body as "<strong>Resolved</strong> - ...", newest update first, and uses
# one of these labels: incidents run Investigating → Identified →
# Monitoring → Resolved (with "Update" for interim notes and "Postmortem"
# after the fact), scheduled maintenances run Scheduled → In progress →
# Verifying → Completed. OPEN means "still happening" — the operator wants
# to hear about it the moment the watch is added.
_OPEN_STATUSES = frozenset({
    "investigating", "identified", "monitoring", "update",
    "scheduled", "in progress", "verifying",
})
_CLOSED_STATUSES = frozenset({"resolved", "completed", "postmortem"})

# Newest-update label in a Statuspage entry body. Bounded repetition, and
# only over the head of the body (see _BODY_SCAN_CHARS), so a hostile feed
# can't make this scan expensive.
_STRONG_LABEL_RE = re.compile(r"<strong>\s*([^<>]{1,40}?)\s*</strong>", re.IGNORECASE)
# Same label, in a body that carries no markup for us to key on — an
# xhtml-typed Atom <content> (real child elements, so the tags never reach
# us as text) or a plain-text update. Statuspage's own wording puts the
# label first: "Resolved - The issue has been fixed."
_TEXT_LABEL_RE = re.compile(r"^\s*([A-Za-z][A-Za-z ]{1,18}?)\s*[-–—:]\s", re.IGNORECASE)
# AWS's rss/all.rss carries no per-update markup; it stamps the resolution
# into the title instead ("Service is operating normally: [RESOLVED] …").
_TITLE_MARKER_RE = re.compile(r"\[\s*(resolved|completed)\s*\]", re.IGNORECASE)
# The newest update sits at the top of the body; a few KB is far more than
# enough to find it and bounds the regex work regardless of body size.
_BODY_SCAN_CHARS = 8_000


class VendorStatusSource:
    kind: str = SOURCE_KIND_VENDOR_STATUS
    default_poll_interval_minutes: int = 5
    # A history feed returns its whole archive on every poll, so the first
    # poll is a baseline — otherwise every incident the vendor ever had
    # fires as news when the watch is added (issue #90). Safe here ONLY
    # because the dedup key carries <updated> (see _make_dedup_key): a
    # baselined entry burns one STATE of an incident, not the incident, so
    # the next update surfaces. Incidents that are still open are exempted
    # from the baseline entirely — see promote_on_baseline.
    seed_on_first_poll: bool = True

    async def poll(
        self, item: WatchlistItem, *, db_path: Path | None = None
    ) -> list[Signal]:
        if not item.target:
            logger.warning(
                "vendor_status: watchlist %r has empty target — skipping", item.slug
            )
            return []

        # SSRF guard — see monitoring.sources._http.validate_target_url
        # for the full rationale. Watchlist rows are user-supplied, so
        # this is the only spot that turns a string into an HTTP request.
        ok, reason = validate_target_url(item.target)
        if not ok:
            logger.warning(
                "vendor_status: rejecting watchlist %r target — %s",
                item.slug, reason,
            )
            return []

        max_bytes = get_settings().external_monitor_max_fetch_bytes
        try:
            body = await fetch_bounded(item.target, max_bytes)
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.warning(
                "vendor_status: fetch failed for %s (%s): %s",
                item.slug, item.target, exc,
            )
            return []
        except FetchOverflowError:
            logger.warning(
                "vendor_status: feed %s exceeded %d bytes — dropping tick",
                item.target, max_bytes,
            )
            return []

        try:
            entries = _parse_feed(body)
        except ParseError as exc:
            logger.warning(
                "vendor_status: feed %s failed to parse: %s", item.target, exc
            )
            return []

        if not entries:
            return []

        vendor_label = (
            item.config_json.get("vendor_label")
            or _host_label(item.target)
        )
        signals: list[Signal] = []
        for entry in entries[:_MAX_ENTRIES_PER_FEED]:
            entry_id = entry.get("id") or entry.get("link") or ""
            if not entry_id:
                # Without a stable upstream id we cannot dedup — skip
                # rather than emit a noisy hash-of-title signal that
                # would re-fire on every minor edit.
                continue
            title = collapse_whitespace(entry.get("title") or "") or "(untitled incident)"
            summary = f"[{vendor_label}] {title}"
            updated = entry.get("updated", "")
            signals.append(Signal(
                watchlist_id=item.id or 0,
                source_kind=self.kind,
                # The incident, not the state — two states of one incident
                # share it, which is what makes an operator's "show me this
                # incident" query work. Uniqueness lives on dedup_key.
                source_external_id=entry_id[:500],
                captured_at=datetime.now(UTC).isoformat(),
                published_at=feed_text_published_at(updated),
                normalized_summary=summary[:500],
                raw_payload={
                    "vendor_label": vendor_label,
                    "target_url": item.target,
                    "entry_id": entry_id,
                    "title": title,
                    "link": entry.get("link", ""),
                    "updated": updated,
                    "status": _latest_status(entry.get("body", ""), title),
                },
                provenance_url=entry.get("link") or item.target,
                severity_hint=AlertSeverity.HIGH,
                dedup_key=_make_dedup_key(item.slug, entry_id, updated),
            ))
        return signals

    def matches_trigger(self, signal: Signal, item: WatchlistItem) -> bool:
        """Optional keyword filter — see module docstring."""
        keywords = item.trigger_json.get("keywords") or []
        if not keywords:
            return True
        haystack = (signal.normalized_summary or "").lower()
        return any(kw.lower() in haystack for kw in keywords)

    def promote_on_baseline(self, signal: Signal, item: WatchlistItem) -> bool:
        """First poll only: True for an incident that is still OPEN.

        The optional hook documented on ``sources.base.Source``. A history
        feed's archive is what the baseline exists to swallow, but an
        incident that is open the moment the watch is added is live news —
        the operator adding a Stripe watch during a Stripe outage must hear
        about it now, not at the vendor's next update.

        Unrecognised status counts as CLOSED, deliberately: a vendor that
        changes its feed format must not be able to promote its whole
        archive at HIGH. Nothing is lost for good — that entry is recorded
        as baseline, and the next ``<updated>`` bump mints a new dedup key
        and surfaces normally.
        """
        return _is_open(str(signal.raw_payload.get("status") or ""))


def _parse_feed(body: bytes) -> list[dict[str, str]]:
    """Parse a feed into {id, title, link, updated, body} dicts.

    Uses ``defusedxml.ElementTree`` to block entity-expansion attacks
    (billion-laughs, quadratic-blowup) — see the module-level import
    comment for the full rationale. Returns ``[]`` on unknown shapes
    so a vendor switching feed formats doesn't crash the scan.
    """
    root = defused_fromstring(body)
    tag = root.tag.lower()

    # Atom 1.0 feed root: <feed xmlns="http://www.w3.org/2005/Atom"> with <entry>s
    if tag.endswith("feed"):
        return _parse_atom(root)

    # RSS 2.0: <rss><channel><item>...
    if tag == "rss":
        channel = root.find("channel")
        return _parse_rss(channel) if channel is not None else []

    return []


def _parse_atom(feed: Element) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for entry in feed.findall(f"{_ATOM_NS}entry"):
        entry_id = (entry.findtext(f"{_ATOM_NS}id") or "").strip()
        title = (entry.findtext(f"{_ATOM_NS}title") or "").strip()
        updated = (entry.findtext(f"{_ATOM_NS}updated") or "").strip()
        link = ""
        link_el = entry.find(f"{_ATOM_NS}link")
        if link_el is not None:
            link = (link_el.get("href") or "").strip()
        link = strip_url_query(link) if link else ""
        out.append({
            "id": entry_id, "title": title, "link": link, "updated": updated,
            "body": _element_text(entry, (f"{_ATOM_NS}content", f"{_ATOM_NS}summary")),
        })
    return out


def _parse_rss(channel: Element) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for item in channel.findall("item"):
        guid = (item.findtext("guid") or "").strip()
        link = (item.findtext("link") or "").strip()
        title = (item.findtext("title") or "").strip()
        pub = (item.findtext("pubDate") or "").strip()
        link = strip_url_query(link) if link else ""
        # Prefer guid for id (stable upstream identifier); fall back to
        # the cleaned link so dedup remains stable.
        entry_id = guid or link
        out.append({
            "id": entry_id, "title": title, "link": link, "updated": pub,
            "body": _element_text(item, ("description", _CONTENT_ENCODED)),
        })
    return out


def _element_text(parent: Element, tags: tuple[str, ...]) -> str:
    """Text of the first present child in ``tags``, or "".

    ``itertext`` rather than ``findtext`` so an XHTML-typed Atom
    ``<content>`` (child elements rather than escaped markup) still yields
    its text instead of an empty string.
    """
    for tag in tags:
        el = parent.find(tag)
        if el is None:
            continue
        text = "".join(el.itertext()).strip()
        if text:
            return text
    return ""


def _latest_status(body: str, title: str) -> str:
    """The incident's CURRENT status, lowercased, or "" when unknown.

    Statuspage puts the newest update first in the entry body and labels
    it ``<strong>Resolved</strong>`` / ``Investigating`` / …, so the first
    recognised label in the body head is the incident's state right now.
    Two fallbacks for feeds shaped differently: a label leading the body
    text (an xhtml-typed ``<content>`` reaches us as text with its tags
    already consumed by the parser, and some vendors publish plain-text
    updates), then a title marker (AWS stamps ``[RESOLVED]`` there and
    publishes no per-update markup at all).

    Returns "" for anything unrecognised rather than guessing — callers
    decide what to do with an unknown status, and ``_is_open`` fails
    closed.
    """
    head = body[:_BODY_SCAN_CHARS]
    for match in _STRONG_LABEL_RE.finditer(head):
        label = _known_status(match.group(1))
        if label:
            return label
    leading = _TEXT_LABEL_RE.match(head)
    if leading:
        label = _known_status(leading.group(1))
        if label:
            return label
    marker = _TITLE_MARKER_RE.search(title)
    return marker.group(1).lower() if marker else ""


def _known_status(raw: str) -> str:
    """``raw`` normalised to a status we know, or "" — never a guess."""
    label = collapse_whitespace(raw).lower()
    return label if label in _OPEN_STATUSES or label in _CLOSED_STATUSES else ""


def _is_open(status: str) -> bool:
    """True only for a status we recognise AND that means "still happening".

    Fails closed on "" (unknown): see ``VendorStatusSource.promote_on_baseline``.
    """
    return status in _OPEN_STATUSES


def _host_label(url: str) -> str:
    """Best-effort vendor name from a URL host when config doesn't set one."""
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        return "vendor"
    # status.aws.amazon.com → aws; status.stripe.com → stripe
    parts = [p for p in host.split(".") if p and p != "status" and p != "www"]
    return parts[0] if parts else host or "vendor"


def _make_dedup_key(slug: str, entry_id: str, updated: str) -> str:
    """Deterministic dedup_key over (watchlist slug, entry id, ``<updated>``).

    Hashed because Atom ids can be 200+ char tag URIs; the watchlist
    slug prefix ensures two different watchlist rows pointing at the
    same vendor still produce distinct keys (so each row's own
    trigger / routing fires independently).

    ``<updated>`` is in the key on purpose (issue #90). An incident's id
    is stable across its whole lifetime, so keying on the id alone made
    every suppression permanent — one baselined or stale insert and that
    incident could never surface again, which is why this adapter used to
    sit outside both freshness gates. Keyed on the id AND the update
    stamp, a suppressed insert burns a single state: re-polling an
    unchanged feed still dedups (same id, same stamp), while an incident
    moving Investigating → Resolved mints a new key and surfaces.

    A feed that omits ``<updated>`` degrades to a stable per-incident key
    (the pre-#90 behaviour) rather than to one that changes every poll —
    an entry with no stamp has nothing to change, and a per-poll key
    would re-alert forever.
    """
    payload = f"{slug}\x00{entry_id}\x00{updated}".encode()
    digest = hashlib.sha256(payload).hexdigest()[:32]
    return f"vendor_status:{digest}"
