"""Fixture load / unload / reset must clear the external-monitoring tables.

Before this change the ``watchlist`` and ``external_signals`` tables were
never wiped by the fixture loader. A research scan (or onboarding) would
populate the watchlist with AI/competitor monitors, and those rows then
leaked into every subsequent fixture load and into the restored user state
on unload — the "clean" fixture inherited the previous company's monitors.

The fix routes both the shared load/unload path (``_apply_state_from_source``)
and ``reset_all_state`` through ``_delete_all_rows`` with the two monitoring
tables, ``external_signals`` first so the FK
(``external_signals.watchlist_id`` → ``watchlist.id``) is never violated
under ``PRAGMA foreign_keys=ON``.

We exercise ``_delete_all_rows`` directly (the same helper both call sites
delegate to) so the assertion that matters — the deletion works against the
live schema in the correct FK order — is proven without dragging ChromaDB,
Honcho, and an ``app.state`` shim into a unit test.
"""
from __future__ import annotations

import inspect
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from openexecutive.cli.fixture_loader import (
    _apply_state_from_source,
    _delete_all_rows,
    reset_all_state,
)


@pytest.fixture
def _episodic_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the episodic DB at tmp and create episodic + monitoring schema."""
    from openexecutive.memory import episodic
    from openexecutive.monitoring import store as monitoring_store

    db_path = tmp_path / "episodic.db"
    monkeypatch.setattr(episodic, "DB_PATH", db_path)
    episodic.initialize_db(db_path)
    monitoring_store.initialize_db(db_path)
    return db_path


def test_delete_clears_watchlist_and_signals_in_fk_order(
    _episodic_db: Path,
) -> None:
    """A watchlist row plus a signal that references it must both be wiped.

    Deleting ``external_signals`` before ``watchlist`` keeps the FK satisfied;
    if the tuple order were reversed this DELETE would raise an
    IntegrityError, so a green test also proves the ordering is correct.
    """
    from openexecutive.monitoring import store as ms
    from openexecutive.monitoring.models import Signal

    wl_id = ms.insert_watchlist_item(
        slug="tesla-fsd",
        signal_type="rss",
        target="https://example.com/feed",
        db_path=_episodic_db,
    )
    ms.insert_signal(
        Signal(
            watchlist_id=wl_id,
            source_kind="rss",
            source_external_id="evt-1",
            captured_at=datetime.now(UTC).isoformat(),
            normalized_summary="something happened",
            provenance_url="https://example.com/evt-1",
            dedup_key="evt-1",
        ),
        db_path=_episodic_db,
    )

    with sqlite3.connect(str(_episodic_db)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM watchlist").fetchone()[0] == 1
        assert (
            conn.execute("SELECT COUNT(*) FROM external_signals").fetchone()[0] == 1
        )

    cleared = _delete_all_rows(
        _episodic_db, ("external_signals", "watchlist")
    )

    assert cleared == {"external_signals": 1, "watchlist": 1}
    with sqlite3.connect(str(_episodic_db)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM watchlist").fetchone()[0] == 0
        assert (
            conn.execute("SELECT COUNT(*) FROM external_signals").fetchone()[0] == 0
        )


def test_reset_all_state_wipe_list_includes_monitoring_tables() -> None:
    """Guard against silently dropping the monitoring tables from reset.

    ``reset_all_state`` is an expensive async function (ChromaDB, Honcho,
    file I/O), so assert the table names appear in its source — the same
    cheap guard pattern used for the run/audit tables.
    """
    src = inspect.getsource(reset_all_state)
    for table in ("external_signals", "watchlist"):
        assert f'"{table}"' in src, (
            f"reset_all_state no longer mentions {table!r} — a reset will "
            "stop clearing the external-monitoring layer and the previous "
            "company's watchlist monitors will survive the reset."
        )


def test_apply_state_from_source_clears_monitoring_tables() -> None:
    """The shared load/unload path must clear the monitoring layer too.

    ``_apply_state_from_source`` backs both ``load_fixture`` and
    ``unload_fixture``; if it stops clearing these tables the watchlist
    leaks across fixture loads and into the restored user state.
    """
    src = inspect.getsource(_apply_state_from_source)
    for table in ("external_signals", "watchlist"):
        assert f'"{table}"' in src, (
            f"_apply_state_from_source no longer mentions {table!r} — fixture "
            "load/unload will stop clearing the watchlist."
        )


def test_apply_state_from_source_resets_research_skip_gate() -> None:
    """The shared load/unload path must reset the research skip-if-unchanged gate.

    Fixture load wipes profile/initiatives/watchlist but preserves audit_log;
    without clearing the research run-history rows the seeded
    watchlist_research_scan skips itself (the "no findings on a seeded run"
    bug). Behavioural coverage of the helper lives in
    test_executive_research_scheduler.py; here we guard the wiring on the heavy
    load path (same cheap source-grep guard used for the monitoring tables)."""
    src = inspect.getsource(_apply_state_from_source)
    assert "clear_research_run_history" in src, (
        "_apply_state_from_source no longer calls clear_research_run_history — "
        "a fixture reload within 24h will skip its seeded research scan and "
        "surface zero findings."
    )


# ── Derived per-company caches (same leak class as the watchlist above) ──────
#
# briefing_narrative and person_insights were wiped by NO path. Because /today
# serves them from cache and only regenerates in a BackgroundTask, loading a
# demo fixture over a live company rendered that company's real briefing
# narrative verbatim under the demo — on the surface most likely to be
# screen-shared. All three swapping paths now consume PER_CLIENT_CACHE_TABLES,
# and on the fixture path the wipe sits in _apply_state_from_source rather
# than in _seed_episodic_memory, which returns early without a memory.json.


def test_delete_clears_derived_caches_on_a_never_briefed_db(
    _episodic_db: Path,
) -> None:
    """The cache wipe must work against the live schema, including a cold DB.

    Behavioural, and deliberately routed through ``_delete_all_rows`` — the
    same helper the call site delegates to — for the reason this module's
    docstring gives: exercising ``_apply_state_from_source`` end to end would
    drag ChromaDB, Honcho and an ``app.state`` shim into a unit test.

    The cold-DB half is the regression the author hit: both caches CREATE
    TABLE lazily on first put, so a DB that has never served a briefing lacks
    them, and ``_delete_all_rows`` is not per-table existence-guarded. The
    call site initializes both schemas first; this proves that is sufficient
    and that the DELETE then really empties warm rows.
    """
    from openexecutive.briefing import narrative_cache
    from openexecutive.cli.fixture_loader import PER_CLIENT_CACHE_TABLES
    from openexecutive.people import insights_cache

    # Cold: neither table exists yet on this DB.
    with sqlite3.connect(str(_episodic_db)) as conn:
        present = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN (?, ?)",
                PER_CLIENT_CACHE_TABLES,
            )
        }
    assert present == set(), (
        "these caches are expected to be created lazily; if they now ship in "
        "the base episodic schema the initialize_db calls at the wipe site "
        "are redundant, but the wipe itself still must not regress."
    )
    narrative_cache.initialize_db(_episodic_db)
    insights_cache.initialize_db(_episodic_db)
    _delete_all_rows(_episodic_db, PER_CLIENT_CACHE_TABLES)  # must not raise

    # Warm: rows written by the outgoing company are actually removed.
    narrative_cache.put(
        narrative_cache.BriefingNarrative(
            scope="principal",
            input_hash="outgoing",
            narrative_text="**Real client narrative** — must not reach a demo.",
            generated_at=datetime.now(UTC).isoformat(),
        ),
        db_path=_episodic_db,
    )
    insights_cache.put(
        insights_cache.PersonInsight(
            person_id=1,
            input_hash="outgoing",
            insight_text="Real client founder note.",
            generated_at=datetime.now(UTC).isoformat(),
        ),
        db_path=_episodic_db,
    )
    assert narrative_cache.get("principal", db_path=_episodic_db) is not None
    assert insights_cache.get(1, db_path=_episodic_db) is not None

    _delete_all_rows(_episodic_db, PER_CLIENT_CACHE_TABLES)

    assert narrative_cache.get("principal", db_path=_episodic_db) is None
    assert insights_cache.get(1, db_path=_episodic_db) is None


def test_fixture_path_wipes_caches_unconditionally() -> None:
    """The fixture-path wipe must not sit behind ``memory.json``.

    ``_seed_episodic_memory`` returns early when the fixture has no
    ``memory.json``, when that file will not parse, and when the DB is
    missing. ``load_fixture`` only requires ``profile.yaml``, so a fixture
    with no usable ``memory.json`` still swaps the company — and a wipe
    placed inside the seeder is skipped on exactly those loads, leaving the
    outgoing company's narrative to be served under the incoming one.

    So the wipe belongs in ``_apply_state_from_source``, beside the
    unconditional watchlist wipe, and must stay out of the seeder. This pins
    both halves; the sibling test above proves the deletion itself works.
    """
    from openexecutive.cli.fixture_loader import (
        PER_CLIENT_CACHE_TABLES,
        _seed_episodic_memory,
    )

    assert PER_CLIENT_CACHE_TABLES == ("briefing_narrative", "person_insights")

    assert "PER_CLIENT_CACHE_TABLES" in inspect.getsource(_apply_state_from_source), (
        "_apply_state_from_source no longer wipes the derived caches — fixture "
        "load/unload will serve the outgoing company's briefing narrative "
        "under the incoming one."
    )
    assert "PER_CLIENT_CACHE_TABLES" not in inspect.getsource(_seed_episodic_memory), (
        "the derived-cache wipe moved back into _seed_episodic_memory, which "
        "returns early on a fixture with no readable memory.json — those loads "
        "would swap the company and skip the wipe."
    )


def test_reset_and_slot_switch_consume_the_shared_cache_constant() -> None:
    """The other two company-swapping paths must reference the one constant.

    The original bug was three hand-maintained table lists over one DB: the
    fix landed in one and the leak stayed live in the other two. Source-grep
    for the heavy async ``reset_all_state`` (the same cheap guard the
    monitoring tables use above) and for the shared constant in the slot
    wipe list.
    """
    from openexecutive.cli.fixture_loader import PER_CLIENT_CACHE_TABLES
    from openexecutive.clients.slots import _BLANK_WIPE_TABLES

    assert "PER_CLIENT_CACHE_TABLES" in inspect.getsource(reset_all_state), (
        "reset_all_state no longer consumes PER_CLIENT_CACHE_TABLES — a factory "
        "reset will leave the previous company's cached briefing narrative."
    )

    for table in PER_CLIENT_CACHE_TABLES:
        assert table in _BLANK_WIPE_TABLES, (
            f"{table!r} dropped out of the client-slot wipe list — switching "
            "into a blank/seed slot will leak the previous client's cache."
        )
