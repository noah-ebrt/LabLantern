from sqlalchemy import inspect, text

from app.db import init_db, make_engine


def columns(engine, table):
    return {c["name"] for c in inspect(engine).get_columns(table)}


def test_init_db_adds_new_columns_to_an_existing_old_database(tmp_path):
    engine = make_engine(tmp_path / "old.db")
    # Schema wie nach dem alten Stand: scan_runs ohne die neuen Spalten
    with engine.begin() as c:
        c.execute(text(
            "CREATE TABLE scan_runs (id INTEGER PRIMARY KEY, started_at DATETIME, finished_at DATETIME,"
            " status VARCHAR, canary_status VARCHAR, canary_details TEXT, summary_counts TEXT)"
        ))
        c.execute(text("INSERT INTO scan_runs (id, status, canary_status, summary_counts) VALUES (7, 'success', 'ok', '{}')"))
    assert "trigger" not in columns(engine, "scan_runs")

    init_db(engine)

    assert {"trigger", "db_status", "error", "notify_status"} <= columns(engine, "scan_runs")
    with engine.connect() as c:
        row = c.execute(text("SELECT id, status, trigger, db_status FROM scan_runs")).one()
    assert row == (7, "success", "manual", "{}")


def test_init_db_is_idempotent(tmp_path):
    engine = make_engine(tmp_path / "x.db")
    init_db(engine)
    init_db(engine)
    assert "last_seen_run_id" in columns(engine, "findings")


def test_new_tables_are_created(tmp_path):
    engine = make_engine(tmp_path / "x.db")
    init_db(engine)
    assert "system_scan_results" in inspect(engine).get_table_names()


# ---------- Einstellungen: von „nur Anthropic“ auf mehrere KI-Anbieter ----------

def settings_session(tmp_path):
    from sqlalchemy.orm import sessionmaker

    engine = make_engine(tmp_path / "x.db")
    init_db(engine)
    return sessionmaker(engine, expire_on_commit=False)


def test_migration_keeps_choices(tmp_path):
    from app.aiproviders import migrate_ai_settings
    from app.models import Setting, put_setting, setting

    models = {"at": 123.0, "items": [{"id": "claude-haiku-5-5", "name": "Haiku", "created_at": ""}]}
    with settings_session(tmp_path)() as s:
        put_setting(s, "claude.model", "claude-haiku-5-5")
        put_setting(s, "earlywarning.research", {"enabled": False, "model": "claude-sonnet-5-5"})
        put_setting(s, "ai.models", models)
        put_setting(s, "ai.last_used", {"at": "2026-10-29T10:00:00+00:00", "model": "claude-haiku-5-5", "ok": True})
        s.commit()
        assert migrate_ai_settings(s) is True
        s.commit()
        assert setting(s, "ai.tasks") == {"classify": "anthropic:claude-haiku-5-5",
                                          "research": "anthropic:claude-sonnet-5-5",
                                          "verify": "anthropic:claude-sonnet-5-5"}
        assert setting(s, "earlywarning.research") == {"enabled": False, "verify": False}
        assert setting(s, "ai.models.anthropic") == models
        assert setting(s, "ai.last_used.anthropic") == {"at": "2026-10-29T10:00:00+00:00", "task": "classify",
                                                         "model": "claude-haiku-5-5", "ok": True}
        assert s.get(Setting, "ai.models") is None and s.get(Setting, "ai.last_used") is None
        assert setting(s, "claude.model") == "claude-haiku-5-5"   # die alte Wahl bleibt für configdoc stehen


def test_migration_without_old_choices_means_automatic(tmp_path):
    from app.aiproviders import migrate_ai_settings
    from app.models import setting

    with settings_session(tmp_path)() as s:   # frische Installation: keine alten Schlüssel
        assert migrate_ai_settings(s) is True
        s.commit()
        assert setting(s, "ai.tasks") == {"classify": "", "research": "", "verify": ""}
        assert setting(s, "earlywarning.research") == {"enabled": True, "verify": True}
        assert setting(s, "ai.models.anthropic") is None and setting(s, "ai.last_used.anthropic") is None


def test_migration_keeps_research_on_with_only_a_classify_model(tmp_path):
    from app.aiproviders import migrate_ai_settings
    from app.models import put_setting, setting

    with settings_session(tmp_path)() as s:
        put_setting(s, "claude.model", "claude-haiku-5-5")
        put_setting(s, "earlywarning.research", {"enabled": True, "model": ""})
        migrate_ai_settings(s)
        assert setting(s, "ai.tasks") == {"classify": "anthropic:claude-haiku-5-5", "research": "", "verify": ""}
        assert setting(s, "earlywarning.research") == {"enabled": True, "verify": True}


def test_migration_is_idempotent(tmp_path):
    from app.aiproviders import migrate_ai_settings
    from app.models import Setting, put_setting
    from sqlalchemy import select

    with settings_session(tmp_path)() as s:
        put_setting(s, "claude.model", "claude-haiku-5-5")
        put_setting(s, "ai.last_used", {"at": "x", "model": "claude-haiku-5-5", "ok": True})
        assert migrate_ai_settings(s) is True
        s.commit()
        before = {r.key: r.value for r in s.scalars(select(Setting))}
        put_setting(s, "claude.model", "claude-opus-5-5")   # eine spätere Änderung des alten Schlüssels zählt nicht mehr
        s.commit()
        assert migrate_ai_settings(s) is False
        s.commit()
        after = {r.key: r.value for r in s.scalars(select(Setting))}
    assert after == {**before, "claude.model": '"claude-opus-5-5"'}


def test_the_app_migrates_at_startup_and_keeps_working(env):
    from app.models import setting

    ctx = env.app.state.ctx
    with ctx.session_factory() as s:
        assert setting(s, "ai.tasks") == {"classify": "", "research": "", "verify": ""}
