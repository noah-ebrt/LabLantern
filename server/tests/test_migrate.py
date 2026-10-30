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
