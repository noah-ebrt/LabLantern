"""Additive Schema-Nachrüstung für SQLite: fehlende Spalten werden ergänzt, nichts wird gelöscht oder umgebaut.
Alembic (PLAN Abschnitt 3a) ist weiter offen; für reine Spaltenergänzungen genügt das bis dahin."""
from sqlalchemy import Engine, inspect, text

from .db import Base


def add_missing_columns(engine: Engine) -> None:
    insp = inspect(engine)
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if not insp.has_table(table.name):
                continue
            have = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name in have:
                    continue
                default = col.server_default
                if col.primary_key or (not col.nullable and default is None):
                    raise RuntimeError(
                        f"Column {table.name}.{col.name} cannot be added (NOT NULL without server_default)"
                    )
                ddl = f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {col.type.compile(engine.dialect)}'
                if default is not None:
                    ddl += " DEFAULT '" + str(default.arg).replace("'", "''") + "'"
                if not col.nullable:
                    ddl += " NOT NULL"
                conn.execute(text(ddl))
            for index in table.indexes:
                index.create(conn, checkfirst=True)
