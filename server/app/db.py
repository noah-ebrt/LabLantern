from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


def make_engine(path: Path) -> Engine:
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _pragmas(dbapi_conn, _record):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    return engine


def init_db(engine: Engine) -> None:
    from . import models  # noqa: F401  registriert die Tabellen

    Base.metadata.create_all(engine)
    from .migrate import add_missing_columns

    add_missing_columns(engine)
    from sqlalchemy.orm import Session

    from .snooze import transfer_accepted_findings

    with Session(engine) as s:   # einmalig: altes "Accept" wird zum Snooze
        if transfer_accepted_findings(s):
            s.commit()
