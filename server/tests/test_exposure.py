"""Internet-Erreichbarkeit aus mehreren Quellen (PLAN-extensions A4): eine Schnittstelle, Fehler sichtbar."""
import time

from app import exposure, fritzbox
from app.connectors import NPM_CONFIG, NPM_SECRET, NPM_STATE
from app.containers import HOST
from app.coverage import calculate_coverage_matrix
from app.models import put_setting, setting
from tests.test_scan_flow import ctx, make_system  # noqa: F401 (Fixture)


def test_merge_two_sources_via_texts(ctx):
    sid = make_system(ctx)
    now = time.time()
    with ctx.session_factory() as s:
        put_setting(s, NPM_STATE, {"configured": True, "ok": True, "at": now, "exposed": {str(sid): ["vw"]},
                                   "via": {str(sid): {"vw": ["vw.example.org"]}}})
        put_setting(s, fritzbox.FRITZ_STATE, {"configured": True, "ok": True, "at": now,
                                              "exposed": {str(sid): ["vw", HOST]},
                                              "via": {str(sid): {"vw": ["port 443"], HOST: ["port 22"]}}})
        s.commit()
        assert exposure.exposure_via(s) == {sid: {"vw": ["via NPM: vw.example.org", "via FRITZ!Box: port 443"],
                                                  HOST: ["via FRITZ!Box: port 22"]}}
        # ohne gespeicherte Einzelheiten (Zustand von vor A4): nur die Quelle
        put_setting(s, NPM_STATE, {"configured": True, "ok": True, "at": now, "exposed": {str(sid): ["vw"]}})
        s.commit()
        assert exposure.exposure_via(s)[sid]["vw"][0] == "via NPM"


def test_failed_source_is_matrix_error(ctx, monkeypatch):
    sid = make_system(ctx)
    with ctx.session_factory() as s:
        put_setting(s, NPM_CONFIG, {"url": "http://npm.lan:81", "email": "a@b.c", "system_id": None})
        put_setting(s, NPM_STATE, {"configured": True, "ok": True, "at": time.time() - 3600,
                                   "exposed": {str(sid): ["vw"]}})
        s.commit()
    ctx.secrets.set(NPM_SECRET, "pw")

    def boom(*a):
        raise RuntimeError("unexpected answer")

    monkeypatch.setattr("app.connectors.fetch_npm", boom)
    exposure.refresh_all(ctx)
    with ctx.session_factory() as s:
        state = setting(s, NPM_STATE)
        assert state["ok"] is False and "unexpected answer" in state["error"]
        assert state["exposed"] == {str(sid): ["vw"]}   # letzte Zuordnung bleibt
        rows = calculate_coverage_matrix(s)["exposure_sources"]
    assert [(r["key"], r["status"]) for r in rows] == [("npm", "fehler")]
    assert "unexpected answer" in rows[0]["detail"] and "last known" in rows[0]["detail"]


def test_stale_source_is_error(ctx):
    with ctx.session_factory() as s:
        put_setting(s, fritzbox.FRITZ_STATE, {"configured": True, "ok": True, "at": time.time() - 27 * 3600,
                                              "exposed": {}})
        s.commit()
        rows = exposure.source_rows(s, time.time())
    assert [(r["key"], r["status"]) for r in rows] == [("fritzbox", "fehler")]
    assert "27 h" in rows[0]["detail"]


def test_ok_source_counts_as_checked(ctx):
    with ctx.session_factory() as s:
        put_setting(s, fritzbox.FRITZ_STATE, {"configured": True, "ok": True, "at": time.time(), "exposed": {},
                                              "unmatched": [{"forward": "x"}]})
        s.commit()
        m = calculate_coverage_matrix(s)
    row = m["exposure_sources"][0]
    assert (row["status"], row["label"], row["unmatched"]) == ("ok", "FRITZ!Box", 1)
    assert m["total_checks"] == 1 and m["ok_checks"] == 1
