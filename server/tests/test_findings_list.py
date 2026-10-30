from app.models import Finding
from tests.test_agent_api import activate


def test_findings_are_listed_critical_first_and_searchable(admin):
    env, client, h = admin
    sid, _ = activate(env, client, h)
    with env.app.state.ctx.session_factory() as s:
        s.add_all([
            Finding(system_id=sid, cve_id="CVE-1", severity="hoch", component="openssl", cvss_score=10.0),
            Finding(system_id=sid, cve_id="CVE-2", severity="kritisch", component="log4j", cvss_score=5.0, kev=True),
            Finding(system_id=sid, cve_id="CVE-3", severity="info", component="bash", cvss_score=9.9),
            Finding(system_id=sid, cve_id="CVE-4", severity="kritisch", component="zlib", cvss_score=9.0),
        ])
        s.commit()
    r = client.get("/api/findings")
    assert [f["cve_id"] for f in r.json()] == ["CVE-2", "CVE-4", "CVE-1", "CVE-3"]   # Stufe vor CVSS
    assert r.headers["X-Total-Count"] == "4"
    r = client.get("/api/findings", params={"q": "SSL"})
    assert [f["cve_id"] for f in r.json()] == ["CVE-1"] and r.headers["X-Total-Count"] == "1"
