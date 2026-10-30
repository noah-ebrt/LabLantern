from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def make(tmp_path, with_web=True):
    web = tmp_path / "web"
    web.mkdir()
    (web / "index.html").write_text("<!doctype html><title>vulnwatch</title>")
    (web / "assets").mkdir()
    (web / "assets" / "app.js").write_text("console.log(1)")
    app = create_app(Settings(data_dir=tmp_path / "data", web_dir=web if with_web else None))
    return TestClient(app, base_url="https://testserver")


def test_root_serves_index(tmp_path):
    r = make(tmp_path).get("/")
    assert r.status_code == 200 and "<title>vulnwatch</title>" in r.text
    assert "default-src 'self'" in r.headers["content-security-policy"]


def test_assets_are_served(tmp_path):
    r = make(tmp_path).get("/assets/app.js")
    assert r.status_code == 200 and r.text == "console.log(1)"


def test_unknown_page_falls_back_to_index_for_the_spa(tmp_path):
    r = make(tmp_path).get("/einstellungen")
    assert r.status_code == 200 and "<title>vulnwatch</title>" in r.text


def test_unknown_api_path_is_404_not_index(tmp_path):
    r = make(tmp_path).get("/api/gibtsnicht")
    assert r.status_code == 404 and "<title>" not in r.text


def test_path_traversal_does_not_leak_files(tmp_path):
    (tmp_path / "geheim.txt").write_text("GEHEIM")
    c = make(tmp_path)
    for p in ("/../geheim.txt", "/%2e%2e/geheim.txt", "/assets/../../geheim.txt", "/..%2fgeheim.txt"):
        assert "GEHEIM" not in c.get(p).text, p


def test_without_web_dir_root_is_404(tmp_path):
    assert make(tmp_path, with_web=False).get("/").status_code == 404
