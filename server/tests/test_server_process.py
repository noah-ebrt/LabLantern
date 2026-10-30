import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.request

import pytest


@pytest.fixture
def running_server(tmp_path):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = {**os.environ, "VULNWATCH_DATA_DIR": str(tmp_path / "data"), "VULNWATCH_PORT": str(port),
           "VULNWATCH_HOSTNAMES": "localhost,127.0.0.1", "VULNWATCH_BIND": "127.0.0.1"}
    log = (tmp_path / "server.log").open("w")
    proc = subprocess.Popen([sys.executable, "-m", "app"], env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        ca = tmp_path / "data" / "pki" / "ca.pem"
        for _ in range(100):
            if proc.poll() is not None:
                raise AssertionError("Server beendet: " + (tmp_path / "server.log").read_text())
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                if ca.exists():
                    break
            except OSError:
                time.sleep(0.1)
        yield port, ca, tmp_path / "server.log"
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        log.close()


def test_server_speaks_tls_verified_by_its_own_ca_and_logs_token_and_fingerprint(running_server):
    port, ca, logfile = running_server
    ctx = ssl.create_default_context(cafile=str(ca))
    with urllib.request.urlopen(f"https://localhost:{port}/api/state", context=ctx, timeout=5) as r:
        assert r.status == 200 and b'"setup_complete":false' in r.read().replace(b" ", b"")
    log = logfile.read_text()
    assert "Setup token:" in log
    assert "CA fingerprint (SHA-256):" in log


def test_server_refuses_plain_http(running_server):
    port, _, _ = running_server
    with pytest.raises(Exception):
        urllib.request.urlopen(f"http://127.0.0.1:{port}/api/state", timeout=3).read()


def start(tmp_path, extra_env):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = {**os.environ, "VULNWATCH_DATA_DIR": str(tmp_path / "data"), "VULNWATCH_PORT": str(port),
           "VULNWATCH_HOSTNAMES": "localhost", "VULNWATCH_BIND": "127.0.0.1", **extra_env}
    log = (tmp_path / "server.log").open("w")
    proc = subprocess.Popen([sys.executable, "-m", "app"], env=env, stdout=log, stderr=subprocess.STDOUT)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    return proc, port, log


def test_plain_http_mode_behind_a_proxy_creates_no_pki_and_logs_no_misleading_fingerprint(tmp_path):
    proc, port, log = start(tmp_path, {"VULNWATCH_PLAIN_HTTP": "1"})
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/state", timeout=5) as r:
            assert r.status == 200
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        log.close()
    assert not (tmp_path / "data" / "pki").exists()
    text = (tmp_path / "server.log").read_text()
    assert "CA fingerprint" not in text and "Setup token:" in text


def test_master_key_and_worker_token_can_live_in_their_own_volumes(tmp_path):
    keys, auth = tmp_path / "keys", tmp_path / "auth"
    proc, port, log = start(tmp_path, {"VULNWATCH_PLAIN_HTTP": "1",
                                       "VULNWATCH_MASTER_KEY_FILE": str(keys / "master.key"),
                                       "VULNWATCH_WORKER_TOKEN_FILE": str(auth / "worker.token")})
    try:
        pass
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        log.close()
    assert (keys / "master.key").is_file() and (auth / "worker.token").is_file()
    assert not (tmp_path / "data" / "master.key").exists() and not (tmp_path / "data" / "worker.token").exists()


def test_forwarded_for_is_only_believed_from_the_proxy_address(tmp_path):
    """Wer Port 8000 direkt erreicht (Worker, Docker-Host), darf keine fremde Adresse vortäuschen: 20 Fehlversuche
    mit wechselndem X-Forwarded-For zählen alle für dieselbe echte Adresse, der 21. wird gesperrt."""
    import json as _json
    proc, port, log = start(tmp_path, {"VULNWATCH_PLAIN_HTTP": "1", "VULNWATCH_TRUSTED_PROXY": "10.255.255.2"})
    codes = []
    try:
        for i in range(21):
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/login", method="POST",
                data=_json.dumps({"username": f"u{i}", "password": "falsch-falsch", "totp_code": "000000"}).encode(),
                headers={"Content-Type": "application/json", "X-Forwarded-For": f"192.168.7.{i}"})
            try:
                urllib.request.urlopen(req, timeout=10)
            except urllib.error.HTTPError as e:
                codes.append(e.code)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        log.close()
    assert codes[:20] == [401] * 20 and codes[20] == 429
