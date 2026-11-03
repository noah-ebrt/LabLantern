import logging
import os

import uvicorn

from .config import Settings
from .main import create_app
from .pki import ensure_pki, fingerprint_sha256

log = logging.getLogger("lablantern")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = Settings.from_env()
    plain_http = os.environ.get("LABLANTERN_PLAIN_HTTP", "0") in ("1", "true", "yes")
    ssl_kwargs: dict = {}
    if plain_http:
        # Hinter dem Proxy (Caddy): TLS und CA gehören dem Proxy, der Server spricht nur intern HTTP.
        log.info("Plain HTTP mode: TLS is terminated by the proxy")
        # Die echte Client-IP steht in X-Forwarded-For vom Proxy. Geglaubt wird der Kopfzeile nur von seiner festen
        # Adresse (compose.yaml, Netz „edge“): Worker, andere Container und der Docker-Host erreichen Port 8000 auch
        # direkt und könnten sonst jede Adresse vortäuschen (Rate-Limits, Audit-Log).
        ssl_kwargs = {"proxy_headers": True,
                      "forwarded_allow_ips": os.environ.get("LABLANTERN_TRUSTED_PROXY", "127.0.0.1")}
    else:
        # Eigenständig ohne Proxy: eigene CA und eigenes Server-Zertifikat.
        pki = ensure_pki(settings.data_dir / "pki", settings.hostnames)
        log.info("Certificate valid for: %s", ", ".join(settings.hostnames))
        log.info("CA fingerprint (SHA-256): %s", fingerprint_sha256(pki.ca_cert))
        ssl_kwargs = {"ssl_certfile": str(pki.server_cert), "ssl_keyfile": str(pki.server_key)}

    app = create_app(settings)
    uvicorn.run(
        app,
        host=os.environ.get("LABLANTERN_BIND", "0.0.0.0"),
        port=int(os.environ.get("LABLANTERN_PORT", "8000" if plain_http else "8443")),
        server_header=False,
        # Live-Ströme und Long-Polls enden nie von selbst: beim Stoppen nicht ewig auf sie warten
        timeout_graceful_shutdown=5,
        **ssl_kwargs,
    )


if __name__ == "__main__":
    main()
