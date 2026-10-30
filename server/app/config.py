import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    hostnames: list[str] = field(default_factory=lambda: ["localhost"])
    secure_cookies: bool = True
    session_ttl: int = 12 * 3600
    web_dir: Path | None = None
    master_key_file: Path | None = None
    worker_token_file: Path | None = None
    ca_url: str | None = None  # woher der Server das Wurzelzertifikat seiner TLS-Schicht (Caddy) holt
    public_port: int = 8443
    max_agent_body: int = 64 * 1024 * 1024
    anthropic_base_url: str = "https://api.anthropic.com"
    agent_version: str = "0.5.0"  # Version der ausgelieferten Agent-Binaries
    agent_releases_dir: Path | None = None  # signierte Agent-Releases aus agent-sign (latest.json, release.pub)
    agent_dir: Path | None = None  # enthält vulnwatch-agent-linux-{amd64,arm64}

    @property
    def master_key_path(self) -> Path:
        return self.master_key_file or self.data_dir / "master.key"

    @property
    def worker_token_path(self) -> Path:
        return self.worker_token_file or self.data_dir / "worker.token"

    @classmethod
    def from_env(cls) -> "Settings":
        hostnames = [h.strip() for h in os.environ.get("VULNWATCH_HOSTNAMES", "localhost").split(",") if h.strip()]
        if "localhost" not in hostnames:
            hostnames.append("localhost")  # der Healthcheck im Container prüft gegen diesen Namen
        web_dir = os.environ.get("VULNWATCH_WEB_DIR")
        key_file = os.environ.get("VULNWATCH_MASTER_KEY_FILE")
        worker_token = os.environ.get("VULNWATCH_WORKER_TOKEN_FILE")
        agent_dir = os.environ.get("VULNWATCH_AGENT_DIR")
        return cls(
            data_dir=Path(os.environ.get("VULNWATCH_DATA_DIR", "/data")),
            hostnames=hostnames,
            web_dir=Path(web_dir) if web_dir else None,
            master_key_file=Path(key_file) if key_file else None,
            worker_token_file=Path(worker_token) if worker_token else None,
            ca_url=os.environ.get("VULNWATCH_CA_URL") or None,
            public_port=int(os.environ.get("VULNWATCH_PUBLIC_PORT", "8443")),
            agent_dir=Path(agent_dir) if agent_dir else None,
            agent_version=os.environ.get("VULNWATCH_AGENT_VERSION", "0.5.0"),
            agent_releases_dir=Path(releases) if (releases := os.environ.get("VULNWATCH_AGENT_RELEASES_DIR")) else None,
            anthropic_base_url=os.environ.get("VULNWATCH_ANTHROPIC_BASE_URL", "https://api.anthropic.com"),
        )
