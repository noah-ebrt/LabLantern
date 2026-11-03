FROM node:22-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d AS web
WORKDIR /web
COPY web/package.json web/package-lock.json web/.npmrc ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY server/requirements.txt ./
RUN pip install --require-hashes -r requirements.txt
COPY server/app ./app
COPY --from=web /web/dist ./web
# /data: Datenbank und SBOMs. /keys: Master-Schlüssel (nur der Server). /worker_auth: Token des Workers.
# /agent-releases: signierte Agent-Pakete aus agent-sign (nur lesend eingehängt).
RUN useradd --system --uid 10001 --no-create-home lablantern \
 && mkdir /data /keys /worker_auth /agent-releases && chown 10001:10001 /data /keys /worker_auth /agent-releases
USER 10001:10001
ENV LABLANTERN_DATA_DIR=/data LABLANTERN_WEB_DIR=/app/web \
    LABLANTERN_MASTER_KEY_FILE=/keys/master.key LABLANTERN_WORKER_TOKEN_FILE=/worker_auth/worker.token \
    LABLANTERN_AGENT_RELEASES_DIR=/agent-releases
EXPOSE 8000 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
  CMD ["python", "-c", "import os,urllib.request as u; port=os.environ.get('LABLANTERN_PORT','8000'); proto='http' if os.environ.get('LABLANTERN_PLAIN_HTTP')=='1' else 'https'; u.urlopen(f'{proto}://localhost:{port}/api/state', timeout=4)"]
CMD ["python", "-m", "app"]
