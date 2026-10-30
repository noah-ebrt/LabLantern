"""Image-Aktualität (PLAN Abschnitt 14: Ersatz für image-check). Übernommen aus `image-check.py`: anonymer
OCI-Registry-Client, Digest des Tags, neuere Versionen. Eingaben kommen aus dem Agenten-Inventar statt über SSH.

Vergleich: Digest des Tags in der Registry gegen die RepoDigests des laufenden Images. Ältere Agenten (vor 0.13)
schicken keine RepoDigests; dann wird die Config-Digest des passenden Manifests mit der Image-ID verglichen.
Das braucht zwei GET-Anfragen, die Docker Hub als Pull zählt: deshalb ein Budget je Durchgang, ein dauerhafter
Cache (Digests ändern sich nie), und was nicht mehr ins Budget passt, ist „offen“ statt falsch."""
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

TIMEOUT = 20
MAX_TAG_PAGES = 30
CACHE_DAYS = 7
NEWEST_CANDIDATES = 15   # version tags tried to name the newest image
RUNNING_CANDIDATES = 60  # version tags tried to name the running image
DOCKERHUB = "registry-1.docker.io"
DOCKERHUB_GET_BUDGET = 8   # Manifest-GETs je Durchgang (anonym: Pull-Limit von Docker Hub)
CLEAN_VERSION = re.compile(r'^v?\d+(\.\d+){1,3}$')  # 12.2.0, v3.15.0, 2026.9.2
UNSTABLE = re.compile(r'rc|beta|alpha|dev|nightly|test|preview|edge|snapshot|pr-|sha|unstable|next', re.I)

MANIFEST_TYPES = ', '.join([
    'application/vnd.oci.image.index.v1+json',
    'application/vnd.docker.distribution.manifest.list.v2+json',
    'application/vnd.docker.distribution.manifest.v2+json',
    'application/vnd.oci.image.manifest.v1+json',
])


class BudgetExhausted(Exception):
    pass


def parse_ref(ref):
    """'lscr.io/linuxserver/plex:latest' -> ('lscr.io', 'linuxserver/plex', 'latest')."""
    if '@' in ref:
        return None  # pinned by digest, nothing to compare
    name, tag = ref, 'latest'
    if ':' in ref.rsplit('/', 1)[-1]:
        name, tag = ref.rsplit(':', 1)
    first, _, rest = name.partition('/')
    if rest and first in ('docker.io', 'index.docker.io'):   # Podman nennt Docker-Hub-Images voll qualifiziert
        name, first, rest = rest, '', ''
    if rest and ('.' in first or ':' in first or first == 'localhost'):
        return first, rest, tag
    return DOCKERHUB, name if '/' in name else 'library/' + name, tag


class Registry:
    """Minimal anonymous OCI distribution client (bearer token challenge)."""

    def __init__(self, cache_dir: Path | None = None, opener=urllib.request.urlopen):
        self.tokens = {}
        self.tag_cache = {}
        self.configs = {}    # Manifest-Digest -> {arch: Config-Digest}; unveränderlich
        self.budget = {DOCKERHUB: DOCKERHUB_GET_BUDGET}
        self.cache_dir = cache_dir
        self.opener = opener
        if cache_dir:
            try:
                cutoff = time.time() - CACHE_DAYS * 86400
                with open(cache_dir / 'tag-digests.json') as f:
                    self.tag_cache = {k: v for k, v in json.load(f).items() if v[1] > cutoff}
            except (OSError, ValueError):
                pass
            try:
                with open(cache_dir / 'configs.json') as f:
                    self.configs = json.load(f)
            except (OSError, ValueError):
                pass

    def save_cache(self):
        if not self.cache_dir:
            return
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        for name, data in (('tag-digests.json', self.tag_cache), ('configs.json', dict(list(self.configs.items())[-5000:]))):
            tmp = self.cache_dir / (name + '.tmp')
            with open(tmp, 'w') as f:
                json.dump(data, f)
            os.replace(tmp, self.cache_dir / name)

    def tag_digest(self, registry, repo, tag):
        """Digest of a version tag, cached: version tags rarely move."""
        key = f'{registry}/{repo}:{tag}'
        if key not in self.tag_cache:
            self.tag_cache[key] = (self.digest(registry, repo, tag), time.time())
        return self.tag_cache[key][0]

    def version_of(self, registry, repo, digests, tags, limit, hint='', family=None):
        """The highest stable version tag whose image is one of `digests`, or ''.

        Names what ':latest' (or the running image) actually is, e.g. 2.33.1.
        HEAD requests only, they do not count against Docker Hub pull limits.
        """
        def by_version(t):
            return tuple(map(int, re.findall(r'\d+', t))), -len(t)
        # The image label is only a hint: it counts once the registry confirms the digest
        # (labels often carry the base image version, gitlab-runner says 24.04).
        for tag in (hint, 'v' + hint) if hint else ():
            if tag in tags:
                try:
                    if self.tag_digest(registry, repo, tag) in digests:
                        return tag
                except urllib.error.HTTPError:
                    pass
        if family:  # '7-alpine' -> only 7.x.y-alpine
            tags = [t for t in tags if family.match(t)]
        clean = sorted((t for t in tags if CLEAN_VERSION.match(t)), key=by_version, reverse=True)
        loose = sorted((t for t in tags if re.search(r'\d', t) and not UNSTABLE.search(t)
                        and not CLEAN_VERSION.match(t)), key=by_version, reverse=True)
        for candidates in (clean, loose):
            for tag in candidates[:limit]:
                try:
                    if self.tag_digest(registry, repo, tag) in digests:
                        return tag
                except urllib.error.HTTPError:
                    continue
        return ''

    def _open(self, method, url, registry, repo, accept=None):
        headers = {'Accept': accept} if accept else {}
        token = self.tokens.get((registry, repo))
        if token:
            headers['Authorization'] = 'Bearer ' + token
        try:
            return self.opener(urllib.request.Request(url, method=method, headers=headers), timeout=TIMEOUT)
        except urllib.error.HTTPError as e:
            challenge = e.headers.get('WWW-Authenticate', '') if e.headers else ''
            if e.code != 401 or token or not challenge.lower().startswith('bearer'):
                raise
            params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
            query = {k: v for k, v in params.items() if k in ('service', 'scope')}
            query.setdefault('scope', f'repository:{repo}:pull')
            realm = params['realm'] + '?' + urllib.parse.urlencode(query)
            if not realm.startswith('https://'):
                raise
            with self.opener(urllib.request.Request(realm), timeout=TIMEOUT) as r:
                body = json.load(r)
            self.tokens[(registry, repo)] = body.get('token') or body.get('access_token')
            return self._open(method, url, registry, repo, accept)

    def digest(self, registry, repo, tag):
        url = f'https://{registry}/v2/{repo}/manifests/{tag}'
        with self._open('HEAD', url, registry, repo, MANIFEST_TYPES) as r:
            digest = r.headers.get('Docker-Content-Digest')
        if digest:
            return digest
        with self._get(url, registry, repo) as r:
            return 'sha256:' + hashlib.sha256(r.read()).hexdigest()

    def _get(self, url, registry, repo):
        if registry in self.budget:
            if self.budget[registry] <= 0:
                raise BudgetExhausted(registry)
            self.budget[registry] -= 1
        return self._open('GET', url, registry, repo, MANIFEST_TYPES)

    def config_digest(self, registry, repo, digest, arch):
        """Config-Digest (= Image-ID beim klassischen Docker-Speicher) des Manifests für `arch`."""
        known = self.configs.get(digest, {})
        if arch in known:
            return known[arch]
        url = f'https://{registry}/v2/{repo}/manifests/{digest}'
        with self._get(url, registry, repo) as r:
            doc = json.loads(r.read(4_000_000))
        if 'manifests' in doc:   # Index: passende Plattform suchen
            match = next((m['digest'] for m in doc['manifests'] if (m.get('platform') or {}).get('os') == 'linux'
                          and (m.get('platform') or {}).get('architecture') == arch), None)
            if not match:
                result = ''
            else:
                with self._get(f'https://{registry}/v2/{repo}/manifests/{match}', registry, repo) as r:
                    result = (json.loads(r.read(4_000_000)).get('config') or {}).get('digest', '')
        else:
            result = (doc.get('config') or {}).get('digest', '')
        self.configs[digest] = {**known, arch: result}
        return result

    def tags(self, registry, repo):
        url = f'https://{registry}/v2/{repo}/tags/list?n=1000'
        tags = []
        for _ in range(MAX_TAG_PAGES):
            with self._open('GET', url, registry, repo) as r:
                tags += json.load(r).get('tags') or []
                link = r.headers.get('Link', '')
            m = re.search(r'<([^>]+)>;\s*rel="next"', link)
            if not m:
                break
            url = urllib.parse.urljoin(url, m.group(1))
            if not url.startswith(f'https://{registry}/'):
                break
        return tags


def newer_version(tag, tags):
    """Highest tag with the same shape as `tag` and a higher version, or ''.

    '19.4.1-ce.0' only compares with tags like 'N.N.N-ce.N', so release
    candidates or other variants never count as newer.
    """
    numbers = re.findall(r'\d+', tag)
    if not numbers:
        return ''
    shape = re.sub(r'\d+', '#', tag)
    current = tuple(map(int, numbers))
    best = max(((tuple(map(int, re.findall(r'\d+', t))), t) for t in tags
                if re.sub(r'\d+', '#', t) == shape), default=None)
    return best[1] if best and best[0] > current else ''


def check(ref, local_digests, image_id, arch, label_version, registry, cache):
    """(status, running_version, newest_version, detail) für eine Image-Referenz.
    status: current, newer-version, outdated, local, unknown (Fehler), pending (Budget, nächster Durchgang)."""
    if ref.startswith('sha256:') or not ref:
        return 'unknown', '', '', 'container runs an untagged image (tag moved elsewhere): recreate it'
    parsed = parse_ref(ref)
    if not parsed:
        return 'current', label_version, '', 'pinned by digest'
    if parsed[0] == 'localhost':   # Podmans lokale Builds: es gibt keine Registry zum Vergleichen
        return 'local', '', '', 'built locally (localhost/), no version check'
    if ref not in cache:
        try:
            remote = registry.digest(*parsed)
            tags = registry.tags(parsed[0], parsed[1])
            if re.search(r'\d', parsed[2]):
                newer = newer_version(parsed[2], tags)
            else:  # 'latest' and friends: name the version behind the tag
                newer = registry.version_of(parsed[0], parsed[1], {remote}, tags, NEWEST_CANDIDATES)
            cache[ref] = (remote, newer, '', tags)
        except urllib.error.HTTPError as e:
            if parsed[0] == DOCKERHUB and e.code in (401, 404):
                # Docker Hub answers 401 for repositories that do not exist
                cache[ref] = ('local', '', 'not on Docker Hub, built locally', [])
            elif e.code == 429:   # Rate-Limit der Registry: nächster Durchgang, kein Fehler
                cache[ref] = ('pending', '', f'registry {parsed[0]} rate limit (429), checked in the next pass', [])
            elif e.code in (401, 403):
                cache[ref] = (None, '', f'registry {parsed[0]} refuses anonymous access ({e.code})', [])
            else:
                cache[ref] = (None, '', f'registry {parsed[0]}: HTTP {e.code}', [])
        except BudgetExhausted:
            cache[ref] = ('pending', '', 'Docker Hub request budget used up, checked in the next pass', [])
        except Exception as e:  # noqa: BLE001 - one bad registry must not stop the run
            cache[ref] = (None, '', f'{type(e).__name__}: {e}'[:200], [])
    remote, newer, error, tags = cache[ref]
    # Ohne Bestätigung durch die Registry keine laufende Version nennen: Labels tragen oft die Version des
    # Basis-Images (gitlab-ce sagt 24.04), und Frühwarnung/EOL würden damit falsch vergleichen.
    if remote is None:
        return 'unknown', '', '', error
    if remote in ('local', 'pending'):
        return remote, '', '', error
    local = set(local_digests)
    if not local:
        if image_id == remote:   # containerd-Speicher: Image-ID ist der Index-Digest
            local = {remote}
        else:
            try:
                if registry.config_digest(parsed[0], parsed[1], remote, arch) == image_id:
                    local = {remote}
            except BudgetExhausted:
                return 'pending', '', '', 'Docker Hub request budget used up, checked in the next pass'
            except (urllib.error.URLError, OSError, ValueError, KeyError) as e:
                return 'unknown', '', '', f'manifest lookup failed: {type(e).__name__}'
    tag = parsed[2]
    if re.search(r'\d', tag) and remote in local:
        running = tag
    elif local:
        # No image label fallback here: labels often carry the base image's version
        # (gitlab-runner says 24.04, the Ubuntu release).
        family = None
        m = re.match(r'^(v?\d+(?:\.\d+)*)(.*)$', tag)
        if m:  # mutable version tag: 7-alpine -> 7.x.y-alpine, 3.11-slim -> 3.11.x-slim
            family = re.compile('^' + re.escape(m.group(1)) + r'(?:\.\d+)*' + re.escape(m.group(2)) + '$')
        running = registry.version_of(parsed[0], parsed[1], local, tags, RUNNING_CANDIDATES,
                                      hint=label_version, family=family)
    else:
        running = ''
    if remote not in local:
        if not re.search(r'\d', tag) and newer and newer == running:
            newer = ''  # same version, only rebuilt (base image updates)
        return 'outdated', running, newer, 'newer image for this tag'
    if newer and re.search(r'\d', tag):
        return 'newer-version', running, newer, f'{newer} available'
    return 'current', running, newer if not re.search(r'\d', tag) else '', ''
