"""Funde zurückstellen (PLAN-extensions A2): bis zu einem Datum, mit Grund, sichtbar im Bericht.

Ein Snooze endet von selbst, wenn das Datum erreicht ist, die CVE auf die KEV-Liste kommt, die Einstufung steigt oder
ein Fix erscheint, wo vorher keiner war. Ein zurückgestellter Fund zählt nicht für die Alarmstufe, wird aber weiter
gezählt und gezeigt; Finding.status "accepted" ist nur das Abbild der aktiven Snoozes."""
from datetime import datetime, timedelta

from sqlalchemy import select

from .freshness import DOCKERHUB, parse_ref
from .models import AuditLog, CoverageExclusion, Finding, Snooze, System
from .report import EN

MAX_SNOOZE_DAYS = 180
SCOPES = ("occurrence", "everywhere")
RANK = {"info": 0, "mittel": 1, "hoch": 2, "kritisch": 3}


def target_key(target: str) -> str:
    """Ziel ohne Tag und Digest: ein Snooze für ein Image übersteht dessen Updates."""
    if not target.startswith("image:"):
        return target
    ref = target[len("image:"):].split("@", 1)[0]
    parsed = parse_ref(ref) if ref else None
    if not parsed:
        return target
    registry = "docker.io" if parsed[0] in (DOCKERHUB, "docker.io", "index.docker.io") else parsed[0]
    return f"image:{registry}/{parsed[1]}"


def matches(snooze: Snooze, f: Finding) -> bool:
    if (snooze.cve_id, snooze.component) != (f.cve_id, f.component):
        return False
    return snooze.scope == "everywhere" or (snooze.system_id == f.system_id
                                            and snooze.target_key == target_key(f.target))


def end_reason(snooze: Snooze, f: Finding | None, now: datetime) -> str | None:
    if snooze.until <= now:
        return "expired"
    if f is None:
        return None
    if f.kev and not snooze.baseline_kev:
        return "now on the KEV list"
    if RANK.get(f.severity, 0) > RANK.get(snooze.baseline_severity, 0):
        return f"rating went up to {EN.get(f.severity, f.severity)}"
    if f.fixed_version and not snooze.baseline_has_fix:
        return "a fix is now available"
    return None


def _audit(s, now: datetime, actor: str, action: str, detail: str) -> None:
    s.add(AuditLog(ts=now.timestamp(), actor=actor, action=action, detail=detail))


def create_snooze(s, f: Finding, scope: str, until: datetime, reason: str, actor: str, now: datetime) -> Snooze:
    """Legt den Snooze an; der Ausgangsstand (Einstufung, KEV, Fix) kommt von allen Funden, die er abdeckt."""
    if scope not in SCOPES:
        raise ValueError(f"scope must be one of {', '.join(SCOPES)}")
    if not now < until <= now + timedelta(days=MAX_SNOOZE_DAYS):
        raise ValueError(f"until must be in the future and at most {MAX_SNOOZE_DAYS} days away")
    sn = Snooze(scope=scope, cve_id=f.cve_id, component=f.component, reason=reason, until=until, created_by=actor,
                created_at=now, system_id=f.system_id if scope == "occurrence" else None,
                target_key=target_key(f.target) if scope == "occurrence" else "")
    covered = [x for x in s.scalars(select(Finding).where(
        Finding.cve_id == f.cve_id, Finding.component == f.component, Finding.status.in_(("open", "accepted"))))
        if matches(sn, x)] or [f]
    sn.baseline_severity = max((x.severity for x in covered), key=lambda v: RANK.get(v, 0))
    sn.baseline_kev = any(x.kev for x in covered)
    sn.baseline_has_fix = any(x.fixed_version for x in covered)
    s.add(sn)
    _audit(s, now, actor, "finding.snoozed",
           f"{f.cve_id} in {f.component} ({scope}) until {until.date().isoformat()}: {reason}")
    s.flush()
    return sn


def apply_snoozes(s, now: datetime, system_id: int | None = None) -> list[dict]:
    """Beendet fällige Snoozes und setzt jeden offenen oder zurückgestellten Fund auf den passenden Status.
    Mit `system_id` nur die Funde dieses Systems (Connectoren). Gibt die beendeten Snoozes zurück."""
    s.flush()
    for ex in s.scalars(select(CoverageExclusion).where(CoverageExclusion.ended_at.is_(None),
                                                         CoverageExclusion.until <= now)):
        ex.ended_at, ex.end_reason = now, "expired"
        _audit(s, now, "system", "exclusion.ended", f"{ex.subject}: expired ({ex.reason})")
    active = list(s.scalars(select(Snooze).where(Snooze.ended_at.is_(None))))
    by_key: dict[tuple[str, str], list[Snooze]] = {}
    for sn in active:
        by_key.setdefault((sn.cve_id, sn.component), []).append(sn)
    q = select(Finding).where(Finding.status.in_(("open", "accepted")))
    if system_id is not None:
        q = q.where(Finding.system_id == system_id)
    findings = list(s.scalars(q))
    covered: dict[int, list[Finding]] = {sn.id: [] for sn in active}
    for f in findings:
        for sn in by_key.get((f.cve_id, f.component), ()):
            if matches(sn, f):
                covered[sn.id].append(f)
    ended = []
    names = {sid: name for sid, name in s.execute(select(System.id, System.name))}
    for sn in active:
        # Für "everywhere" beendet ein Auslöser auf einem System den Snooze überall (sicherer Weg)
        reason = end_reason(sn, None, now) or next(
            (r for r in (end_reason(sn, f, now) for f in covered[sn.id]) if r), None)
        if reason is None:
            continue
        sn.ended_at, sn.end_reason = now, reason
        _audit(s, now, "system", "snooze.ended", f"{sn.cve_id} in {sn.component}: {reason}")
        ended.append(_row(sn, names) | {"end_reason": reason})
    still = {sn.id: sn for sn in active if sn.ended_at is None}
    snoozed: dict[int, Snooze] = {}
    for sid, fs in covered.items():
        if sid in still:
            for f in fs:
                snoozed.setdefault(f.id, still[sid])
    for f in findings:
        sn = snoozed.get(f.id)
        if sn is not None:
            f.status, f.accepted_reason, f.accepted_until = "accepted", sn.reason, sn.until
        elif f.status == "accepted":
            f.status = "open"
    return ended


def _row(sn: Snooze, names: dict[int, str]) -> dict:
    return {"cve_id": sn.cve_id, "component": sn.component,
            "system_name": "all systems" if sn.system_id is None else names.get(sn.system_id, "?"),
            "reason": sn.reason}


def snoozed_summary(s) -> dict:
    """Für den Bericht: zurückgestellte Funde gesamt und je aktivem Snooze (mit Grund und Ablauf)."""
    names = {sid: name for sid, name in s.execute(select(System.id, System.name))}
    accepted = list(s.scalars(select(Finding).where(Finding.status == "accepted")))
    items = []
    for sn in s.scalars(select(Snooze).where(Snooze.ended_at.is_(None)).order_by(Snooze.until)):
        n = sum(1 for f in accepted if matches(sn, f))
        items.append(_row(sn, names) | {"until": sn.until.date().isoformat(), "findings": n})
    return {"count": len(accepted), "items": items}


def ended_since(s, since: datetime | None, now: datetime) -> list[dict]:
    """Seit dem letzten Lauf beendete Snoozes, auch die von Connectoren oder von Hand entfernten."""
    names = {sid: name for sid, name in s.execute(select(System.id, System.name))}
    start = since or now - timedelta(days=1)
    return [_row(sn, names) | {"end_reason": sn.end_reason}
            for sn in s.scalars(select(Snooze).where(Snooze.ended_at > start).order_by(Snooze.ended_at))]


def create_exclusion(s, subject: str, until: datetime, reason: str, actor: str, now: datetime) -> CoverageExclusion:
    if not now < until <= now + timedelta(days=MAX_SNOOZE_DAYS):
        raise ValueError(f"until must be in the future and at most {MAX_SNOOZE_DAYS} days away")
    if subject in active_exclusions(s, now):
        raise LookupError(f"{subject} is already excluded")
    ex = CoverageExclusion(subject=subject, reason=reason, until=until, created_by=actor, created_at=now)
    s.add(ex)
    _audit(s, now, actor, "exclusion.created", f"{subject} until {until.date().isoformat()}: {reason}")
    s.flush()
    return ex


def active_exclusions(s, now: datetime) -> dict[str, CoverageExclusion]:
    """Nur lesen: abgelaufene zählen nicht mehr; beendet (mit Audit) werden sie in apply_snoozes."""
    return {ex.subject: ex for ex in s.scalars(select(CoverageExclusion).where(
        CoverageExclusion.ended_at.is_(None), CoverageExclusion.until > now))}


def transfer_accepted_findings(s) -> int:
    """Einmalig beim Start: Funde aus dem alten "Accept" (ohne Snooze) bekommen einen Snooze für dieses Vorkommen."""
    from .models import utcnow
    now = utcnow()
    count = 0
    for f in s.scalars(select(Finding).where(Finding.status == "accepted")):
        if any(matches(sn, f) for sn in s.scalars(select(Snooze).where(
                Snooze.ended_at.is_(None), Snooze.cve_id == f.cve_id, Snooze.component == f.component))):
            continue
        until = f.accepted_until or now
        s.add(Snooze(scope="occurrence", cve_id=f.cve_id, component=f.component, system_id=f.system_id,
                     target_key=target_key(f.target), reason=f.accepted_reason or "accepted before snoozes existed",
                     until=until, created_by="migration", created_at=now, baseline_severity=f.severity,
                     baseline_kev=f.kev, baseline_has_fix=bool(f.fixed_version)))
        s.flush()
        count += 1
    return count
