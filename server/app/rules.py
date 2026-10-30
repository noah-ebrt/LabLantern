"""Feste Bewertungsregeln (PLAN Abschnitt 5). Reiner Code, keine Zufälle: gleiche Eingaben, gleiche Stufe."""

# Ohne CVSS-Wert (z. B. reine GHSA-Einträge) zählt das Etikett des Advisories,
# damit ein „Critical“ nicht still herabgestuft wird.
_LABEL_FALLBACK_CVSS = {"critical": 9.0, "high": 7.0}


def classify_severity(
    cvss_score: float,
    kev: bool,
    has_fix: bool,
    internet_exposed: bool = False,
    severity_label: str = "",
) -> str:
    """kritisch: KEV, oder CVSS >= 9,0 auf internet-erreichbarem Dienst.
    hoch: CVSS >= 7,0 internet-erreichbar mit Fix, oder CVSS >= 9,0 intern mit Fix.
    mittel: übrige Funde mit Fix.   info: Funde ohne Fix."""
    score = cvss_score if cvss_score > 0 else _LABEL_FALLBACK_CVSS.get(severity_label.lower(), 0.0)
    if kev:
        return "kritisch"
    if internet_exposed and score >= 9.0:
        return "kritisch"
    if not has_fix:
        return "info"
    if internet_exposed and score >= 7.0:
        return "hoch"
    if score >= 9.0:
        return "hoch"
    return "mittel"


def is_patch_step(current: str, newer: str) -> bool:
    """True, wenn sich nur die dritte Zahl unterscheidet (19.5.1-ce.0 -> 19.5.3-ce.0): ein Patch der gleichen Linie.
    Zweistellige Versionen (3.11 -> 3.15) sind ein Linienwechsel."""
    import re

    lead = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")
    a, b = lead.match(current or ""), lead.match(newer or "")
    return bool(a and b) and a.groups()[:2] == b.groups()[:2] and a.group(3) != b.group(3)


def classify_product(kind: str, patch_only: bool = False) -> str:
    """Produktstände (PLAN Abschnitt 5, Stufe „hoch“): Produkt nicht auf neuestem Patch, Linie EOL.
    outdated: gleicher Tag, neueres Image in der Registry (= neuester Patch fehlt).
    newer:    neuere Version verfügbar; nur ein Patch der gleichen Linie ist „hoch“, ein Linienwechsel „mittel“.
    eol:      Release-Linie ohne Sicherheitsupdates."""
    if kind in ("outdated", "eol"):
        return "hoch"
    if kind == "newer":
        return "hoch" if patch_only else "mittel"
    raise ValueError(f"unknown product finding kind: {kind}")


def classify_update(installed: str, latest: str) -> str:
    """Updates von TrueNAS und Home Assistant (Connectors): gleiche Linie (die ersten zwei Zahlen gleich, z. B.
    25.04.2.4 -> 25.04.2.5 oder 2026.10.1 -> 2026.10.3) ist ein fehlender Patch, „hoch“ wie bei Produktständen.
    Neue Linie oder unlesbare Version „mittel“."""
    import re

    line = re.compile(r"^v?(\d+)\.(\d+)")
    a, b = line.match(installed or ""), line.match(latest or "")
    return classify_product("newer", bool(a and b) and a.groups() == b.groups() and installed != latest)


def classify_appliance_alert(level: str) -> str | None:
    """Alarme von TrueNAS: CRITICAL und schlimmer „hoch“, ERROR und WARNING „mittel“, INFO/NOTICE kein Fund."""
    if level in ("CRITICAL", "ALERT", "EMERGENCY"):
        return "hoch"
    if level in ("ERROR", "WARNING"):
        return "mittel"
    return None


BACKUP_WARN_DAYS = 3    # automatische Backups laufen täglich: drei verpasste sind kein Zufall mehr
BACKUP_ALARM_DAYS = 7
DISK_WARN_PERCENT = 90
DISK_ALARM_PERCENT = 95
BATTERY_LOW_PERCENT = 15


def classify_backup_age(days: float | None) -> str | None:
    """Betriebs-Check (PLAN Abschnitt 14): Alter des letzten erfolgreichen Backups. None (nie) und über 7 Tage
    „hoch“, über 3 Tage „mittel“."""
    if days is None or days > BACKUP_ALARM_DAYS:
        return "hoch"
    if days > BACKUP_WARN_DAYS:
        return "mittel"
    return None


def classify_task_age(days: float, interval_days: float) -> str | None:
    """Betriebs-Check: letzter Erfolg einer geplanten Sicherung (Replikation, Cloud Sync, Rsync), gemessen am
    eigenen Takt. Täglich: über 3 Tage „mittel“, über 7 „hoch“ (wie classify_backup_age); wöchentlich 15 und 31."""
    if days > 4 * interval_days + 3:
        return "hoch"
    if days > 2 * interval_days + 1:
        return "mittel"
    return None


SCRUB_GRACE_DAYS = 7   # Scrub-Schwelle der Aufgabe (TrueNAS-Standard 35 Tage) plus eine Woche Spielraum


def classify_disk(percent: float) -> str | None:
    """Betriebs-Check: Plattenfüllstand. Ab 95 % „hoch“, ab 90 % „mittel“."""
    if percent >= DISK_ALARM_PERCENT:
        return "hoch"
    if percent >= DISK_WARN_PERCENT:
        return "mittel"
    return None


CERT_WARN_DAYS = 20   # NPM erneuert 30 Tage vorher: darunter klemmt die Erneuerung
CERT_ALARM_DAYS = 7


def classify_certificate(days_left: float) -> str | None:
    """Betriebs-Check (PLAN Abschnitt 14): Ablauf der TLS-Zertifikate öffentlicher Domains.
    None = in Ordnung; unter 20 Tagen „mittel“ (Erneuerung schlägt fehl), unter 7 Tagen oder abgelaufen „hoch“."""
    if days_left < CERT_ALARM_DAYS:
        return "hoch"
    if days_left < CERT_WARN_DAYS:
        return "mittel"
    return None


SEVERE_IMPACT = ("remote_code_execution", "privilege_escalation", "authentication_bypass")


def classify_early_warning(exploited: str, public_exploit: str, stated: str, impact: str = "unknown") -> str:
    """KI-Frühwarnung (PLAN Abschnitt 5): höchstens „hoch“, den Rest bestätigt der Scanner, sobald es Daten gibt.
    hoch: aktiv ausgenutzt, öffentlicher Exploit/PoC, als kritisch gemeldet, oder Codeausführung, Root-Rechte oder
          Umgehung der Anmeldung, solange die Quelle es nicht ausdrücklich niedriger einstuft (neue Lücken haben
          oft noch keine Einstufung).
    mittel: als hoch gemeldet.   info: alles andere."""
    if exploited == "yes" or public_exploit == "yes" or stated == "critical":
        return "hoch"
    if impact in SEVERE_IMPACT and stated not in ("medium", "low"):
        return "hoch"
    if stated == "high":
        return "mittel"
    return "info"
