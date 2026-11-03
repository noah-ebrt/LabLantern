import logging
from typing import Any

log = logging.getLogger("lablantern.report")

MAX_LISTED_FINDINGS = 25
EN = {"kritisch": "critical", "hoch": "high", "mittel": "medium", "info": "info"}



def _subject(info: dict[str, Any]) -> str:
    summary = info.get("summary") or {}
    errors = info.get("system_errors") or []
    invalid = info["status"] == "failed" or not info["canary_ok"] or not info["db_ok"]
    kritisch, hoch = summary.get("kritisch", 0), summary.get("hoch", 0)
    repeat = info.get("repeat_no_data") or []
    drops = info.get("sharp_drops") or []
    if invalid:
        reason = info.get("error") or info.get("canary_message") or info.get("db_reason") or "unbekannt"
        subject = f"[IMMEDIATE ALERT] LabLantern: run invalid – {reason}"
    elif repeat:
        # PLAN Abschnitt 5: System zweimal in Folge ohne Daten ist kritisch (Sofort-Alarm)
        subject = f"[IMMEDIATE ALERT] LabLantern: no data from {', '.join(repeat)} in two runs in a row"
    elif drops:
        subject = ("[IMMEDIATE ALERT] LabLantern: findings dropped sharply on "
                   + ", ".join(f"{name} ({a} → {b})" for name, a, b in drops))
    elif kritisch:
        subject = f"[ALERT] LabLantern: {kritisch} critical vulnerabilit{'y' if kritisch == 1 else 'ies'} open"
    elif errors:
        subject = f"[ERROR] LabLantern: {len(errors)} system(s) not checked"
    elif hoch:
        subject = f"[WARNING] LabLantern: {hoch} high vulnerabilit{'y' if hoch == 1 else 'ies'} open"
    else:
        subject = f"[OK] LabLantern: {info.get('period', 'daily')} report – all systems as expected"
    return subject


def run_level(info: dict[str, Any]) -> str:
    """Stufe aus dem Betreff: IMMEDIATE ALERT, ALERT, ERROR, WARNING oder OK."""
    return _subject(info)[1:].split("]", 1)[0]


def format_run_report(info: dict[str, Any]) -> tuple[str, str]:
    """Titel und Klartext-Bericht eines Laufs. `info` kommt aus scanrun.process_scan_result / expire_stale_jobs."""
    summary = info.get("summary") or {}
    errors = info.get("system_errors") or []
    kritisch, hoch = summary.get("kritisch", 0), summary.get("hoch", 0)
    repeat = info.get("repeat_no_data") or []
    drops = info.get("sharp_drops") or []
    subject = _subject(info)

    lines = [
        f"lablantern run #{info['run_id']} ({info.get('trigger', 'manual')}) – status: {info['status']}",
        "=" * 60,
        f"Canary test: {'green' if info['canary_ok'] else 'RED'} – {info.get('canary_message', '')}",
        f"Scanner database: {'fresh' if info['db_ok'] else 'ERROR'}"
        + (f" – {info['db_reason']}" if info.get("db_reason") else ""),
    ]
    if info.get("osv_disabled"):
        lines.append("Second source (OSV-Scanner): off (light mode)")
    elif "osv_ok" in info:
        lines.append(f"Second source (OSV-Scanner): {'ok' if info['osv_ok'] else 'ERROR – ' + info.get('osv_reason', '')}")
    if info.get("config_version"):
        lines.append(f"Config version: {info['config_version']}"
                     + (f" · raw data archive: {info['archive_status']}" if info.get("archive_status") else ""))
    if info.get("error"):
        lines.append(f"Error: {info['error']}")
    if repeat:
        lines.append(f"CRITICAL: no fresh data in two consecutive runs from: {', '.join(repeat)}")
    for name, a, b in drops:
        lines.append(f"CRITICAL: open findings on {name} fell from {a} to {b} in one run. Expected after a large "
                     "update; otherwise check the host's SBOM and the worker, they may report a host as clean.")
    lines += [
        "",
        "Open findings by severity:",
        f"  critical: {kritisch}   high: {hoch}   medium: {summary.get('mittel', 0)}   info: {summary.get('info', 0)}",
        "",
    ]
    if errors:
        lines.append("Systems that could NOT be checked:")
        lines += [f"  - {name}: {err}" for name, err in errors]
        lines.append("")
    new = info.get("new_findings") or []
    if new:
        # Kanäle wie ntfy oder Telegram lehnen lange Nachrichten ab: gefährliche Funde zuerst, der Rest wird gezählt.
        per_level = {lvl: sum(1 for f in new if f["severity"] == lvl) for lvl in ("kritisch", "hoch", "mittel", "info")}
        lines.append("New findings: " + ", ".join(f"{EN[lvl]} {n}" for lvl, n in per_level.items()))
        shown_pool = sorted(
            (f for f in new if f["severity"] in ("kritisch", "hoch")),
            key=lambda f: (f["severity"] != "kritisch", not f.get("kev"), f["cve_id"]),
        )
        for nf in shown_pool[:MAX_LISTED_FINDINGS]:
            kev = " [KEV]" if nf.get("kev") else ""
            lines.append(
                f"  [{EN[nf['severity']].upper()}]{kev} {nf['cve_id']} in {nf['component']} "
                f"{nf.get('installed_version', '')}"
                + (f" ({nf['target']})" if nf.get("target", "host") != "host" else "")
                + f" on {nf.get('system_name', '?')}"
                + (f" (Fix: {nf['fixed_version']})" if nf.get("fixed_version") else "")
            )
        if len(shown_pool) > MAX_LISTED_FINDINGS:
            lines.append(f"  … and {len(shown_pool) - MAX_LISTED_FINDINGS} more critical/high findings (see the web UI)")
        lines.append("")
    snoozed = info.get("snoozed") or {}
    if snoozed.get("count") or snoozed.get("items"):
        # Zurückgestellt heißt nicht erledigt: jeder Snooze steht mit Grund und Ablauf im Bericht
        lines.append(f"Snoozed ({snoozed.get('count', 0)}):")
        lines += [f"  - {x['cve_id']} in {x['component']} on {x['system_name']} ({x['findings']} finding(s)) "
                  f"until {x['until']}: {x['reason']}" for x in snoozed.get("items") or []]
        lines.append("")
    for x in info.get("snooze_ended") or []:
        lines.append(f"Back: {x['cve_id']} in {x['component']} on {x['system_name']} – snooze ended: "
                     f"{x['end_reason']} (reason was: {x['reason']})")
    if info.get("resolved_count"):
        lines.append(f"Resolved since last run: {info['resolved_count']}")
    if info.get("osv_closed_count"):
        lines.append(f"{info['osv_closed_count']} OSV-only finding(s) closed: OSV is switched off (light mode)")
    if info.get("changed_count"):
        lines.append(f"Changed since last run (rating or fix): {info['changed_count']}")
    ew = info.get("early_warnings") or {}
    if any((ew.get("counts") or {}).values()):
        c = ew["counts"]
        lines += ["", f"AI early warnings since the last run: affected {c['betroffen']}, "
                      f"not affected {c['nicht_betroffen']}, needs review {c['unklar']}"]
        for w in ew.get("affected") or []:
            sev = {"hoch": " [HIGH]", "mittel": " [MEDIUM]"}.get(w.get("severity"), "")
            lines.append(f"  [AFFECTED]{' [EXPLOITED]' if w['exploited'] == 'ja' else ''}{sev} {w['title'][:120]} – {w['link']}")
    cov = info.get("coverage") or {}
    if cov.get("systems"):
        lines += ["", f"Coverage: {cov.get('coverage_percent', 0)} %"]
        for entry in cov["systems"]:
            checks = entry.get("checks", {})
            parts = ", ".join(f"{k}={v['status']}" for k, v in checks.items())
            age = f"{entry['age_hours']} h" if entry.get("age_hours") is not None else "never"
            lines.append(f"  - {entry['system_name']} (data {age} old): {parts}")
    return subject, "\n".join(lines)
