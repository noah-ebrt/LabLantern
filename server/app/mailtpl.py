"""HTML-Vorlagen der Mails: ein gemeinsamer Rahmen im Stil der Oberfläche (dunkel, ruhig, Schweregrade als einzige
Farbe), darin je Mailart ein Inhalt. Alle Stile stehen inline, weil Mailprogramme <style> und CSS-Variablen oft
verwerfen; Farbmischungen werden deshalb hier vorberechnet statt per color-mix."""
import re
from html import escape
from typing import Any
from urllib.parse import urlsplit

# Tokens aus web/src/style.css
GROUND, SURFACE, SURFACE_2 = "#0e1015", "#171922", "#1e222f"
TEXT, TEXT_2, MUTED = "#f0f1f5", "#b8bcc8", "#7e8392"
CRIT, HIGH, MED, INFO, OK, WARN = "#f2555a", "#f08c3c", "#e1b443", "#8b9099", "#45bf83", "#e1b443"
FONT = "ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif"
MONO = "ui-monospace,'SF Mono','JetBrains Mono',Menlo,Consolas,monospace"

SEV_COLOR = {"kritisch": CRIT, "hoch": HIGH, "mittel": MED, "info": INFO}
SEV_LABEL = {"kritisch": "Critical", "hoch": "High", "mittel": "Medium", "info": "Info"}
CHECK_NAMES = {"paket_cve": "Package CVEs", "sicherheitsupdates": "Security updates", "reboot": "Reboot",
               "container": "Containers", "images": "Container images", "versionen": "Versions",
               "schutz": "Protection"}
CHECK_STATUS = {"fund": ("Finding", WARN), "fehler": ("Error", CRIT), "offen": ("Queued", MUTED),
                "excluded": ("Excluded", MUTED)}


def _mix(color: str, pct: float, base: str = SURFACE) -> str:
    """color zu pct Prozent über base, wie color-mix(in srgb, …) in der Oberfläche."""
    a, b = (tuple(int(c[i:i + 2], 16) for i in (1, 3, 5)) for c in (color, base))
    return "#" + "".join(f"{round(x * pct / 100 + y * (1 - pct / 100)):02x}" for x, y in zip(a, b))


LINE = _mix("#ffffff", 8)
e = escape


def badge(text: str, color: str) -> str:
    """Pille mit Punkt wie .badge in der Oberfläche."""
    return (f'<span style="display:inline-block;padding:2px 10px;border-radius:999px;border:1px solid {_mix(color, 30)};'
            f'background:{_mix(color, 12)};color:{color};font-size:12px;font-weight:600;line-height:18px;'
            f'white-space:nowrap"><span style="display:inline-block;width:6px;height:6px;border-radius:3px;'
            f'background:{color};vertical-align:1px;margin-right:6px"></span>{e(text)}</span>')


def link(url: str, text: str, color: str = TEXT) -> str:
    """Nur http(s) wird verlinkt: Links stammen aus fremden Feeds."""
    if not url.lower().startswith(("https://", "http://")):
        return e(text)
    return (f'<a href="{e(url)}" style="color:{color};text-decoration:underline;'
            f'text-decoration-color:{_mix("#ffffff", 25)};text-underline-offset:3px">{e(text)}</a>')


def code(text: str) -> str:
    return f'<span style="font-family:{MONO};font-size:12.5px">{e(text)}</span>'


# --- Rahmen und Bausteine ----------------------------------------------------------------------------------------
# Typografie in vier Stufen: Überschrift 22, Hauptzeile 14 halbfett, Text 13, Detail/Etikett 12. Jeder Abschnitt ist
# eine eigene Karte; in der Karte liest man jede Zeile von links nach rechts: Stufe → was → wo.

CARD = f"background:{SURFACE};border:1px solid {LINE};border-radius:12px"
GAP = '<tr><td style="height:10px;font-size:0;line-height:0">&nbsp;</td></tr>'


def pill(text: str, color: str) -> str:
    """Kleines Etikett ohne Punkt, für die linke Spalte einer Zeile (Stufe, Zustand)."""
    return (f'<span style="display:inline-block;padding:1px 8px;border-radius:6px;background:{_mix(color, 16)};'
            f'color:{color};font-size:11px;font-weight:700;line-height:18px;letter-spacing:0.04em;text-transform:uppercase;white-space:nowrap">'
            f'{e(text)}</span>')


def section(title: str, inner: str, count: int | str = "") -> str:
    """Eine Karte: Kopf mit Titel und Anzahl, darunter die Zeilen."""
    count = (f'<td align="right" style="font-size:12px;color:{MUTED};font-variant-numeric:tabular-nums">{count}</td>'
             if count != "" else "")
    head = (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>'
            f'<td style="font-size:12px;font-weight:700;letter-spacing:0.06em;text-transform:uppercase;color:{TEXT_2}">'
            f'{e(title)}</td>{count}</tr></table>') if title else ""
    return (f'{GAP}<tr><td style="{CARD}"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            f'border="0"><tr><td class="ll-pad" style="padding:16px 22px 8px">{head}{inner}</td></tr></table></td></tr>')


def item(key: str, main: str, detail: str = "", where: str = "", first: bool = False) -> str:
    """Eine Zeile: links das Etikett (feste Breite), Mitte Hauptzeile und Detail, rechts wo."""
    line = "" if first else f"border-top:1px solid {LINE};"
    detail = f'<div style="font-size:12px;line-height:1.5;color:{MUTED};margin-top:2px">{detail}</div>' if detail else ""
    if where:
        detail += f'<div class="ll-where-m" style="display:none;font-size:12px;color:{TEXT_2};margin-top:2px">{where}</div>'
        where = (f'<td class="ll-where" align="right" valign="top" style="padding:11px 0 11px 12px;{line}font-size:13px;'
                 f'color:{TEXT_2};white-space:nowrap">{where}</td>')
    return (f'<tr><td valign="top" width="96" style="padding:11px 12px 11px 0;{line}white-space:nowrap">{key}</td>'
            f'<td valign="top" style="padding:11px 0;{line}font-size:14px;line-height:1.45;color:{TEXT};'
            f'word-break:break-word">{main}{detail}</td>{where}</tr>')


def rows(items: list[str]) -> str:
    return (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
            f'style="margin-top:6px">{"".join(items)}</table>')


def page(subject: str, headline: str, status: str, meta: str, lede: str, sections: list[str], top: str = "",
         note: str = "") -> str:
    """Kopfzeile mit Marke und Stufe, Kopfkarte mit Überschrift, Kurzfassung und optional `top` (Zahlen),
    darunter je Abschnitt eine Karte. Fußzeile: was der Lauf war und wo man die Kanäle einstellt.

    Der Vorschautext im Posteingang ist die Kurzfassung, sonst die Überschrift."""
    preview = re.sub(r"<[^>]+>", "", lede) if lede else e(headline)
    lede = f'<p style="margin:8px 0 0;font-size:14px;line-height:1.5;color:{TEXT_2}">{lede}</p>' if lede else ""
    top = f'<div style="margin-top:18px">{top}</div>' if top else ""
    foot = " · ".join(x for x in (meta, note) if x)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark"><meta name="supported-color-schemes" content="dark"><title>{e(subject)}</title>
<style>@media (max-width:540px){{.ll-pad{{padding-left:16px!important;padding-right:16px!important}}.ll-sev td.ll-gap{{display:none!important}}.ll-sev td.ll-cell{{display:inline-block!important;width:48%!important;box-sizing:border-box;margin:0 0 6px!important}}td.ll-where{{display:none!important}}.ll-where-m{{display:block!important}}}}</style></head>
<body style="margin:0;padding:0;background:{GROUND};color:{TEXT};font-family:{FONT};-webkit-font-smoothing:antialiased">
<div style="display:none;max-height:0;overflow:hidden">{preview}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:{GROUND}">
<tr><td align="center" style="padding:24px 10px 32px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:600px">
<tr><td style="padding:0 2px 12px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
<td style="font-size:13px;font-weight:700;letter-spacing:-0.01em;color:{TEXT_2}">LabLantern</td>
<td align="right">{status}</td></tr></table></td></tr>
<tr><td style="{CARD}"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
<td class="ll-pad" style="padding:22px 22px 22px">
<h1 style="margin:0;font-size:22px;line-height:1.3;font-weight:650;letter-spacing:-0.02em;color:{TEXT}">{e(headline)}</h1>
{lede}{top}</td></tr></table></td></tr>
{''.join(sections)}
<tr><td style="padding:14px 2px 0;font-size:12px;line-height:1.6;color:{MUTED}">{foot}{'<br>' if foot else ''}What each channel gets: Settings → Alerts</td></tr>
</table></td></tr></table></body></html>"""


def _strong(text: str) -> str:
    return f'<span style="color:{TEXT};font-weight:600">{e(text)}</span>'


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n:,} {one if n == 1 else (many or one + 's')}"


# --- Laufbericht -------------------------------------------------------------------------------------------------

TONES = [("[IMMEDIATE ALERT]", "Immediate alert", CRIT), ("[ALERT]", "Alert", CRIT), ("[ERROR]", "Error", CRIT),
         ("[WARNING]", "Warning", HIGH), ("[OK]", "OK", OK)]
SEV_SHORT = {"kritisch": "CRITICAL", "hoch": "HIGH", "mittel": "MEDIUM", "info": "INFO"}
CHECK_PHRASE = {"fund": ("has findings", WARN), "fehler": ("failed", CRIT), "offen": ("queued", MUTED)}
FOUND_PHRASE = {"sicherheitsupdates": "pending", "reboot": "needed", "images": "outdated", "versionen": "outdated"}


def _tone(subject: str) -> tuple[str, str, str]:
    """Stufe und Überschrift aus dem Betreff, damit beide nie auseinanderlaufen."""
    for tag, label, color in TONES:
        if subject.startswith(tag):
            head = subject[len(tag):].strip().removeprefix("LabLantern:").strip()
            return label, color, head[:1].upper() + head[1:]
    return "Report", INFO, subject


def _severity_row(summary: dict, new: dict) -> str:
    """Offene Funde je Stufe: Zahl groß, darunter die Stufe, neue als „+n new“ in der Stufenfarbe."""
    cells = []
    for lvl in ("kritisch", "hoch", "mittel", "info"):
        n = summary.get(lvl, 0)
        color = SEV_COLOR[lvl] if n and lvl != "info" else (TEXT_2 if n else MUTED)
        added = (f'<span style="color:{SEV_COLOR[lvl] if lvl != "info" else TEXT_2};font-weight:600">'
                 f'+{new[lvl]:,} new</span>') if new.get(lvl) else "&nbsp;"
        cells.append(f'<td class="ll-cell" width="25%" valign="top" style="padding:10px 12px;background:{SURFACE_2};'
                     f'border-radius:8px"><div style="font-size:12px;color:{MUTED}">{SEV_LABEL[lvl]}</div>'
                     f'<div style="font-size:24px;line-height:1.2;font-weight:650;letter-spacing:-0.02em;color:{color};'
                     f'font-variant-numeric:tabular-nums">{n:,}</div><div style="font-size:12px">{added}</div></td>')
    gap = '<td class="ll-gap" width="6" style="font-size:0">&nbsp;</td>'
    return (f'<table class="ll-sev" role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%"><tr>'
            f'{gap.join(cells)}</tr></table>')


def _finding(f: dict, first: bool) -> str:
    """Stufe | Paket Version → Fix, darunter CVE (KEV) | Host."""
    fix = (f' <span style="color:{MUTED}">→</span> <span style="color:{OK}">{e(f["fixed_version"])}</span>'
           if f.get("fixed_version") else f' <span style="color:{MUTED};font-weight:400">· no fix yet</span>')
    main = (f'<span style="font-weight:600">{e(f["component"])}</span> '
            f'<span style="color:{TEXT_2}">{e(f.get("installed_version") or "")}</span>{fix}')
    kev = f' · <span style="color:{CRIT};font-weight:700">KEV exploited</span>' if f.get("kev") else ""
    detail = f'<span style="font-family:{MONO}">{e(f["cve_id"])}</span>{kev}'
    where = e(f.get("system_name", "?"))
    if f.get("target", "host") != "host":
        detail += f' · image {e(f["target"].removeprefix("image:"))}'
    return item(pill(SEV_SHORT[f["severity"]], SEV_COLOR[f["severity"]]), main, detail, where, first)


def _attention(info: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    """Was am Lauf nicht stimmt oder ein Eingreifen braucht: (Zustand, Farbe, worum es geht, Detail)."""
    out = []
    if info.get("error"):
        out.append(("FAILED", CRIT, "Run", info["error"]))
    if not info.get("canary_ok", True):
        out.append(("RED", CRIT, "Canary", info.get("canary_message") or "the test image was not detected"))
    if not info.get("db_ok", True):
        out.append(("ERROR", CRIT, "Scanner database", info.get("db_reason") or ""))
    if "osv_ok" in info and not info["osv_ok"] and not info.get("osv_disabled"):
        out.append(("ERROR", CRIT, "OSV-Scanner", info.get("osv_reason") or ""))
    for name in info.get("repeat_no_data") or []:
        out.append(("NO DATA", CRIT, name, "no fresh data in two runs in a row"))
    for name, a, b in info.get("sharp_drops") or []:
        out.append(("DROP", CRIT, name, f"open findings {a} → {b} in one run; fine after a big update, "
                                        "otherwise check the SBOM and the worker"))
    unchecked = set()
    for name, err in info.get("system_errors") or []:
        unchecked.add(name)
        out.append(("SKIPPED", CRIT, name, "not checked: " + err))
    for x in info.get("snooze_ended") or []:
        out.append(("BACK", HIGH, f'{x["cve_id"]} on {x["system_name"]}', f'snooze ended: {x["end_reason"]}'))
    for entry in (info.get("coverage") or {}).get("systems") or []:
        if entry["system_name"] in unchecked:
            continue
        if entry.get("age_hours") is None:
            out.append(("NO DATA", MUTED, entry["system_name"], "no data yet"))
            continue
        flagged = [(k, v["status"]) for k, v in entry.get("checks", {}).items() if v["status"] in CHECK_PHRASE]
        if flagged:
            worst = next((st for st in ("fehler", "fund", "offen") if any(s == st for _k, s in flagged)))
            label, color = {"fehler": ("FAILED", CRIT), "fund": ("TO DO", WARN), "offen": ("QUEUED", MUTED)}[worst]
            out.append((label, color, entry["system_name"],
                        " · ".join(f'{CHECK_NAMES.get(k, k)} '
                                   f'{FOUND_PHRASE.get(k, CHECK_PHRASE[st][0]) if st == "fund" else CHECK_PHRASE[st][0]}'
                                   for k, st in flagged)))
    return out


def _tldr(info: dict[str, Any], per_new: dict) -> str:
    """Die Nachricht in einer Zeile: was neu ist, was weg ist, was hakt."""
    if info.get("error") or not info.get("canary_ok", True) or not info.get("db_ok", True):
        return "The results of this run are incomplete. Fix the problem below, then run again."
    bits = [f"{_strong(f'{per_new[lvl]:,} new')} {SEV_LABEL[lvl].lower()}" for lvl in ("kritisch", "hoch", "mittel")
            if per_new.get(lvl)]
    if info.get("resolved_count"):
        bits.append(f'{_strong(str(info["resolved_count"]))} resolved')
    unchecked = len(info.get("system_errors") or [])
    if unchecked:
        bits.append(f'{_strong(str(unchecked))} {"host" if unchecked == 1 else "hosts"} not checked')
    affected = len((info.get("early_warnings") or {}).get("affected") or [])
    if affected:
        bits.append(f'{_strong(str(affected))} early {"warning" if affected == 1 else "warnings"} for you')
    return " · ".join(bits) if bits else "Nothing new since the last run."


def run_report_html(subject: str, info: dict[str, Any], max_findings: int) -> str:
    label, color, headline = _tone(subject)
    summary = info.get("summary") or {}
    new = info.get("new_findings") or []
    per_new = {lvl: sum(1 for f in new if f["severity"] == lvl) for lvl in SEV_LABEL}
    sections = []

    attention = _attention(info)
    if attention:
        sections.append(section("Needs attention", rows([
            item(pill(st, c), e(what), e(detail), first=i == 0) for i, (st, c, what, detail) in enumerate(attention)]),
            len(attention)))

    pool = sorted((f for f in new if f["severity"] in ("kritisch", "hoch")),
                  key=lambda f: (f["severity"] != "kritisch", not f.get("kev"), f["cve_id"]))
    if pool:
        lines = [_finding(f, i == 0) for i, f in enumerate(pool[:max_findings])]
        if len(pool) > max_findings:
            lines.append(item("", f'<span style="color:{MUTED};font-size:13px">'
                                  f'{len(pool) - max_findings:,} more in the web UI</span>'))
        sections.append(section("New critical and high", rows(lines), len(pool)))

    ew = info.get("early_warnings") or {}
    affected = ew.get("affected") or []
    if affected:
        lines = [item(pill("EXPLOITED", CRIT) if w["exploited"] == "ja" else pill("AFFECTED", HIGH),
                      link(w["link"], w["title"][:160]), first=i == 0) for i, w in enumerate(affected)]
        review = (ew.get("counts") or {}).get("unklar", 0)
        if review:
            lines.append(item("", f'<span style="color:{MUTED};font-size:13px">'
                                  f'{_plural(review, "more needs", "more need")} a manual check</span>'))
        sections.append(section("Early warnings for your systems", rows(lines), len(affected)))

    notes = []
    if info.get("canary_ok") and info.get("db_ok", True) and not info.get("error"):
        notes.append("verified: canary green, scanner database fresh"
                     + (", OSV ok" if info.get("osv_ok") and not info.get("osv_disabled") else ""))
    cov = info.get("coverage") or {}
    if cov.get("systems"):
        notes.append(f'coverage {cov.get("coverage_percent", 0)} %')
    snoozed = info.get("snoozed") or {}
    if snoozed.get("count"):
        nxt = min((x["until"] for x in snoozed.get("items") or [] if x.get("until")), default=None)
        notes.append(_plural(snoozed["count"], "finding") + " snoozed" + (f" (next ends {nxt})" if nxt else ""))
    meta = f'Run #{info["run_id"]} ({e(info.get("trigger", "manual"))})'
    return page(subject, headline, badge(label, color), meta, _tldr(info, per_new), sections,
                top=_severity_row(summary, per_new), note=e(" · ".join(notes)))


# --- Frühwarnung --------------------------------------------------------------------------------------------------

MAX_REASONS = 3


def _label(text: str) -> str:
    return (f'<div style="margin:16px 0 6px;font-size:11px;font-weight:700;letter-spacing:0.06em;'
            f'text-transform:uppercase;color:{MUTED}">{e(text)}</div>')


def _advisory(w: dict, with_title: bool = True) -> str:
    """Eine Karte je Meldung: Etiketten, Titel, betroffene Stellen, dann Fix (hervorgehoben) und Quelle."""
    affected = w["status"] == "betroffen"
    tags = [pill("Affected", CRIT) if affected else pill("Check", WARN)]
    if w["exploited"]:
        tags.append(pill("Exploited", CRIT))
    sev = {"hoch": ("High", HIGH), "mittel": ("Medium", MED)}.get(w["severity"])
    if sev:
        tags.append(pill(*sev))
    reasons = [r for r in (w["detail"].split("; ") if w["detail"] else []) if r]
    hits = []
    for i, r in enumerate(reasons[:MAX_REASONS]):
        what, _sep, why = r.partition(": ")
        hits.append(f'<tr><td style="padding:6px 0;{"" if i == 0 else f"border-top:1px solid {LINE};"}font-size:13px;'
                    f'line-height:1.45"><span style="color:{TEXT};font-weight:600">{e(what)}</span>'
                    f'{f"<div style=\"color:{MUTED};font-size:12px\">{e(why)}</div>" if why else ""}</td></tr>')
    if len(reasons) > MAX_REASONS:
        hits.append(f'<tr><td style="padding:6px 0;border-top:1px solid {LINE};font-size:12px;color:{MUTED}">'
                    f'+{len(reasons) - MAX_REASONS} more</td></tr>')
    where = (_label("Affects") + f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">'
             f'{"".join(hits)}</table>') if hits else ""
    steps = ""
    for st in w["actions"]:
        cmd = (f'<div style="margin-top:6px;padding:8px 10px;background:{GROUND};border-radius:6px;font-family:{MONO};'
               f'font-size:12px;line-height:1.5;color:{TEXT};white-space:pre-wrap;overflow-wrap:anywhere">'
               f'{e(st["command"])}</div>') if st["command"] else ""
        steps += (f'<div style="padding:4px 0;font-size:13px;line-height:1.45;color:{TEXT_2}">'
                  f'<span style="color:{TEXT};font-weight:600">{e(st["system"])}</span> · {e(st["text"])}{cmd}</div>')
    if steps:
        steps = (_label("Fix") + f'<div style="padding:8px 12px;background:{SURFACE_2};border-radius:8px">{steps}</div>')
    mitig = "".join(f'<div style="font-size:13px;line-height:1.45;color:{TEXT_2};padding:2px 0">{e(m)}</div>'
                    for m in w["mitigations"])
    mitig = _label("Until patched") + mitig if mitig else ""
    host = urlsplit(w["link"]).hostname or ""
    source = (f'<div style="margin:16px 0 8px;font-size:12px;color:{MUTED}">{link(w["link"], "Read the advisory", TEXT_2)}'
              f'{" · " + e(host) if host else ""}</div>') if w["link"] else '<div style="height:8px"></div>'
    title = (f'<div style="margin-top:10px;font-size:16px;line-height:1.35;font-weight:650;letter-spacing:-0.01em">'
             f'{link(w["link"], w["title"])}</div>') if with_title else ""
    return section("", f'{" ".join(tags)}{title}{where}{steps}{mitig}{source}')


def early_warning_html(subject: str, items: list[dict], systems: list[str], more: int) -> str:
    """items: je Meldung title, link, status, exploited (bool), severity, detail, actions, mitigations."""
    n = len(items) + more
    single = n == 1
    headline = items[0]["title"] if single else f"{n} new advisories for your systems"
    affected = sum(1 for w in items if w["status"] == "betroffen")
    color = CRIT if affected or any(w["exploited"] for w in items) else HIGH
    lede = []
    if affected:
        lede.append(f"{_strong(str(affected))} affected")
    review = len(items) - affected
    if review:
        lede.append(f"{_strong(str(review))} to check")
    if systems:
        lede.append("on " + ", ".join(_strong(s) for s in systems[:4]) + (" …" if len(systems) > 4 else ""))
    sections = [_advisory(w, with_title=not single) for w in items]
    if more:
        sections.append(section("", f'<div style="padding-bottom:8px;font-size:13px;color:{MUTED}">'
                                    f'{more} more under Early warnings</div>'))
    return page(subject, headline, badge("Early warning", color), _plural(n, "advisory", "advisories"),
                " · ".join(lede), sections)


# --- Kurze Alarme (Ausfall, Störung, Abdeckung) ------------------------------------------------------------------

NOTICE_TONES = {"outage": ("Outage", CRIT), "service": ("Problem", WARN), "coverage": ("Coverage check", INFO),
                "alert": ("Alert", CRIT), "early_warning": ("Early warning", HIGH), "report": ("Report", INFO)}
ROW_PILL = {"outage": ("DOWN", CRIT), "service": ("PROBLEM", WARN), "coverage": ("GAP", WARN)}
GOOD_NEWS = ("recovered", "works again", "back up")
EVENT_LABELS = {"report": "Scan report", "alert": "Scan alert", "outage": "Outage", "early_warning": "Early warning",
                "service": "LabLantern problem", "coverage": "Coverage check"}


def _row_pill(kind: str, text: str) -> str:
    low = text.lower()
    if any(w in low for w in GOOD_NEWS) or low.startswith("resolved"):
        return pill("UP" if kind == "outage" else "OK", OK)
    if kind == "coverage":
        state = low.rsplit(": ", 1)[-1]
        return pill(state.upper()[:10], CRIT if state == "missed" else WARN)
    return pill(*ROW_PILL.get(kind, ("NOTE", INFO)))


def notice_html(subject: str, body: str, kind: str) -> str:
    """Rahmen für Meldungen ohne eigene Vorlage: der erste Absatz wird die Kurzfassung, „- “-Zeilen Einträge mit
    Etikett, eingerückte Zeilen deren Details, „Titel:“-Zeilen ein eigener Abschnitt."""
    label, color = NOTICE_TONES.get(kind, ("Notice", INFO))
    headline = subject.removeprefix("LabLantern:").strip()
    if kind in ("service", "coverage"):   # eigene Sätze; bei Ausfällen steht vorn ein Hostname, der bleibt, wie er ist
        headline = headline[:1].upper() + headline[1:]
    if any(w in subject.lower() for w in GOOD_NEWS):
        label, color = "Resolved", OK
    groups, lede, tail = [], "", []   # (Titel, Zeilen)
    for i, chunk in enumerate(c for c in body.strip().split("\n\n") if c.strip()):
        lines = chunk.splitlines()
        title = lines[0].rstrip(":") if len(lines) > 1 and lines[0].endswith(":") else ""
        entries, text = [], []
        for line in lines[1:] if title else lines:
            if line.startswith("- "):
                entries.append([line[2:], []])
            elif line.startswith("  ") and entries:
                entries[-1][1].append(e(line.strip()))
            else:
                text.append(e(line))
        if i == 0 and text and not title:
            lede = " ".join(text)
        elif text:
            tail.append(" ".join(text))
        if entries:
            resolved = title.lower().startswith("resolved")
            groups.append((title, [item(pill("OK", OK) if resolved else _row_pill(kind, txt),
                                        e(txt.rsplit(": ", 1)[0] if kind == "coverage" else txt), "<br>".join(det),
                                        first=j == 0) for j, (txt, det) in enumerate(entries)]))
    top = ""
    if len(groups) == 1 and not groups[0][0]:
        # Eine einzelne Liste ohne Titel gehört in die Kopfkarte: eine Meldung, eine Karte
        top, groups = rows(groups[0][1]), []
    blocks = [section(title, rows(lines), len(lines) if len(lines) > 1 else "") for title, lines in groups]
    return page(subject, headline, badge(label, color), "", lede, blocks, top=top, note=e(" ".join(tail)))
