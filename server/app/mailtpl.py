"""HTML-Vorlagen der Mails: ein gemeinsamer Rahmen im Stil der Oberfläche (dunkel, ruhig, Schweregrade als einzige
Farbe), darin je Mailart ein Inhalt. Alle Stile stehen inline, weil Mailprogramme <style> und CSS-Variablen oft
verwerfen; Farbmischungen werden deshalb hier vorberechnet statt per color-mix."""
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


def section(title: str, inner: str, aside: str = "") -> str:
    aside = f'<span style="float:right;color:{MUTED};font-weight:400">{aside}</span>' if aside else ""
    return (f'<tr><td class="ll-pad" style="padding:22px 28px;border-top:1px solid {LINE}">'
            f'<div style="font-size:14px;font-weight:600;color:{TEXT};margin:0 0 12px">{aside}{e(title)}</div>'
            f'{inner}</td></tr>')


def page(subject: str, headline: str, status: str, meta: str, lede: str, sections: list[str]) -> str:
    """Gemeinsamer Rahmen: Kopfzeile, Karte mit Überschrift und Abschnitten, Fußzeile."""
    lede = f'<p style="margin:12px 0 0;color:{TEXT_2};font-size:14px;line-height:1.55">{lede}</p>' if lede else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark"><meta name="supported-color-schemes" content="dark"><title>{e(subject)}</title>
<style>@media (max-width:540px){{.ll-pad{{padding-left:18px!important;padding-right:18px!important}}.ll-sev td.ll-gap{{display:none!important}}.ll-sev td.ll-cell{{display:inline-block!important;width:49%!important;box-sizing:border-box;margin-bottom:6px}}}}</style></head>
<body style="margin:0;padding:0;background:{GROUND};color:{TEXT};font-family:{FONT};-webkit-font-smoothing:antialiased">
<div style="display:none;max-height:0;overflow:hidden">{e(headline)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:{GROUND}">
<tr><td align="center" style="padding:28px 12px 40px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:640px">
<tr><td style="padding:0 4px 14px;font-size:13px;color:{MUTED}">
<span style="float:right">{meta}</span><span style="color:{TEXT};font-weight:600;letter-spacing:-0.01em">LabLantern</span></td></tr>
<tr><td style="background:{SURFACE};border:1px solid {LINE};border-radius:14px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
<tr><td class="ll-pad" style="padding:26px 28px 24px">
<h1 style="margin:0 0 12px;font-size:22px;line-height:1.25;font-weight:600;letter-spacing:-0.02em;color:{TEXT}">{e(headline)}</h1>
{status}{lede}</td></tr>
{''.join(sections)}
</table></td></tr>
<tr><td style="padding:16px 4px 0;font-size:12px;line-height:1.5;color:{MUTED}">Sent by LabLantern. The web UI has the full list and history.</td></tr>
</table></td></tr></table></body></html>"""


def _kv(label: str, value: str) -> str:
    return (f'<tr><td style="padding:5px 16px 5px 0;color:{MUTED};font-size:13px;white-space:nowrap;vertical-align:top">'
            f'{e(label)}</td><td style="padding:5px 0;color:{TEXT_2};font-size:13px;line-height:1.5">{value}</td></tr>')


def _state(ok: bool, good: str, bad: str, detail: str = "") -> str:
    color = OK if ok else CRIT
    dot = (f'<span style="display:inline-block;width:7px;height:7px;border-radius:4px;background:{color};'
           f'margin-right:7px;vertical-align:1px"></span>')
    detail = f' <span style="color:{MUTED}">· {e(detail)}</span>' if detail else ""
    return f'{dot}<span style="color:{TEXT};font-weight:500">{e(good if ok else bad)}</span>{detail}'


def _table(rows: str) -> str:
    return f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">{rows}</table>'


# --- Laufbericht -------------------------------------------------------------------------------------------------

TONES = [("[IMMEDIATE ALERT]", "Immediate alert", CRIT), ("[ALERT]", "Alert", CRIT), ("[ERROR]", "Error", CRIT),
         ("[WARNING]", "Warning", HIGH), ("[OK]", "OK", OK)]


def _tone(subject: str) -> tuple[str, str, str]:
    """Stufe und Überschrift aus dem Betreff, damit beide nie auseinanderlaufen."""
    for tag, label, color in TONES:
        if subject.startswith(tag):
            return label, color, subject[len(tag):].strip().removeprefix("LabLantern:").strip()
    return "Report", INFO, subject


def _severity_row(summary: dict, new: dict) -> str:
    cells = []
    for lvl in ("kritisch", "hoch", "mittel", "info"):
        n = summary.get(lvl, 0)
        color = SEV_COLOR[lvl] if n and lvl != "info" else (TEXT if n else MUTED)
        added = (f'<div style="font-size:12px;color:{TEXT_2};margin-top:2px">+{new[lvl]:,} new</div>'
                 if new.get(lvl) else f'<div style="font-size:12px;margin-top:2px">&nbsp;</div>')
        cells.append(f'<td class="ll-cell" width="25%" style="padding:12px 14px;background:{SURFACE_2};border-radius:9px;vertical-align:top">'
                     f'<div style="font-size:12px;color:{MUTED}">{SEV_LABEL[lvl]}</div>'
                     f'<div style="font-size:22px;font-weight:600;letter-spacing:-0.02em;color:{color};'
                     f'font-variant-numeric:tabular-nums;margin-top:2px">{n:,}</div>{added}</td>')
    gap = '<td class="ll-gap" width="8" style="font-size:0">&nbsp;</td>'
    return (f'<table class="ll-sev" role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%"><tr>'
            f'{gap.join(cells)}</tr></table>')


def _finding(f: dict) -> str:
    color = SEV_COLOR[f["severity"]]
    kev = (f' <span style="font-family:{MONO};font-size:11px;font-weight:600;color:{CRIT};letter-spacing:0.04em">'
           f'KEV</span>' if f.get("kev") else "")
    pkg = f'{e(f["component"])} <span style="color:{MUTED}">{e(f.get("installed_version") or "")}</span>'
    fix = (f' <span style="color:{MUTED}">· fix</span> <span style="color:{OK}">{code(f["fixed_version"])}</span>'
           if f.get("fixed_version") else f' <span style="color:{MUTED}">· no fix yet</span>')
    where = e(f.get("system_name", "?"))
    if f.get("target", "host") != "host":
        where += f' <span style="color:{MUTED}">·</span> {code(f["target"])}'
    return (f'<tr><td style="padding:10px 0;border-top:1px solid {LINE};vertical-align:top;width:72px">'
            f'<span style="font-size:12px;font-weight:600;color:{color}">{SEV_LABEL[f["severity"]]}</span></td>'
            f'<td style="padding:10px 0;border-top:1px solid {LINE};font-size:13px;line-height:1.5;color:{TEXT_2}">'
            f'<div style="color:{TEXT};font-family:{MONO};font-size:13px;font-weight:600">{e(f["cve_id"])}{kev}</div>'
            f'<div style="word-break:break-word">{pkg}{fix}</div>'
            f'<div style="color:{MUTED};word-break:break-word">{where}</div></td></tr>')


def run_report_html(subject: str, info: dict[str, Any], max_findings: int) -> str:
    label, color, headline = _tone(subject)
    summary = info.get("summary") or {}
    new = info.get("new_findings") or []
    per_new = {lvl: sum(1 for f in new if f["severity"] == lvl) for lvl in SEV_LABEL}
    meta = f'Run #{info["run_id"]} · {e(info.get("trigger", "manual"))}'
    status = badge(label, color) + f' <span style="color:{MUTED};font-size:13px;margin-left:6px">run {e(info["status"])}</span>'
    lede_bits = []
    if info.get("resolved_count"):
        lede_bits.append(f'{info["resolved_count"]:,} resolved since the last run')
    if info.get("reopened_count"):
        lede_bits.append(f'{info["reopened_count"]:,} snooze(s) ended')
    sections = [section("Open findings", _severity_row(summary, per_new))]

    health = [_kv("Canary test", _state(info["canary_ok"], "Green", "Red", info.get("canary_message", ""))),
              _kv("Scanner database", _state(info["db_ok"], "Fresh", "Error", info.get("db_reason", "")))]
    if info.get("osv_disabled"):
        health.append(_kv("OSV-Scanner", f'<span style="color:{MUTED}">Off (light mode)</span>'))
    elif "osv_ok" in info:
        health.append(_kv("OSV-Scanner", _state(info["osv_ok"], "OK", "Error", info.get("osv_reason", ""))))
    if info.get("config_version"):
        archive = f' <span style="color:{MUTED}">· raw data archive {e(info["archive_status"])}</span>' \
            if info.get("archive_status") else ""
        health.append(_kv("Config", code(info["config_version"]) + archive))
    if info.get("error"):
        health.append(_kv("Error", f'<span style="color:{CRIT}">{e(info["error"])}</span>'))
    if info.get("repeat_no_data"):
        health.append(_kv("No data", f'<span style="color:{CRIT}">two runs in a row without fresh data from '
                                     f'{e(", ".join(info["repeat_no_data"]))}</span>'))
    for name, a, b in info.get("sharp_drops") or []:
        health.append(_kv("Sharp drop", f'<span style="color:{CRIT}">{e(name)}: open findings {a} → {b} in one run. '
                                        'Expected after a large update; otherwise check the SBOM and the worker.</span>'))
    sections.append(section("Run health", _table("".join(health))))

    errors = info.get("system_errors") or []
    if errors:
        sections.append(section("Systems not checked", _table("".join(
            _kv(name, f'<span style="color:{CRIT}">{e(err)}</span>') for name, err in errors))))

    pool = sorted((f for f in new if f["severity"] in ("kritisch", "hoch")),
                  key=lambda f: (f["severity"] != "kritisch", not f.get("kev"), f["cve_id"]))
    if pool:
        rows = "".join(_finding(f) for f in pool[:max_findings])
        if len(pool) > max_findings:
            rows += (f'<tr><td></td><td style="padding:10px 0;border-top:1px solid {LINE};font-size:13px;color:{MUTED}">'
                     f'{len(pool) - max_findings:,} more critical or high findings in the web UI</td></tr>')
        sections.append(section("New critical and high findings", _table(rows), f"{len(pool):,}"))

    snoozed = info.get("snoozed") or {}
    back = info.get("snooze_ended") or []
    if snoozed.get("items") or back:
        rows = "".join(_kv(f'{x["cve_id"]} · {x["system_name"]}',
                           f'<span style="color:{CRIT}">snooze ended: {e(x["end_reason"])}</span>'
                           f' <span style="color:{MUTED}">· {e(x["reason"])}</span>') for x in back)
        rows += "".join(_kv(f'{x["cve_id"]} · {x["system_name"]}',
                            f'until {e(x["until"])} <span style="color:{MUTED}">· {e(x["reason"])}</span>')
                        for x in snoozed.get("items") or [])
        sections.append(section("Snoozed", _table(rows), f'{snoozed.get("count", 0):,}'))

    ew = info.get("early_warnings") or {}
    c = ew.get("counts") or {}
    if any(c.values()):
        items = [f'<p style="margin:0 0 8px;font-size:13px;color:{TEXT_2}">{c["betroffen"]} affected · '
                 f'{c["nicht_betroffen"]} not affected · {c["unklar"]} need review</p>']
        for w in ew.get("affected") or []:
            tags = badge("Exploited", CRIT) + " " if w["exploited"] == "ja" else ""
            items.append(f'<div style="padding:8px 0;border-top:1px solid {LINE};font-size:13px;line-height:1.5">'
                         f'{tags}{link(w["link"], w["title"][:160])}</div>')
        sections.append(section("AI early warnings since the last run", "".join(items)))

    cov = info.get("coverage") or {}
    if cov.get("systems"):
        rows = []
        for entry in cov["systems"]:
            age = f'data {entry["age_hours"]} h old' if entry.get("age_hours") is not None else "no data yet"
            checks = entry.get("checks", {})
            flagged = [(k, v["status"]) for k, v in checks.items() if v["status"] != "ok"]
            chips = " ".join(badge(f'{CHECK_NAMES.get(k, k)}: {CHECK_STATUS.get(st, (st, MUTED))[0]}',
                                   CHECK_STATUS.get(st, (st, MUTED))[1]) for k, st in flagged)
            rest = len(checks) - len(flagged)
            ok_note = (f'<span style="font-size:12px;color:{MUTED};white-space:nowrap">{"all " if not flagged else ""}{rest} '
                       f'{"check" if rest == 1 else "checks"} OK</span>') if rest else ""
            rows.append(f'<tr><td style="padding:10px 16px 10px 0;border-top:1px solid {LINE};vertical-align:top;'
                        f'white-space:nowrap;font-size:13px"><div style="color:{TEXT};font-weight:600">'
                        f'{e(entry["system_name"])}</div><div style="color:{MUTED};font-size:12px">{age}</div></td>'
                        f'<td style="padding:10px 0;border-top:1px solid {LINE};vertical-align:top;line-height:26px">'
                        f'{chips} {ok_note}</td></tr>')
        sections.append(section("Coverage", _table("".join(rows)), f'{cov.get("coverage_percent", 0)} %'))
    return page(subject, headline, status, meta, " · ".join(lede_bits), sections)


# --- Frühwarnung --------------------------------------------------------------------------------------------------

def _reason(text: str) -> str:
    """'python:3.11-slim on host-b: Begründung' → Produkt hervorgehoben, Begründung gedämpft."""
    head, sep, rest = text.partition(": ")
    if not sep:
        return f'<div style="padding:2px 0">{e(text)}</div>'
    return (f'<div style="padding:3px 0"><span style="color:{TEXT}">{e(head)}</span> '
            f'<span style="color:{MUTED}">–</span> {e(rest)}</div>')


def _advisory(w: dict) -> str:
    affected = w["status"] == "betroffen"
    tags = [badge("Affected", CRIT) if affected else badge("Needs review", WARN)]
    if w["exploited"]:
        tags.append(badge("Exploited", CRIT))
    sev = {"hoch": ("High", HIGH), "mittel": ("Medium", MED)}.get(w["severity"])
    if sev:
        tags.append(badge(*sev))
    host = urlsplit(w["link"]).hostname or ""
    detail = w["detail"]
    reasons = "".join(_reason(r) for r in (detail.split("; ") if detail else []))
    steps = ""
    for st in w["actions"]:
        cmd = (f'<div style="margin:6px 0 0;padding:9px 12px;background:{SURFACE_2};border-radius:9px;'
               f'font-family:{MONO};font-size:12px;line-height:1.55;color:{TEXT};white-space:pre-wrap;'
               f'overflow-wrap:anywhere">{e(st["command"])}</div>') if st["command"] else ""
        steps += (f'<div style="padding:8px 0 0"><span style="color:{TEXT};font-weight:600">{e(st["system"])}</span> '
                  f'<span style="color:{TEXT_2}">{e(st["text"])}</span>{cmd}</div>')
    if steps:
        steps = f'<div style="margin-top:14px;font-size:12px;color:{MUTED}">What to do</div>{steps}'
    mitig = "".join(f'<div style="padding:3px 0">{e(m)}</div>' for m in w["mitigations"])
    if mitig:
        mitig = f'<div style="margin-top:14px;font-size:12px;color:{MUTED}">Mitigation from the advisory</div>{mitig}'
    source = (f'<div style="margin-top:14px;font-size:12px;color:{MUTED}">{link(w["link"], "Read the advisory", TEXT_2)}'
              f'{" · " + e(host) if host else ""}</div>') if w["link"] else ""
    return (f'<tr><td class="ll-pad" style="padding:22px 28px;border-top:1px solid {LINE};font-size:13px;line-height:1.55;color:{TEXT_2}">'
            f'<div style="line-height:26px">{" ".join(tags)}</div>'
            f'<div style="margin:8px 0 10px;font-size:16px;line-height:1.35;font-weight:600;letter-spacing:-0.01em">'
            f'{link(w["link"], w["title"])}</div>'
            f'{reasons}{steps}{mitig}{source}</td></tr>')


def early_warning_html(subject: str, items: list[dict], systems: list[str], more: int) -> str:
    """items: je Meldung title, link, status, exploited (bool), severity, detail, actions, mitigations."""
    n = len(items) + more
    headline = items[0]["title"] if n == 1 else f"{n} new advisories for your systems"
    affected = sum(1 for w in items if w["status"] == "betroffen")
    color = CRIT if affected or any(w["exploited"] for w in items) else HIGH
    status = badge("Early warning", color)
    lede = []
    if systems:
        lede.append("Matches products on " + ", ".join(f'<span style="color:{TEXT}">{e(s)}</span>' for s in systems))
    if affected:
        lede.append(f"{affected} confirmed affected")
    review = len(items) - affected
    if review:
        lede.append(f"{review} {'needs' if review == 1 else 'need'} a manual check")
    sections = [_advisory(w) for w in items]
    if more:
        sections.append(f'<tr><td class="ll-pad" style="padding:16px 28px;border-top:1px solid {LINE};font-size:13px;color:{MUTED}">'
                        f'{more} more under Early warnings in the web UI</td></tr>')
    meta = f"{n} {'advisory' if n == 1 else 'advisories'}"
    return page(subject, headline, status, meta, " · ".join(lede), sections)
