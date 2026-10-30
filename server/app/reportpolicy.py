from datetime import date, datetime, timedelta
from typing import Any

from .context import Context
from .models import put_setting, setting
from .report import run_level

POLICY_KEY = "report.policy"
DEFAULT = {"frequency": "daily", "weekday": 0, "paused_until": None, "last_regular_sent": None}
FREQUENCIES = ("daily", "weekly", "on_change")
# Diese Stufen gehen am selben Tag raus, egal was eingestellt ist: Ein kritischer Fund wartet nie eine Woche.
ALERT_LEVELS = ("IMMEDIATE ALERT", "ALERT", "ERROR")


def get_report_policy(ctx: Context) -> dict:
    with ctx.session_factory() as s:
        return {**DEFAULT, **(setting(s, POLICY_KEY) or {})}


def set_report_policy(ctx: Context, policy: dict) -> None:
    """Übernimmt Häufigkeit, Wochentag und Pause; last_regular_sent bleibt erhalten, wenn es nicht mitkommt."""
    merged = {**get_report_policy(ctx), **policy}
    if merged["frequency"] not in FREQUENCIES:
        raise ValueError(f"frequency must be one of {', '.join(FREQUENCIES)}")
    if not isinstance(merged["weekday"], int) or not 0 <= merged["weekday"] <= 6:
        raise ValueError("weekday must be 0 (Monday) to 6 (Sunday)")
    if merged["paused_until"]:
        date.fromisoformat(merged["paused_until"])   # ValueError bei falschem Format
    with ctx.session_factory() as s:
        put_setting(s, POLICY_KEY, merged)
        s.commit()


def is_changed(info: dict[str, Any]) -> bool:
    return any(info.get(k) for k in ("new_findings", "resolved_count", "reopened_count", "changed_count",
                                     "system_errors"))


def report_decision(policy: dict, info: dict[str, Any], now_local: datetime) -> str:
    """Ob der regelmäßige Bericht eines geplanten Laufs rausgeht. Alarme und Fehler immer."""
    if run_level(info) in ALERT_LEVELS:
        return "send"
    paused = policy.get("paused_until")
    if paused and now_local.date() <= date.fromisoformat(paused):
        return f"skip: paused until {paused}"
    frequency = policy.get("frequency", "daily")
    if frequency == "weekly":
        last = policy.get("last_regular_sent")
        # Ging der Bericht am Wochentag nicht raus (Lauf ausgefallen), holt der nächste Lauf ihn einmal nach
        if now_local.weekday() == policy.get("weekday", 0) or not last \
                or now_local - datetime.fromisoformat(last) > timedelta(days=7):
            return "send"
        return "skip: weekly"
    if frequency == "on_change" and not is_changed(info):
        return "skip: no change"
    return "send"


def reports_paused_until(ctx: Context, today: date) -> str | None:
    paused = get_report_policy(ctx).get("paused_until")
    return paused if paused and today <= date.fromisoformat(paused) else None
