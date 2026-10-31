import { reactive } from 'vue'
import { api } from './api.js'

// Zeitzone des Systems (Einstellungen → Zeitplan); alle Zeitangaben der Oberfläche richten sich danach
export const clock = reactive({ timeZone: 'UTC' })

// Der Server rechnet in UTC, SQLite verliert dabei aber die Zone: ein ISO-Wert ohne Offset ist UTC, nicht Ortszeit
const NAIVE = /T\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/
export const parseTime = (v) => {
  if (v === null || v === undefined || v === '') return null
  if (v instanceof Date) return v
  if (typeof v === 'number') return new Date(v * 1000)   // Unix-Sekunden (Befehle, Passkeys)
  return new Date(NAIVE.test(v) ? `${v}Z` : v)
}

const fmt = (v, opts) => {
  const d = parseTime(v)
  if (!d) return ''
  try {
    return d.toLocaleString('en-GB', { timeZone: clock.timeZone, ...opts })
  } catch {
    return d.toLocaleString('en-GB', opts)   // unbekannte Zone im Browser
  }
}
export const fmtDateTime = (v) => fmt(v, {})
export const fmtStamp = (v) => fmt(v, { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })
export const fmtDay = (v) => fmt(v, { day: '2-digit', month: 'short' })
export const fmtDayOnly = (v) => fmt(v, { day: '2-digit', month: '2-digit', year: 'numeric' })
export const fmtClock = (v) => fmt(v, { hour: '2-digit', minute: '2-digit' })
export const fmtClockSec = (v) => fmt(v, { hour: '2-digit', minute: '2-digit', second: '2-digit' })
export const fmtWeekdayTime = (v) => fmt(v, { weekday: 'short', hour: '2-digit', minute: '2-digit' })

// Stunden seit einem Zeitpunkt, für "vor 5 min"
export const hoursSince = (v) => {
  const d = parseTime(v)
  return d ? (Date.now() - d.getTime()) / 3.6e6 : null
}
export const ago = (h) => (h === null || h === undefined ? 'never' : h < 1 / 60 ? 'just now' : h < 1 ? `${Math.round(h * 60)} min ago` : h < 48 ? `${Math.round(h)} h ago` : `${Math.round(h / 24)} d ago`)
export const timeAgo = (v) => ago(hoursSince(v))

export async function loadTimeZone() {
  try {
    clock.timeZone = (await api.get('/api/settings/timezone')).timezone || 'UTC'
  } catch {
    /* ohne Anmeldung oder älterer Server: UTC */
  }
}
