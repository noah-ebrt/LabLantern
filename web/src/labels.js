// Internal values come from the API in German; this maps them to English labels for display.
const LABELS = {
  ok: 'OK', fund: 'FINDING', fehler: 'ERROR', offen: 'QUEUED', na: 'N/A', excluded: 'EXCLUDED',
  kritisch: 'CRITICAL', hoch: 'HIGH', mittel: 'MEDIUM', info: 'INFO',
}
export const label = (v) => LABELS[v] ?? String(v ?? '').toUpperCase()
export { fmtDateTime as fmtDate } from './time.js'
export const fmtNum = (n) => (n ?? 0).toLocaleString('en-GB')

// Prüfungen der Abdeckungsmatrix (PLAN Abschnitt 6) in Anzeigereihenfolge
export const CHECKS = [
  ['paket_cve', 'Package CVEs'],
  ['sicherheitsupdates', 'Security updates'],
  ['reboot', 'Reboot'],
  ['container', 'Containers'],
  ['images', 'Container images'],
  ['versionen', 'Versions'],
]
export const CHECK_NAMES = Object.fromEntries(CHECKS)
export const checkClass = (s) => ({ ok: 'badge ok', fund: 'badge warning', fehler: 'badge danger' })[s] ?? 'badge neutral'

// Gesamtzustand aus overview.ampel
export const POSTURE = {
  gruen: { text: 'All systems as expected', cls: 'ok' },
  gelb: { text: 'Warnings present', cls: 'warning' },
  rot: { text: 'Action needed', cls: 'danger' },
  unbekannt: { text: 'No valid run yet', cls: 'neutral' },
}

// Zustand eines Hosts aus /api/systems (status, state, online) für Punkt und Kurztext
export function hostState(s) {
  if (s.status === 'connector') return s.state === 'online' ? { tone: 'ok', text: 'via API' } : { tone: 'bad', text: 'API failing' }
  if (s.status !== 'active') return { tone: 'idle', text: s.status }
  if (s.state === 'initializing') return { tone: 'warn', text: 'initializing…' }
  if (s.state === 'error') return { tone: 'bad', text: 'no first report' }
  if (s.state === 'offline') return { tone: 'bad', text: 'offline' }
  return s.online ? { tone: 'ok', text: 'connected' } : { tone: 'warn', text: 'not connected' }
}

// Geräte ohne Agent (Connectors) und Kurztext unter dem Hostnamen
export const APPLIANCE_KINDS = { truenas: 'TrueNAS', homeassistant: 'Home Assistant', proxmox: 'Proxmox VE' }
export const hostVersion = (s) => (s.connector ? `${APPLIANCE_KINDS[s.connector.kind]} ${s.connector.version || ''}`.trim()
  : `v${s.agent_version || '?'}`)

// Status eines Scan-Laufs
export const RUN_ACTIVE = ['collecting', 'queued', 'running']
export const RUN_STATUS = { success: 'Successful', partial: 'Partial (errors)', failed: 'Failed', collecting: 'Collecting data', queued: 'Queued', running: 'Scanning' }
export const runLabel = (st) => RUN_STATUS[st] || st
export const RUN_TRIGGER = { scheduled: 'daily run', manual: 'started by hand', short: 'short run' }
export const runBadge = (st) => (st === 'success' ? 'badge ok' : RUN_ACTIVE.includes(st) ? 'badge neutral' : 'badge danger')
