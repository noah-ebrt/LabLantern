import { api } from './api.js'
import { LEVELS, estimate, fmtUsd } from './aicost.js'
import { fmtDayOnly, fmtWeekdayTime } from './time.js'

const WEEKDAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

// Kopfzeile der Einstellungen: der wichtigste Zustand je Bereich (wie die Statuszeile der Übersicht) und die
// Probleme je Reiter für die Zähler an den Reitern. Ein Endpunkt, der nicht antwortet, lässt nur seinen Punkt weg.
export async function loadSettingsSummary() {
  const get = (url) => api.get(url).catch(() => null)
  const [schedule, report, notify, watchdog, npm, fritz, cf, level, ai, passkeys, release] = await Promise.all([
    get('/api/settings/schedule'), get('/api/settings/report-policy'), get('/api/integrations/notifications'),
    get('/api/settings/watchdog'), get('/api/settings/npm'), get('/api/settings/fritzbox'), get('/api/settings/cftunnel'),
    get('/api/early-warnings/ai-level'), get('/api/ai'), get('/api/passkeys'), get('/api/settings/releases'),
  ])
  const items = []
  const problems = { scanning: [], alerts: [], exposure: [], ai: [], system: [] }
  const item = (label, value, tab, target, tone = '') => items.push({ label, value, tab, target, tone })
  const problem = (tab, text, tone = 'warning') => problems[tab].push({ text, tone })

  if (schedule) {
    item('Next run', schedule.enabled && schedule.next_run ? fmtWeekdayTime(schedule.next_run) : 'off', 'scanning', 'set-daily',
      schedule.enabled ? '' : 'warning')
    if (!schedule.enabled) problem('scanning', 'The daily run is off')
  }

  if (report) {
    const often = report.frequency === 'weekly' ? `weekly, ${WEEKDAYS[report.weekday ?? 0]}` : report.frequency === 'on_change' ? 'on change' : 'daily'
    item('Report', report.paused_until ? `paused until ${fmtDayOnly(report.paused_until)}` : often, 'alerts', 'set-report',
      report.paused_until ? 'warning' : '')
  }
  if (notify) {
    const n = notify.channels?.length || 0
    item('Channels', String(n), 'alerts', 'set-channels', n ? '' : 'danger')
    if (!n) problem('alerts', 'No notification channel', 'danger')
  }
  if (watchdog) {
    const checks = ['heartbeat', 'run', 'short'].filter((k) => watchdog[k]?.set)
    const failing = checks.some((k) => watchdog[k].last && !watchdog[k].last.ok)
    item('Watchdog', !checks.length ? 'not set up' : failing ? 'ping failing' : 'active', 'alerts', 'set-watchdog', failing ? 'danger' : '')
    if (failing) problem('alerts', 'A watchdog ping is failing', 'danger')
  }

  const sources = [npm, fritz, cf].filter(Boolean)
  if (sources.length) {
    const connected = sources.filter((s) => s.config)
    const failing = connected.filter((s) => s.state?.configured && !s.state.ok).length
    item('Exposure', failing ? `${failing} failing` : `${connected.length} of 3`, 'exposure', 'set-npm', failing ? 'danger' : '')
    if (failing) problem('exposure', `${failing} exposure source${failing > 1 ? 's' : ''} failing`, 'danger')
  }

  if (level) {
    const label = LEVELS.find((l) => l.id === level.level)?.label || level.level
    const cost = level.basis ? ` · ${fmtUsd(estimate(level.basis, level, level.research).total)}/mo` : ''
    item('AI', `${label}${cost}`, 'ai', 'set-ai-level')
  }
  if (ai) {
    if (!ai.providers?.some((p) => p.configured)) problem('ai', 'No AI provider set up')
    const broken = Object.values(ai.tasks || {}).filter((t) => t?.error).length
    if (broken) problem('ai', `${broken} AI task${broken > 1 ? 's' : ''} without a working model`, 'danger')
  }

  if (passkeys) {
    const n = passkeys.keys?.length || 0
    item('Passkeys', passkeys.trust?.outdated ? `${n} · key list to sign` : String(n), 'system', 'set-passkeys',
      !n || passkeys.trust?.outdated ? 'warning' : '')
    if (!n) problem('system', 'No passkey yet')
    if (passkeys.trust?.outdated) problem('system', 'The agents’ key list needs a signature')
  }
  if (release?.last_check && !release.last_check.ok) problem('system', 'The agent release check failed', 'danger')

  return { items, problems }
}
