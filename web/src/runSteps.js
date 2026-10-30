import { ref } from 'vue'
import { api } from './api.js'

// Ablauf eines Scan-Laufs, einmal beschrieben und von Fortschrittskarte, Pipeline und Laufdetails genutzt.
// Grundlage ist overview.active_run: phase (collecting/scanning), beim Sammeln systems_reported/total,
// beim Scannen progress = letzter Schritt des Workers (step, host, host_index, image_index …).

export const STEPS = [
  { key: 'collecting', label: 'Collecting fresh data from the agents' },
  { key: 'database', label: 'Updating the vulnerability database' },
  { key: 'canary', label: 'Canary test' },
  { key: 'scan', label: 'Scanning hosts and images' },
  { key: 'saving', label: 'Saving and rating findings' },
]

// Aktueller Schritt; null, wenn kein Lauf aktiv ist
export function currentStep(run) {
  if (!run) return null
  if (run.phase === 'collecting') return 'collecting'
  const s = run.progress?.step
  // host/image: älterer Worker (der Reihe nach); download/scan: paralleler Worker; osv: zweite Quelle, gleicher Schritt
  return ['host', 'image', 'download', 'scan', 'osv'].includes(s) ? 'scan' : s || 'database'
}

export const stepNumber = (run) => STEPS.findIndex((s) => s.key === currentStep(run)) + 1

// 'done' | 'active' | 'pending' für einen Schritt; ohne aktiven Lauf ist nichts aktiv
export function stepState(key, run) {
  const cur = stepNumber(run)
  if (!cur) return 'pending'
  const i = STEPS.findIndex((s) => s.key === key) + 1
  return i < cur ? 'done' : i === cur ? 'active' : 'pending'
}

// Fortschritt in Prozent: Sammeln bis 30, Datenbank/Kanarie bis 40, Hosts und Images anteilig bis 95
export function percent(run) {
  if (!run) return 0
  if (run.phase === 'collecting') return run.systems_total ? Math.round((run.systems_reported / run.systems_total) * 30) : 5
  const p = run.progress || {}
  if (p.step === 'database') return 33
  if (p.step === 'canary') return 38
  if (p.step === 'saving') return 97
  if (p.step === 'download') return 40
  if (p.step === 'scan') return Math.round(40 + 50 * ((p.done || 0) / Math.max(1, p.total || 1)))
  if (p.step === 'osv') return 92
  if (p.hosts_total) {
    const inHost = p.images_total ? (p.image_index || 0) / (p.images_total + 1) : 0
    return Math.round(40 + 55 * ((p.host_index - 1 + inHost) / p.hosts_total))
  }
  return 33
}

// Rolle eines Hosts im laufenden Scan. Der Worker scannt in der Reihenfolge der Namen (wie die Datenbank sortiert:
// Großbuchstaben vor Kleinbuchstaben, daher einfacher Zeichenvergleich statt localeCompare).
export function hostInScan(name, run) {
  if (currentStep(run) !== 'scan' && currentStep(run) !== 'saving') return null
  const p = run.progress || {}
  if (currentStep(run) === 'saving') return { state: 'done', text: 'scanned' }
  if (!p.host) return { state: 'active', text: 'scanning' }   // paralleler Worker: alle Hosts gleichzeitig
  if (name < p.host) return { state: 'done', text: 'scanned' }
  if (name !== p.host) return { state: 'pending', text: 'queued for scanning' }
  return p.step === 'image'
    ? { state: 'active', text: `scanning image ${p.image_index} of ${p.images_total}` }
    : { state: 'active', text: p.images_total ? `scanning packages, then ${p.images_total} images` : 'scanning packages' }
}

// Kurzbeschreibung des aktuellen Stands für eine Zeile
export function stepSummary(run) {
  if (!run) return ''
  if (run.phase === 'collecting') return `${run.systems_reported ?? 0} of ${run.systems_total ?? 0} hosts ready`
  const p = run.progress || {}
  if (p.step === 'host' || p.step === 'image') {
    return `${p.host} · host ${p.host_index}/${p.hosts_total}${p.step === 'image' ? ` · image ${p.image_index}/${p.images_total}` : ''}`
  }
  return p.text || 'waiting for the worker…'
}

// "Scan now" (Übersicht, Läufe, Pipeline): Lauf starten, danach `after` (z. B. neu laden); Fehler landen in `error`
export function useScanTrigger({ after, error = ref('') } = {}) {
  const triggering = ref(false)
  const message = ref('')
  // full: Agenten um frische Daten bitten, scannen, Versionen und KI-Frühwarnung prüfen
  // latest: sofort die zuletzt automatisch gemeldeten Agentendaten scannen und bewerten
  async function trigger(mode = 'full') {
    triggering.value = true
    message.value = ''
    error.value = ''
    try {
      const res = await api.post('/api/runs/trigger', { mode: mode === 'latest' ? 'latest' : 'full' })
      message.value = res.mode === 'latest'
        ? `Run #${res.run_id} started with the latest agent data: scan and rating begin right away.`
        : `Run #${res.run_id} started: agents report fresh data within seconds, then scan, version check and AI early warning run.`
      await after?.()
    } catch (e) {
      error.value = e.message
    } finally {
      triggering.value = false
    }
  }
  return { triggering, message, trigger }
}
