// Kostenschätzung der KI-Frühwarnung: die Grundlage (gemessen, je Aufruf) kommt vom Server, der Monat wird hier
// je Stufe und Takt gerechnet, damit die Anzeige sofort folgt.

export const LEVELS = [
  { id: 'full', label: 'Fully agentic',
    text: 'Web research and the vendor check both run with AI and web search. Best coverage, highest cost.' },
  { id: 'balanced', label: 'Balanced',
    text: 'Web research less often. The vendor check uses the NVD first and AI only when the NVD has no analysis yet. Adds the CISA KEV catalog as a feed.' },
  { id: 'minimal', label: 'Minimal',
    text: 'No web research. The vendor check uses only the NVD. AI only reads matched feed advisories (the cheap model).' },
]

export const DEFAULT_RESEARCH_HOURS = { full: 20, balanced: 72, minimal: 72 }
export const MAX_VERIFY_PER_PASS = 3
const DAYS = 30

// Die Recherche läuft im ersten Durchgang nach Ablauf ihres Abstands
export function researchRunsPerMonth(passHours, researchHours) {
  return (DAYS * 24) / (Math.ceil(researchHours / passHours) * passHours)
}

// Anteil der Prüfungen, den die NVD beantwortet, solange nichts gemessen ist: im Nachspielen von 15 echten
// KI-Prüfungen (2026-10) nur 1 – Frühwarnungen nennen meist noch keine CVE, oder die NVD hat sie noch nicht analysiert
export const ASSUMED_NVD_SHARE = 0.1

// Anteil der Prüfungen, der eine KI braucht: full alle, balanced die ohne NVD-Analyse, minimal keine
export function aiCheckShare(level, nvdShare) {
  if (level === 'full') return 1
  if (level === 'balanced') return 1 - (nvdShare ?? ASSUMED_NVD_SHARE)
  return 0
}

export const SWITCHES = [
  { id: 'kev', label: 'CISA KEV catalog',
    text: 'Actively exploited vulnerabilities as an extra feed. Structured, free, and catches what the web research misses.' },
  { id: 'release_feeds', label: 'Release notes of your images',
    text: 'GitHub release feeds found from the images’ source label. Only releases that mention security reach the AI.' },
  { id: 'health_alerts', label: 'Alert when the early warning fails',
    text: 'A provider failing two passes in a row, failed web research, or a feed unreachable for a day. Also when it works again.' },
  { id: 'miss_check', label: 'Weekly coverage check',
    text: 'Compares exploited issues (KEV) and GitHub advisories for your products with the warnings you got, and reports gaps.' },
]

// Eine Recherche mit höchstens `maxSearches` Suchen: weniger Suchen lesen auch weniger Seiten (Token anteilig)
export function researchRunUsd(r, maxSearches, searchUsd) {
  if (!r.price) return r.usd
  const share = r.searches ? Math.min(1, maxSearches / r.searches) : 1
  return ((r.tokens_in * r.price[0] + r.tokens_out * r.price[1]) / 1e6) * share + Math.min(r.searches, maxSearches) * searchUsd
}

export function estimate(basis, cfg, research = { enabled: true, verify: true }) {
  const runs = cfg.level === 'minimal' || !research.enabled ? 0 : researchRunsPerMonth(cfg.pass_hours, cfg.research_hours)
  const checksPerDay = Math.min(basis.verify.per_day, (MAX_VERIFY_PER_PASS * 24) / cfg.pass_hours)
  const checks = research.verify ? checksPerDay * DAYS * aiCheckShare(cfg.level, basis.verify.nvd_share) : 0
  const rows = [
    { task: 'classify', label: 'Read feed advisories', count: basis.classify.per_day * DAYS, unit: 'calls' },
    { task: 'research', label: 'Web research', count: runs, unit: 'runs' },
    { task: 'verify', label: 'Vendor check with AI', count: checks, unit: 'checks' },
  ].map((r) => {
    const b = basis[r.task]
    const usd = r.task === 'research' ? researchRunUsd(b, cfg.max_searches ?? 15, basis.search_usd ?? 0.01) : b.usd
    return { ...r, model: b.model, usd, total: r.count === 0 ? 0 : usd == null ? null : r.count * usd }
  })
  const total = rows.some((r) => r.total == null) ? null : rows.reduce((sum, r) => sum + r.total, 0)
  return { rows, total }
}

export function fmtUsd(n) {
  if (n == null) return '—'
  if (n === 0) return '$0'
  if (n < 0.01) return '< $0.01'
  return `$${n < 100 ? n.toFixed(2) : Math.round(n)}`
}
