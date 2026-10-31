// Reiter der Einstellungen, nach dem geordnet, was man erledigen will
export const SETTINGS_TABS = [
  { key: 'scanning', label: 'Scanning', icon: 'clock' },
  { key: 'alerts', label: 'Alerts & reports', icon: 'bell' },
  { key: 'exposure', label: 'Exposure', icon: 'link' },
  { key: 'ai', label: 'AI early warning', icon: 'sparkles' },
  { key: 'system', label: 'System', icon: 'settings' },
]

// Alte Reiter aus Lesezeichen und älteren Verweisen
export const OLD_TABS = { general: 'scanning', notifications: 'alerts', integrations: 'exposure', access: 'system', advanced: 'system' }

// Alles, was „Find a setting“ findet: Bezeichnung, Reiter, Ziel-id und Wörter, nach denen man suchen würde
export const SETTINGS_INDEX = [
  { label: 'Daily full run', tab: 'scanning', target: 'set-daily', words: 'schedule time scan nightly cron disable off' },
  { label: 'Short run', tab: 'scanning', target: 'set-short', words: 'quick rescan interval hours between' },
  { label: 'Time zone', tab: 'scanning', target: 'set-timezone', words: 'timezone utc clock' },
  { label: 'Version check', tab: 'scanning', target: 'set-versions', words: 'registry image outdated end of life eol endoflife docker hub update' },
  { label: 'Notification channels', tab: 'alerts', target: 'set-channels', words: 'mail email smtp ntfy telegram discord slack apprise push webhook test recipient' },
  { label: 'Scan report: how often', tab: 'alerts', target: 'set-report', words: 'daily weekly on change summary mail frequency' },
  { label: 'Pause the report', tab: 'alerts', target: 'set-pause', words: 'vacation holiday stop mute quiet' },
  { label: 'Offsite watchdog', tab: 'alerts', target: 'set-watchdog', words: 'healthchecks uptime kuma ping heartbeat dead man monitor' },
  { label: 'Sharp drop in findings', tab: 'alerts', target: 'set-drop', words: 'alert rule alarm fall tamper sbom compromised worker' },
  { label: 'Early warning failure alert', tab: 'ai', target: 'set-ai-sources', words: 'alert ai fails provider broken' },
  { label: 'Nginx Proxy Manager', tab: 'exposure', target: 'set-npm', words: 'npm proxy internet exposed reverse' },
  { label: 'FRITZ!Box port forwards', tab: 'exposure', target: 'set-fritz', words: 'fritzbox router tr-064 tr064 port forward avm' },
  { label: 'Cloudflare Tunnel', tab: 'exposure', target: 'set-cf', words: 'cloudflared tunnel api token' },
  { label: 'Traefik', tab: 'exposure', target: 'set-traefik', words: 'labels entrypoints router' },
  { label: 'TLS certificates', tab: 'exposure', target: 'set-certs', words: 'certificate ssl https expiry renew' },
  { label: 'AI provider and API key', tab: 'ai', target: 'set-ai-provider', words: 'anthropic claude openai ollama key llm compatible' },
  { label: 'Models per task', tab: 'ai', target: 'set-ai-models', words: 'model haiku sonnet classify research vendor' },
  { label: 'AI level', tab: 'ai', target: 'set-ai-level', words: 'full balanced minimal agentic cost' },
  { label: 'KEV, release feeds, coverage check', tab: 'ai', target: 'set-ai-sources', words: 'sources safety nets cisa github weekly' },
  { label: 'AI intervals', tab: 'ai', target: 'set-ai-tune', words: 'feeds hours research searches fine-tune' },
  { label: 'AI cost estimate', tab: 'ai', target: 'set-ai-cost', words: 'price money dollar month budget' },
  { label: 'Passkeys', tab: 'system', target: 'set-passkeys', words: 'login webauthn yubikey sign in security key trust' },
  { label: 'Agent release', tab: 'system', target: 'set-release', words: 'agent version update signing key build' },
  { label: 'Prometheus metrics', tab: 'system', target: 'set-metrics', words: 'grafana metrics token scrape' },
  { label: 'Configuration as JSON', tab: 'system', target: 'set-config', words: 'export import backup json api download' },
]

// Jedes Suchwort muss in Bezeichnung oder Wörtern vorkommen; Treffer in der Bezeichnung zuerst
export function findSettings(query) {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean)
  if (!terms.length) return []
  return SETTINGS_INDEX
    .map((e) => {
      const label = e.label.toLowerCase()
      const all = `${label} ${e.words}`
      if (!terms.every((t) => all.includes(t))) return null
      const score = terms.reduce((n, t) => n + (label.startsWith(t) ? 3 : label.includes(t) ? 2 : 1), 0)
      return { ...e, score }
    })
    .filter(Boolean)
    .sort((a, b) => b.score - a.score)
}
