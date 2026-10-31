// Gemeinsames der Gesundheitsseite: Zustände, Prüfarten mit Feldern und Vorgaben, Formatierung.

export const STATE = {
  up: { label: 'Up', tone: 'ok', color: 'var(--ok)' },
  degraded: { label: 'Degraded', tone: 'warning', color: 'var(--warn)' },
  down: { label: 'Down', tone: 'danger', color: 'var(--danger)' },
  unknown: { label: 'Unknown', tone: 'neutral', color: 'var(--line-strong)' },
  paused: { label: 'Paused', tone: 'neutral', color: 'var(--surface-3)' },
}
export const stateOf = (s) => STATE[s] || STATE.unknown

// Felder je Prüfart: Der Generator zeigt genau diese; die Vorgaben entsprechen denen des Servers
export const KINDS = {
  ping: { label: 'Ping (ICMP)', hint: 'Is the host reachable at all?', fields: ['target'], defaults: { target: '' } },
  tcp: { label: 'TCP port', hint: 'Is a service listening (SSH 22, SMB 445, RDP 3389 …)?', fields: ['target', 'port'], defaults: { target: '', port: 22 } },
  http: {
    label: 'HTTP(S)', hint: 'Does a web UI or API answer with the expected status, optionally containing a text?',
    fields: ['target', 'scheme', 'port', 'path', 'method', 'expect', 'match', 'verify_tls', 'follow_redirects', 'auth'],
    defaults: { target: '', scheme: 'http', port: 80, path: '/', method: 'GET', expect: '2xx', match: '', verify_tls: true, follow_redirects: true },
  },
  tls: { label: 'TLS certificate', hint: 'Turns degraded before a certificate expires, down once it has.', fields: ['target', 'port', 'warn_days', 'server_name'], defaults: { target: '', port: 443, warn_days: 14, server_name: '' } },
  dns: { label: 'DNS server', hint: 'Does a resolver (AdGuard Home, Pi-hole) answer queries?', fields: ['target', 'port', 'name', 'rtype'], defaults: { target: '', port: 53, name: 'example.com', rtype: 'A' } },
  fritz_host: { label: 'FRITZ!Box: device active', hint: 'Asks the router whether it sees the device. Catches phones and laptops in Wi-Fi power save that ignore ping.', fields: ['fritz_target'], defaults: { target: '' } },
  fritz_wan: { label: 'FRITZ!Box: internet', hint: 'Is the internet connection actually up (DSL, cable or fibre)?', fields: [], defaults: {} },
  heartbeat: { label: 'Heartbeat (push)', hint: 'The device calls a URL regularly. Silence means down; “?state=down” reports a shutdown instantly.', fields: ['grace_s'], defaults: { grace_s: 30 } },
  agent: { label: 'vulnwatch agent', hint: 'The agent’s live connection to vulnwatch. Added automatically on agent hosts.', fields: [], defaults: {} },
}

// Schnellwahl im Generator: häufige Dienste mit passenden Einstellungen
export const PRESETS = [
  { label: 'Ping', kind: 'ping', params: {} },
  { label: 'SSH', kind: 'tcp', params: { port: 22 } },
  { label: 'SMB', kind: 'tcp', params: { port: 445 } },
  { label: 'RDP', kind: 'tcp', params: { port: 3389 } },
  { label: 'Web UI', kind: 'http', params: { scheme: 'http', port: 80 } },
  { label: 'HTTPS', kind: 'http', params: { scheme: 'https', port: 443 } },
  { label: 'Home Assistant', kind: 'http', params: { scheme: 'http', port: 8123 } },
  { label: 'Proxmox', kind: 'http', params: { scheme: 'https', port: 8006, verify_tls: false } },
  { label: 'Proxmox Backup', kind: 'http', params: { scheme: 'https', port: 8007, verify_tls: false } },
  { label: 'TrueNAS', kind: 'http', params: { scheme: 'https', port: 443, verify_tls: false } },
  { label: 'Synology DSM', kind: 'http', params: { scheme: 'https', port: 5001, verify_tls: false } },
  { label: 'UGREEN NAS', kind: 'http', params: { scheme: 'https', port: 9443, verify_tls: false } },
  { label: 'QNAP', kind: 'http', params: { scheme: 'https', port: 443, verify_tls: false } },
  { label: 'Unraid', kind: 'http', params: { scheme: 'http', port: 80 } },
  { label: 'OPNsense', kind: 'http', params: { scheme: 'https', port: 443, verify_tls: false } },
  { label: 'pfSense', kind: 'http', params: { scheme: 'https', port: 443, verify_tls: false } },
  { label: 'UniFi', kind: 'http', params: { scheme: 'https', port: 443, verify_tls: false } },
  { label: 'OpenWrt', kind: 'http', params: { scheme: 'http', port: 80 } },
  { label: 'Pi-hole', kind: 'dns', params: {} },
  { label: 'AdGuard Home', kind: 'dns', params: {} },
  { label: 'DNS', kind: 'dns', params: {} },
  { label: 'Certificate', kind: 'tls', params: {} },
]

export function newCheck(kind, params = {}) {
  return {
    kind, params: { ...KINDS[kind].defaults, ...params },
    interval_s: kind === 'heartbeat' ? 60 : 30, retry_s: 10, timeout_s: 5, fails_degraded: 2, fails_down: 4, paused: false, auth: null,
  }
}

export const fmtMs = (v) => (v == null ? '–' : v < 10 ? `${v.toFixed(1)} ms` : `${Math.round(v)} ms`)
export const fmtPct = (v) => (v == null ? '–' : v >= 99.995 ? '100%' : `${v.toFixed(v >= 99 ? 2 : 1)}%`)
export function fmtDuration(s) {
  if (s == null) return '–'
  if (s < 90) return `${Math.round(s)} s`
  if (s < 5400) return `${Math.round(s / 60)} min`
  if (s < 172800) return `${Math.round(s / 3600)} h`
  return `${Math.round(s / 86400)} d`
}
// Kategoriale Farben für mehrere Prüfungen in einem Diagramm (keine Zustandsfarben)
export const SERIES_COLORS = ['var(--info)', 'var(--high)', 'var(--ok)', 'var(--med)', 'var(--crit)']
