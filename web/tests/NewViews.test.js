import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import EarlyWarningsView from '../src/views/EarlyWarningsView.vue'
import HistoryView from '../src/views/HistoryView.vue'
import { setCsrf } from '../src/api.js'

let calls
const json = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json' } })
const WARNING = { id: 1, title: 'GitLab Critical Patch Release', link: 'https://example.org/gl', feed: 'https://f', published: '',
  status: 'betroffen', exploited: 'ja', cves: ['CVE-2026-110264'], detail: 'affected: gitlab 19.5.1 on host-b',
  matched: [{ product: 'gitlab/gitlab-ce:19.5.1-ce.0', version: '19.5.1-ce.0', system: 'host-b' }], affected: [],
  source: 'about.gitlab.com', published: '2026-10-25T00:00:00+00:00', retryable: false }

beforeEach(() => {
  setCsrf('tok')
  calls = []
  vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
    calls.push({ url, method: init.method || 'GET', body: init.body ? JSON.parse(init.body) : null })
    if (url.startsWith('/api/early-warnings') && (init.method || 'GET') === 'GET') {
      return json({ items: [WARNING, { ...WARNING, id: 2, status: 'unklar', exploited: 'unbekannt', detail: 'AI evaluation failed: Claude API HTTP 401', retryable: true }],
        counts: { betroffen: 1, unklar: 1 },
        state: { at: 1761400000, keywords: 12, feed_errors: { 'https://bad': 'HTTP 503' } }, feeds: ['https://f'], products: [], ai_configured: true })
    }
    if (url === '/api/early-warnings/2/retry') return json({ ok: true })
    if (url.startsWith('/api/history')) {
      return json({ runs: [
        { id: 1, started_at: '2026-10-24T03:00:00+00:00', counts: { kritisch: 2, hoch: 5 }, coverage_percent: 80, duration_min: 17 },
        { id: 2, started_at: '2026-10-25T03:00:00+00:00', counts: { kritisch: 1, hoch: 3 }, coverage_percent: 100, duration_min: 20 },
      ], time_to_fix: [] })
    }
    return json({}, 404)
  }))
})

afterEach(() => {
  vi.unstubAllGlobals()
  setCsrf(null)
})

describe('EarlyWarningsView', () => {
  it('zeigt Einstufung, Ausnutzung, Feed-Fehler und erlaubt erneutes Bewerten', async () => {
    const w = mount(EarlyWarningsView)
    await flushPromises()
    expect(w.text()).toContain('Affected')
    expect(w.text()).toContain('Exploited')
    expect(w.text()).toContain('CVE-2026-110264')
    expect(w.text()).toContain('bad: HTTP 503')
    expect(w.text()).toContain('Affected1')
    expect(w.findAll('button.btn-sm')).toHaveLength(1)   // nur der KI-Fehler bekommt einen neuen Versuch
    expect(w.get('button.btn-sm').text()).toBe('Ask again')   // anbieterneutral
    expect(w.text()).not.toMatch(/Ask Claude|No Claude|Claude API key/)
    await w.get('button.btn-sm').trigger('click')
    await flushPromises()
    expect(calls.some((c) => c.url === '/api/early-warnings/2/retry' && c.method === 'POST')).toBe(true)
  })
})

describe('HistoryView', () => {
  it('zeichnet die Verläufe und meldet fehlende Behebungen', async () => {
    const w = mount(HistoryView)
    await flushPromises()
    expect(w.findAll('polyline').length).toBeGreaterThanOrEqual(4)
    expect(w.text()).toContain('No critical or high finding was resolved')
  })
})
