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
  source: 'about.gitlab.com', published: '2026-10-25T00:00:00+00:00', retryable: false,
  actions: [{ system: 'host-a', text: 'Update gitlab', command: 'apt install gitlab' },
            { system: 'host-b', text: 'Update gitlab', command: 'apt install gitlab' },
            { system: 'pi', text: 'Fixed version not confirmed yet', command: '' }] }

beforeEach(() => {
  setCsrf('tok')
  calls = []
  vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
    calls.push({ url, method: init.method || 'GET', body: init.body ? JSON.parse(init.body) : null })
    if (url.startsWith('/api/early-warnings') && (init.method || 'GET') === 'GET') {
      return json({ items: [WARNING, { ...WARNING, id: 2, status: 'unklar', exploited: 'unbekannt', detail: 'AI evaluation failed: Claude API HTTP 401', retryable: true }],
        counts: { betroffen: 1, unklar: 1 },
        state: { at: 1761400000, keywords: 12, feed_errors: { 'https://bad': 'HTTP 503', 'https://github.com/dani-garcia/vaultwarden/releases.atom': 'HTTP 404' } },
        feeds: ['https://f'], products: [], ai_configured: true,
        health: [{ key: 'research', text: 'Web research failed: Anthropic: limit (HTTP 400)', since: 1761400000 }],
        coverage: { at: 1761400000, window_days: 30, errors: {},
          kev: [{ cve: 'CVE-2026-1', title: 'Plex Media Server: CVE-2026-1 exploited', added: '2026-10-20', status: 'related', lead_days: -6 },
                { cve: 'CVE-2026-2', title: 'GitLab: CVE-2026-2 exploited', added: '2026-10-21', status: 'early', lead_days: 2 }],
          ghsa: [], counts: { early: 1, late: 0, related: 1, kev_only: 0, missed: 0, ghsa_seen: 0, ghsa_possible: 0 } } })
    }
    if (url === '/api/early-warnings/2/retry') return json({ ok: true })
    if (url === '/api/early-warnings/coverage-check') return json({ ok: true, started: true })
    if (url.startsWith('/api/history')) {
      return json({ runs: [
        { id: 1, started_at: '2026-10-24T03:00:00+00:00', counts: { kritisch: 2, hoch: 5 }, coverage_percent: 80, duration_min: 17 },
        { id: 2, started_at: '2026-10-25T03:00:00+00:00', counts: { kritisch: 1, hoch: 3 }, coverage_percent: 100, duration_min: 20 },
      ], time_to_fix: [] })
    }
    if (url.endsWith('/fixed')) return json({ ok: true, status: 'behoben', confirmed: false })
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
    expect(w.text()).toContain('dani-garcia/vaultwarden: HTTP 404')   // Release-Feeds: das Repo statt github.com
    expect(w.get('[data-test="health"]').text()).toContain('Web research failed: Anthropic: limit (HTTP 400)')
    const cov = w.get('[data-test="coverage"]').text()
    expect(w.get('[data-test="coverage-count-early"]').text()).toBe('Warned early1')
    expect(w.get('[data-test="coverage-count-related"]').text()).toBe('Same product, no CVE1')
    expect(w.get('[data-test="coverage-count-missed"]').classes()).toContain('zero')
    expect(cov).toContain('same product, no CVE')
    expect(cov).toContain('Plex Media Server CVE-2026-1')
    expect(cov).toContain('warning 6 days after')
    expect(cov).not.toContain('GitLab: CVE-2026-2')   // früh gewarnt: keine Lücke
    await w.get('[data-test="coverage-now"]').trigger('click')
    expect(calls.some((x) => x.url === '/api/early-warnings/coverage-check' && x.method === 'POST')).toBe(true)
    expect(w.text()).toContain('Affected1')
    expect(w.findAll('[data-test="retry"]')).toHaveLength(1)   // nur der KI-Fehler bekommt einen neuen Versuch
    expect(w.get('[data-test="retry"]').text()).toBe('Ask again')   // anbieterneutral
    expect(w.text()).not.toMatch(/Ask Claude|No Claude|Claude API key/)
    await w.get('[data-test="retry"]').trigger('click')
    await flushPromises()
    expect(calls.some((c) => c.url === '/api/early-warnings/2/retry' && c.method === 'POST')).toBe(true)
  })

  it('meldet eine Meldung als behoben und zeigt, was noch nicht bestätigt oder widerlegt ist', async () => {
    const w = mount(EarlyWarningsView)
    await flushPromises()
    expect(w.findAll('[data-test="mark-fixed"]')).toHaveLength(2)   // betroffen und zu prüfen
    expect(w.find('[data-test="reopen"]').exists()).toBe(false)
    await w.get('[data-test="mark-fixed"]').trigger('click')
    await flushPromises()
    expect(calls.find((c) => c.url === '/api/early-warnings/1/fixed')).toMatchObject({ method: 'POST', body: { fixed: true } })
    expect(calls.filter((c) => c.url === '/api/early-warnings' && c.method === 'GET')).toHaveLength(2)   // neu geladen

    fetch.mockImplementation(async (url, init = {}) => {
      calls.push({ url, method: init.method || 'GET', body: init.body ? JSON.parse(init.body) : null })
      return json({ items: [
        { ...WARNING, status: 'behoben', actions: [], fix_claimed_at: '2026-11-11T10:00:00+00:00' },
        { ...WARNING, id: 2, fix_refuted_at: '2026-11-11T11:00:00+00:00' }], counts: { behoben: 1, betroffen: 1 },
        state: {}, feeds: [], products: [], ai_configured: true })
    })
    const v = mount(EarlyWarningsView)
    await flushPromises()
    expect(v.get('[data-test="fix-claimed"]').text()).toContain('not confirmed yet')
    expect(v.get('[data-test="fix-refuted"]').text()).toContain('still reports an affected version')
    expect(v.findAll('[data-test="mark-fixed"]')).toHaveLength(1)   // die widerlegte lässt sich erneut melden
    await v.get('[data-test="reopen"]').trigger('click')
    await flushPromises()
    expect(calls.find((c) => c.url === '/api/early-warnings/1/fixed' && c.body.fixed === false)).toBeTruthy()
  })

  it('fasst gleiche Schritte mehrerer Hosts in einer Zeile zusammen', async () => {
    const w = mount(EarlyWarningsView)
    await flushPromises()
    const steps = w.findAll('.ew-steps li').map((li) => li.get('.ew-step-text').text())
    expect(steps.slice(0, 2)).toEqual(['host-a, host-b Update gitlab', 'pi Fixed version not confirmed yet'])
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
