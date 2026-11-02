import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createMemoryHistory, createRouter } from 'vue-router'
import { setCsrf } from '../src/api.js'
import HealthApiSettings from '../src/components/HealthApiSettings.vue'
import HealthMonitorForm from '../src/components/HealthMonitorForm.vue'
import PageTabs from '../src/components/PageTabs.vue'
import HealthView from '../src/views/HealthView.vue'

let calls
const json = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json' } })
const OPTIONS = { fritz: false, kinds: [
  { kind: 'ping', label: 'Ping', available: true, reason: '' },
  { kind: 'tcp', label: 'TCP port', available: true, reason: '' },
  { kind: 'fritz_host', label: 'FRITZ!Box device', available: false, reason: 'Set up the FRITZ!Box connector under Settings → Integrations' },
  { kind: 'heartbeat', label: 'Heartbeat', available: true, reason: '' },
  { kind: 'agent', label: 'Agent', available: false, reason: 'Added automatically for agent hosts' },
] }
const MON = { id: 1, name: 'pve', slug: 'pve', host: '192.0.2.5', critical: true, paused: false, auto: true, state: 'down', since: 1, warning: '',
  latency_ms: 2.4, uptime: { '24h': 99.5, '7d': 99.9, '30d': null }, segments: [{ state: 'up', uptime: 100 }, { state: 'down', uptime: 0 }],
  checks: [{ id: 1, kind: 'agent', label: 'Agent', params: {}, state: 'down', stale: false, latency_ms: null, error: 'agent silent' }] }

function router() {
  return createRouter({ history: createMemoryHistory(), routes: [{ path: '/:p(.*)*', component: { template: '<div />' } }] })
}

beforeEach(() => {
  setCsrf('tok')
  calls = []
  vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
    calls.push({ url, method: init.method || 'GET', body: init.body ? JSON.parse(init.body) : null })
    if (url === '/api/health/overview') {
      return json({ engine: { ok: true, last_tick: 1 }, summary: { up: 0, degraded: 0, down: 1, unknown: 0, paused: 0, total: 1 },
        monitors: [MON], incidents: [{ monitor_id: 1, name: 'pve', ts: 1800000000, detail: '' }], fritz: false })
    }
    if (url === '/api/health/options') return json(OPTIONS)
    if (url === '/api/health/tokens' && init.method === 'POST') return json({ id: 1, token: 'vwh_secret' })
    if (url === '/api/health/tokens') return json([])
    if (url === '/api/health/webhooks' && init.method === 'POST') return json({ id: 1, secret: 'vwhs_key' })
    if (url === '/api/health/webhooks') return json([])
    if (url === '/api/health/monitors' && init.method === 'POST') return json({ id: 2, slug: 'nas', heartbeat_tokens: {} })
    return json({}, 404)
  }))
})

afterEach(() => {
  vi.unstubAllGlobals()
  setCsrf(null)
})

describe('PageTabs', () => {
  const Host = {
    components: { PageTabs },
    template: `<PageTabs :tabs="[{ key: 'a', label: 'A' }, { key: 'b', label: 'B', count: 3, tone: 'danger' }]">
      <template #a><p class="pa">first</p></template><template #b><p class="pb">second</p></template></PageTabs>`,
  }

  it('shows the first tab, switches on click and keeps the tab in the address', async () => {
    const r = router()
    await r.push('/x')
    const w = mount(Host, { global: { plugins: [r] } })
    expect(w.find('.pa').exists()).toBe(true)
    await w.findAll('[role="tab"]')[1].trigger('click')
    await flushPromises()
    expect(r.currentRoute.value.query.tab).toBe('b')
    expect(w.find('.pb').exists()).toBe(true)
    expect(w.findAll('[role="tab"]')[1].attributes('aria-selected')).toBe('true')
    await w.find('[role="tablist"]').trigger('keydown', { key: 'ArrowRight' })
    await flushPromises()
    expect(r.currentRoute.value.query.tab).toBeUndefined()   // zurück auf den ersten Reiter
  })

  it('opens the tab named in the address', async () => {
    const r = router()
    await r.push('/x?tab=b')
    const w = mount(Host, { global: { plugins: [r] } })
    expect(w.find('.pb').exists()).toBe(true)
  })
})

describe('HealthView', () => {
  it('shows status with outages and the settings tab with the agent host', async () => {
    const r = router()
    await r.push('/gesundheit')
    const w = mount(HealthView, { global: { plugins: [r] } })
    await flushPromises()
    expect(w.text()).toContain('pve')
    expect(w.text()).toContain('99.50%')
    expect(w.text()).toContain('Critical availability 24 h')
    expect(w.text()).toContain('all hosts 99.50%')
    expect(w.find('.row.down').exists()).toBe(true)
    await r.push('/gesundheit?tab=settings')
    await flushPromises()
    expect(w.text()).toContain('Monitored hosts')
    expect(w.text()).toContain('API for other devices')
  })
})

describe('HealthMonitorForm', () => {
  it('offers FRITZ!Box checks only with the connector and posts the generated config', async () => {
    const w = mount(HealthMonitorForm, { props: { options: OPTIONS }, global: { plugins: [router()] } })
    const fritz = w.findAll('option').find((o) => o.text().startsWith('FRITZ!Box: device active'))
    expect(fritz.attributes('disabled')).toBeDefined()
    expect(fritz.text()).toContain('Integrations')

    await w.find('input[placeholder="e.g. TrueNAS"]').setValue('NAS')
    await w.find('input[placeholder="REDACTED"]').setValue('192.0.2.20')
    await w.findAll('.chip').find((b) => b.text() === 'SMB').trigger('click')
    await w.find('form').trigger('submit')
    await flushPromises()
    const post = calls.find((c) => c.method === 'POST')
    expect(post.body.name).toBe('NAS')
    expect(post.body.checks.map((c) => [c.kind, c.params.port ?? null])).toEqual([['ping', null], ['tcp', 445]])
    expect(w.emitted('saved')).toBeTruthy()
  })
})

describe('HealthApiSettings', () => {
  it('shows a new token and a new webhook key once, without examples', async () => {
    const w = mount(HealthApiSettings)
    await flushPromises()
    expect(w.text()).not.toContain('ESP32')
    expect(w.find('.cmd-block').exists()).toBe(false)

    await w.find('input[aria-label="Token name"]').setValue('LED')
    await w.findAll('form')[0].trigger('submit')
    await flushPromises()
    expect(w.find('.cmd-text').text()).toBe('vwh_secret')
    expect(w.text()).toContain('Token for LED · shown only now')

    await w.find('input[aria-label="Webhook name"]').setValue('Shelf')
    await w.find('input[aria-label="Webhook URL"]').setValue('http://192.168.1.50/hook')
    await w.findAll('form')[1].trigger('submit')
    await flushPromises()
    expect(calls.find((c) => c.url === '/api/health/webhooks' && c.method === 'POST').body).toEqual({ name: 'Shelf', url: 'http://192.168.1.50/hook' })
    expect(w.find('.cmd-text').text()).toBe('vwhs_key')
    expect(w.text()).toContain('Signing key for Shelf')
  })
})
