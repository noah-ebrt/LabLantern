import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import PipelineFlow from '../src/components/PipelineFlow.vue'

const minutesAgo = (m) => new Date(Date.now() - m * 60000).toISOString().replace('Z', '')   // wie SQLite: ohne Offset
const data = {
  ampel: 'gelb', coverage_percent: 90, canary_status: 'ok', next_run: '2026-10-26T03:00:00+00:00',
  worker: { age_seconds: 30 }, active_run: null,
  short_run: { enabled: true, hours: 12, next_run: '2026-10-26T15:00:00+00:00' },
  early_warning: { at: Date.now() / 1000 - 600, ai_configured: true, feed_errors: 0, counts: { betroffen: 1, unklar: 2 } }, findings: { kritisch: 2, hoch: 5, mittel: 1, info: 0 },
  last_run: { id: 7, status: 'success', trigger: 'scheduled', started_at: minutesAgo(70),
    finished_at: minutesAgo(65), notify_status: 'sent', db_status: { ok: true, age_hours: 5 } },
  coverage: [
    { system_id: 1, system_name: 'nas', checks: {}, last_scan: { run_id: 7, at: minutesAgo(66) } },
    { system_id: 2, system_name: 'pi', checks: {}, last_scan: { run_id: 7, at: minutesAgo(66) } },
  ],
}
const systems = [
  { id: 1, name: 'nas', status: 'active', state: 'online', online: true, age_hours: 0.1, last_seen: minutesAgo(6) },
  { id: 2, name: 'pi', status: 'active', state: 'online', online: true, age_hours: 1.2, last_seen: minutesAgo(72) },
]

const ai = {
  providers: [{ id: 'anthropic', label: 'Anthropic', configured: true }, { id: 'c1', label: 'Ollama', configured: true }],
  tasks: { classify: { ref: '', resolved: 'c1:qwen3.8:27b', error: null } },
}
let fetchMock

beforeEach(() => {
  // Die Karte fragt /api/ai (Anbieter + Wahl je Aufgabe); die alte Route /api/integrations/claude gibt es nicht mehr
  fetchMock = vi.fn(async (url) => {
    const body = String(url).includes('/api/ai') ? ai : {}
    return new Response(JSON.stringify(body), { status: String(url).includes('/api/ai') ? 200 : 404, headers: { 'content-type': 'application/json' } })
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => vi.unstubAllGlobals())

const mountFlow = (d = data, s = systems) =>
  mount(PipelineFlow, { props: { data: d, systems: s }, global: { stubs: { RouterLink: true, HostDetailModal: true, RunDetailModal: true } } })
const node = (w, title) => w.findAll('.node').find((n) => n.find('.title').text() === title)

describe('PipelineFlow', () => {
  it('draws one node per agent and marks data newer than the last scan as waiting', () => {
    const w = mountFlow()
    expect(node(w, 'nas').text()).toContain('new data, waits for next run')
    expect(node(w, 'pi').text()).toContain('scanned in run #7')
    expect(w.text()).toContain('last report 6 min ago')
    expect(node(w, 'Schedule').text()).toContain('1 host waiting')
    expect(w.findAll('path.edge.wait')).toHaveLength(1)
    expect(node(w, 'AI early warning').text()).toContain('1 affects you · 2 to review')
    expect(w.text()).toContain('next full run')
  })

  it('adding an agent adds a node and an edge', () => {
    const w = mountFlow(data, [...systems, { id: 3, name: 'host-c', status: 'active', state: 'online', online: true, age_hours: 0, last_seen: minutesAgo(0) }])
    expect(node(w, 'host-c')).toBeTruthy()
    expect(w.findAll('path.edge').length).toBe(3 + 6)
  })

  it('opens the host popup, the run popup and the info popups', async () => {
    const w = mountFlow()
    await node(w, 'nas').trigger('click')
    expect(w.findComponent({ name: 'HostDetailModal' }).props('systemId')).toBe(1)
    await node(w, 'Run #7').trigger('click')
    expect(w.findComponent({ name: 'RunDetailModal' }).props('runId')).toBe(7)
    await flushPromises()
    await node(w, 'AI early warning').trigger('click')
    expect(w.find('.modal').text()).toContain('AI provider')
    expect(w.find('.modal').text()).toContain('Ollama (qwen3.8:27b)')
    expect(w.find('.modal').text()).not.toContain('Claude')
    expect(fetchMock.mock.calls.map((c) => String(c[0])).some((u) => u.includes('/api/integrations/claude'))).toBe(false)
  })

  it('says so when no provider is set or the classify model is not chosen yet', async () => {
    const calls = { providers: [{ id: 'c1', label: 'Ollama', configured: true }], tasks: { classify: { ref: '', resolved: null, error: 'choose a model (no automatic choice for this provider)' } } }
    fetchMock.mockImplementation(async () => new Response(JSON.stringify(calls), { status: 200, headers: { 'content-type': 'application/json' } }))
    const w = mountFlow()
    await flushPromises()
    await node(w, 'AI early warning').trigger('click')
    expect(w.find('.modal').text()).toContain('Ollama, no model chosen')
    const none = mountFlow({ ...data, early_warning: { ...data.early_warning, ai_configured: false } })
    expect(node(none, 'AI early warning').text()).toContain('no AI provider: review by hand')
    expect(node(none, 'AI early warning').text()).not.toContain('Claude')
  })

  it('Run now emits trigger; during collection agents that have not reported pulse', async () => {
    const w = mountFlow()
    await w.find('.node-action').trigger('click')
    expect(w.emitted('trigger')).toHaveLength(1)
    const collecting = mountFlow({ ...data, active_run: { run_id: 8, phase: 'collecting', started_at: minutesAgo(1), systems_reported: 0, systems_total: 2 } })
    expect(collecting.findAll('path.edge.active').length).toBeGreaterThanOrEqual(2)
    expect(collecting.find('.node-action').exists()).toBe(false)
  })
})
