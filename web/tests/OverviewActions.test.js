import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import OverviewView from '../src/views/OverviewView.vue'
import FindingsView from '../src/views/FindingsView.vue'
import { setCsrf } from '../src/api.js'

vi.mock('vue-router', () => ({ useRoute: () => ({ query: {} }), useRouter: () => ({ replace: vi.fn(), push: vi.fn() }) }))

let calls
let steps
const json = (b, s = 200, headers = {}) => new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json', ...headers } })
const overview = () => ({
  ampel: 'rot', findings: { kritisch: 2, hoch: 0, mittel: 0, info: 0 }, coverage: [], coverage_percent: 100, canary_status: 'ok',
  last_run: null, active_run: null, next_run: null, worker: { age_seconds: 10 }, setup_hints: [], early_warning: {},
  short_run: {}, next_steps: steps,
  early_warning_hits: [{ id: 1, title: 'Unpatched Tailscale SSH flaws', severity: 'hoch', systems: ['host-b', 'raspberrypi'] }],
})

beforeEach(() => {
  setCsrf('tok')
  calls = []
  steps = [
    { id: 'mini · host packages', title: 'mini · host packages', level: 'rot', detail: '9 critical', command: '', done: false },
    { id: 'g# · host packages', title: 'host-a · host packages', level: 'rot', detail: '4 critical', command: '', done: true },
  ]
  vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
    calls.push({ url, method: init.method || 'GET', body: init.body ? JSON.parse(init.body) : null })
    if (url === '/api/overview') return json(overview())
    if (url === '/api/overview/steps/done') return json({ ok: true })
    if (url.startsWith('/api/findings')) {
      return json([{ id: 5, cve_id: 'CVE-2026-1', title: 't', target: 'host', severity: 'kritisch', system_id: 1, system_name: 'host-c',
        component: 'openssl', installed_version: '3.0.1', fixed_version: '3.0.2', cvss_score: 9.8, epss_score: 0.1, kev: true,
        source: 'grype', internet_exposed: false, status: 'open',
        action: { text: 'Update openssl to 3.0.2 or newer.', command: 'sudo apt update && sudo apt install --only-upgrade openssl' } }],
      200, { 'X-Total-Count': '1' })
    }
    return json([])
  }))
})

afterEach(() => {
  vi.unstubAllGlobals()
  setCsrf(null)
})

const stubs = { RouterLink: { props: ['to'], template: '<a><slot /></a>' }, PipelineFlow: true, RunProgress: true, LineChart: true }

describe('Overview: what to do and early warnings', () => {
  it('shows paused reports as a notice', async () => {
    const base = overview
    vi.stubGlobal('fetch', vi.fn(async (url) => url === '/api/overview' ? json({ ...base(), reports_paused_until: '2026-12-24' }) : json([])))
    const w = mount(OverviewView, { global: { stubs: { RouterLink: true } } })
    await flushPromises()
    expect(w.get('[data-test=reports-paused]').text()).toContain('Reports paused until 2026-12-24')
  })

  it('counts snoozed findings separately, never as ok', async () => {
    const base = overview
    vi.stubGlobal('fetch', vi.fn(async (url) => url === '/api/overview' ? json({ ...base(), snoozed_count: 3 }) : json([])))
    const w = mount(OverviewView, { global: { stubs: { RouterLink: true } } })
    await flushPromises()
    expect(w.get('[data-test=snoozed]').text()).toContain('3 findings snoozed')
  })

  it('shows a failed exposure source as an error row', async () => {
    const base = overview
    const sources = [{ key: 'npm', label: 'NPM', status: 'fehler', detail: 'NPM unreachable; showing the last known mapping', exposed: 4, unmatched: 1 }]
    vi.stubGlobal('fetch', vi.fn(async (url) => url === '/api/overview' ? json({ ...base(), exposure_sources: sources }) : json([])))
    const w = mount(OverviewView, { global: { stubs: { RouterLink: true } } })
    await flushPromises()
    const row = w.get('[data-test=exposure-sources] tbody tr').text()
    expect(row).toContain('NPM')
    expect(row).toContain('ERROR')
    expect(row).toContain('last known mapping')
  })

  it('opens the details of an exposure source on click', async () => {
    const base = overview
    const sources = [{ key: 'fritzbox', label: 'FRITZ!Box', status: 'ok', detail: 'read just now', exposed: 1, unmatched: 1 }]
    const detail = { ...sources[0], items: [{ system_id: 3, system_name: 'mini', name: '(host)', via: ['port 22'] }],
      unmatched_items: [{ what: 'TCP 8080 → REDACTED:80', why: 'no system with this address' }] }
    vi.stubGlobal('fetch', vi.fn(async (url) => url === '/api/overview' ? json({ ...base(), exposure_sources: sources })
      : url === '/api/overview/exposure/fritzbox' ? json(detail) : json([])))
    const w = mount(OverviewView, { global: { stubs: { RouterLink: true } }, attachTo: document.body })
    await flushPromises()
    await w.get('[data-test=exposure-sources] tbody tr').trigger('click')
    await flushPromises()
    expect(w.get('[data-test=exposure-items]').text()).toContain('mini')
    expect(w.get('[data-test=exposure-items]').text()).toContain('host itself')
    expect(w.get('[data-test=exposure-unmatched]').text()).toContain('no system with this address')
    w.unmount()
  })

  it('hides done steps, offers undo and shows affected early warnings as a bar', async () => {
    const w = mount(OverviewView, { global: { stubs } })
    await flushPromises()
    expect(w.find('.ew-bar').text()).toContain('1 early warning affects your systems')
    expect(w.find('.ew-bar').text()).toContain('host-b, raspberrypi')
    const list = w.find('.step-list').text()
    expect(list).toContain('mini · host packages')
    expect(list).not.toContain('host-a · host packages')
    expect(w.text()).toContain('Show 1 marked done')

    await w.findAll('.step-actions button').find((b) => b.text() === 'Done').trigger('click')
    await flushPromises()
    expect(calls.find((c) => c.url === '/api/overview/steps/done').body).toEqual({ id: 'mini · host packages', done: true })
  })
})

describe('Findings: recommended action', () => {
  it('opens text and command under the row', async () => {
    const w = mount(FindingsView, { global: { stubs } })
    await flushPromises()
    expect(w.find('.action-row').exists()).toBe(false)
    await w.findAll('button').find((b) => b.text() === 'How to fix').trigger('click')
    expect(w.find('.action-row').text()).toContain('Update openssl to 3.0.2 or newer.')
    expect(w.find('.action-row code').text()).toBe('sudo apt update && sudo apt install --only-upgrade openssl')
  })
})
