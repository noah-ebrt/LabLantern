import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import GuestCoverage from '../src/components/GuestCoverage.vue'
import OverviewView from '../src/views/OverviewView.vue'
import { setCsrf } from '../src/api.js'

vi.mock('vue-router', () => ({ useRoute: () => ({ query: {} }), useRouter: () => ({ replace: vi.fn(), push: vi.fn() }) }))

let calls
const json = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json' } })
const guests = [
  { subject: 'pve-guest:pve1/103', name: 'old-test', node: 'pve1', vmid: 103, type: 'lxc', source: 'proxmox', status: 'fehler', detail: 'stopped, not checked' },
  { subject: 'pve-guest:pve1/104', name: 'lab', node: 'pve1', vmid: 104, type: 'qemu', source: 'proxmox', status: 'excluded', detail: 'excluded until 2026-12-01: lab', exclusion_id: 9 },
]

beforeEach(() => {
  setCsrf('tok')
  calls = []
  vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
    calls.push({ url, method: init.method || 'GET', body: init.body ? JSON.parse(init.body) : null })
    return json({ ok: true })
  }))
})

afterEach(() => {
  vi.unstubAllGlobals()
  setCsrf(null)
})

describe('Proxmox guests in coverage', () => {
  it('excludes a stopped guest with a reason and includes an excluded one again', async () => {
    const w = mount(GuestCoverage, { props: { guests } })
    expect(w.text()).toContain('GAP')
    await w.find('[data-test=guest-exclude]').trigger('click')
    expect(w.find('input[name=guest_reason]').element.value).toBe('stopped guest')
    await w.find('[data-test=guest-exclude-form]').trigger('submit')
    await flushPromises()
    const post = calls.find((c) => c.url === '/api/coverage/exclusions')
    expect(post.body.subject).toBe('pve-guest:pve1/103')
    expect(post.body.until).toMatch(/^\d{4}-\d{2}-\d{2}$/)
    expect(w.emitted('changed')).toHaveLength(1)
    await w.findAll('button').find((b) => b.text() === 'Include again').trigger('click')
    await flushPromises()
    expect(calls.some((c) => c.url === '/api/coverage/exclusions/9' && c.method === 'DELETE')).toBe(true)
  })

  it('does not claim "no systems" when only the exposure list is empty', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url) => url === '/api/overview' ? json({
      ampel: 'gruen', findings: { kritisch: 0, hoch: 0, mittel: 0, info: 0 }, coverage_percent: 80, canary_status: 'ok',
      coverage: [{ system_id: 1, system_name: 'web01', status: 'active', checks: Object.fromEntries(['paket_cve', 'sicherheitsupdates', 'reboot', 'container', 'images', 'versionen'].map((k) => [k, { status: 'ok', detail: '' }])) }], exposure_sources: [], guests,
      last_run: null, active_run: null, next_run: null, worker: { age_seconds: 1 }, setup_hints: [], early_warning: {},
      short_run: {}, next_steps: [], early_warning_hits: [],
    }) : json([])))
    const w = mount(OverviewView, { global: { stubs: { RouterLink: true, PipelineFlow: true, RunProgress: true, LineChart: true } } })
    await flushPromises()
    expect(w.text()).not.toContain('No systems connected yet')
    expect(w.find('[data-test=guest-coverage]').text()).toContain('old-test')
  })
})
