import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import FindingsView from '../src/views/FindingsView.vue'
import { setCsrf } from '../src/api.js'

vi.mock('vue-router', () => ({ useRoute: () => ({ query: {} }), useRouter: () => ({ replace: vi.fn(), push: vi.fn() }) }))

let calls
const json = (b, s = 200, headers = {}) => new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json', ...headers } })
const row = (extra = {}) => ({ id: 5, cve_id: 'CVE-2026-1', title: 't', target: 'host', severity: 'kritisch', system_id: 1, system_name: 'host-c',
  component: 'openssl', installed_version: '3.0.1', fixed_version: '', cvss_score: 9.8, epss_score: 0.1, kev: false,
  source: 'grype', internet_exposed: false, status: 'open', action: null, ...extra })

beforeEach(() => {
  setCsrf('tok')
  calls = []
  vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
    calls.push({ url, method: init.method || 'GET', body: init.body ? JSON.parse(init.body) : null })
    if (url.startsWith('/api/findings/5/snooze')) return json({ ok: true, id: 1 })
    if (url.startsWith('/api/findings')) return json([row()], 200, { 'X-Total-Count': '1' })
    return json([])
  }))
})
afterEach(() => { vi.unstubAllGlobals(); setCsrf(null) })

describe('Snooze a finding', () => {
  it('sends scope, date and reason', async () => {
    const w = mount(FindingsView, { global: { stubs: { RouterLink: true } } })
    await flushPromises()
    await w.get('button[data-test=snooze]').trigger('click')
    expect(w.text()).toContain('Snooze CVE-2026-1')
    await w.get('input[value=everywhere]').setValue(true)
    await w.get('input[name=snooze_until]').setValue('2026-12-24')
    await w.get('textarea[name=snooze_reason]').setValue('vendor says not affected')
    await w.get('form.snooze').trigger('submit')
    await flushPromises()
    const post = calls.find((c) => c.method === 'POST')
    expect(post).toEqual({ url: '/api/findings/5/snooze', method: 'POST',
      body: { scope: 'everywhere', until: '2026-12-24', reason: 'vendor says not affected' } })
  })

  it('shows snoozed findings with reason and date', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json([row({ status: 'accepted', accepted_reason: 'isolated', accepted_until: '2026-12-24T00:00:00+00:00' })], 200, { 'X-Total-Count': '1' })))
    const w = mount(FindingsView, { global: { stubs: { RouterLink: true } } })
    await flushPromises()
    expect(w.get('.badge.accepted').text()).toBe('Snoozed')
    expect(w.text()).toContain('until 2026-12-24')
    expect(w.find('button[data-test=snooze]').exists()).toBe(false)
  })
})
