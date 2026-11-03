import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import SystemsView from '../src/views/SystemsView.vue'
import { setCsrf } from '../src/api.js'

let calls

beforeEach(() => {
  setCsrf('tok')
  calls = []
  vi.stubGlobal('confirm', () => true)
  vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
    calls.push({ url, method: init.method || 'GET', body: init.body ? JSON.parse(init.body) : null })
    const json = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json' } })
    if (url === '/api/systems') {
      return json([{ id: 7, name: 'unraid', host_type: 'collector', status: 'active', state: 'online', agent_version: '',
        agent_outdated: false, container_count: 3, security_updates_count: 0, last_seen: null, age_hours: null }])
    }
    if (url === '/api/collector/systems' || url === '/api/collector/systems/7/token') {
      return json({ id: 7, name: 'unraid', token: 'tok-once', server_url: 'https://192.0.2.10:8443',
        ca_fingerprint: 'AA:BB', setup_cmd: 'D=${LL_DIR:-/etc/lablantern-collector} && echo tok-once > "$D/token"' })
    }
    return json({}, 404)
  }))
})

afterEach(() => {
  vi.unstubAllGlobals()
  setCsrf(null)
})

describe('collector device', () => {
  it('creates a device and shows the setup command once', async () => {
    const w = mount(SystemsView, { global: { stubs: { RouterLink: true } } })
    await flushPromises()
    expect(w.text()).toContain('collector script, no agent')
    expect(w.text()).not.toContain('outdated')
    await w.find('button.primary').trigger('click')
    await w.findAll('button.kind').find((b) => b.text().includes('collector script')).trigger('click')
    await w.find('input[name=collector_name]').setValue('unraid')
    await w.find('[data-test=collector-form]').trigger('submit')
    await flushPromises()
    expect(calls.find((c) => c.url === '/api/collector/systems').body).toEqual({ name: 'unraid' })
    expect(w.find('[data-test=collector-setup]').text()).toContain('echo tok-once')
  })

  it('issues a new token from the row', async () => {
    const w = mount(SystemsView, { global: { stubs: { RouterLink: true } } })
    await flushPromises()
    await w.find('[data-test=collector-token]').trigger('click')
    await flushPromises()
    expect(calls.some((c) => c.url === '/api/collector/systems/7/token' && c.method === 'POST')).toBe(true)
    expect(w.find('[data-test=collector-setup]').exists()).toBe(true)
  })
})
