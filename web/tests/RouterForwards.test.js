import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import RouterForwardsSettings from '../src/components/RouterForwardsSettings.vue'
import { setCsrf } from '../src/api.js'

let calls
const json = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json' } })
const state = { configured: true, ok: true, at: 1800000000, forwards: 4, exposed: { 1: ['npm'] },
  unmatched: [{ forward: 'TCP 8443 → webservers:8443', description: 'alias target', reason: 'target is an alias' }] }

beforeEach(() => {
  setCsrf('tok')
  calls = []
  vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
    calls.push({ url, method: init.method || 'GET', body: init.body ? JSON.parse(init.body) : null })
    if (url === '/api/settings/router/opnsense' && (init.method || 'GET') === 'GET') {
      return json({ config: { url: 'https://opnsense.lan', fingerprint: 'AA', key: 'opn-key' }, secret: { set: true }, state })
    }
    if (url === '/api/settings/router/unifi' && (init.method || 'GET') === 'GET') return json({ config: null, secret: { set: false }, state: {} })
    if (url.endsWith('/test')) return json(state)
    return json({ ok: true })
  }))
})

afterEach(() => {
  vi.unstubAllGlobals()
  setCsrf(null)
})

describe('router port forwards', () => {
  it('shows a connected OPNsense with its unmatched forwards and saves UniFi with site and key', async () => {
    const w = mount(RouterForwardsSettings)
    await flushPromises()
    expect(w.find('[data-test=router-opnsense]').text()).toContain('API key opn-key')
    expect(w.find('[data-test=router-opnsense-unmatched]').text()).toContain('webservers:8443')
    expect(w.find('[data-test=router-unifi]').text()).toContain('Not connected')
    await w.find('input[name=unifi_url]').setValue('https://unifi.lan')
    await w.find('input[name=unifi_secret]').setValue('unifi-key-123')
    await w.find('[data-test=router-unifi] form').trigger('submit')
    await flushPromises()
    const put = calls.find((c) => c.url === '/api/settings/router/unifi' && c.method === 'PUT')
    expect(put.body).toMatchObject({ url: 'https://unifi.lan', site: 'default', secret: 'unifi-key-123' })
    expect(calls.some((c) => c.url === '/api/settings/router/unifi/test' && c.method === 'POST')).toBe(true)
  })
})
