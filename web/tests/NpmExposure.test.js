import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import ProductsSettings from '../src/components/ProductsSettings.vue'
import { setCsrf } from '../src/api.js'

let calls, npm
const json = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json' } })

beforeEach(() => {
  setCsrf('tok')
  calls = []
  npm = {
    config: { url: 'http://npm.lan:81', email: 'a@b.c', system_id: null },
    password: { set: true },
    overrides: { hosts: { 'old.example.org': 'public' }, entrypoints: {} },
    state: { configured: true, ok: true, at: Date.now() / 1000, hosts: 2, exposed: {}, unmatched: [], dns_failed: ['vw.example.org'],
      lan_only: [{ domains: ['nas.example.org'], target: 'nas:80', reason: 'no public address in public DNS' }] },
  }
  vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
    calls.push({ url, method: init.method || 'GET', body: init.body ? JSON.parse(init.body) : null })
    if (url === '/api/settings/npm') return json(npm)
    if (url === '/api/versions') return json({ systems: {} })
    if (url === '/api/systems') return json([])
    if (url === '/api/settings/fritzbox') return json({ config: null, state: {} })
    if (url === '/api/settings/npm/test') return json(npm.state)
    return json({ ok: true })
  }))
})
afterEach(() => { vi.unstubAllGlobals(); setCsrf(null) })

describe('NPM exposure from public DNS', () => {
  it('lists LAN-only hosts and failed checks, and marks a name by hand', async () => {
    const w = mount(ProductsSettings, { global: { stubs: { SecretField: true } } })
    await flushPromises()
    expect(w.get('[data-test=npm-lan-only]').text()).toContain('nas.example.org → nas:80')
    expect(w.get('[data-test=npm-dns-failed]').text()).toContain('counted as internet-exposed')
    expect(w.get('[data-test=npm-marked]').text()).toContain('old.example.org · public')
    await w.get('[data-test=npm-lan-only] button').trigger('click')
    await flushPromises()
    const put = calls.find((c) => c.method === 'PUT')
    expect(put).toEqual({ url: '/api/settings/exposure-overrides', method: 'PUT',
      body: { hosts: { 'old.example.org': 'public', 'nas.example.org': 'public' }, entrypoints: {} } })
    expect(calls.some((c) => c.url === '/api/settings/npm/test' && c.method === 'POST')).toBe(true)
  })

  it('saves the Cloudflare Tunnel connection and lists unmatched routes', async () => {
    const cf = { config: { account_id: 'a'.repeat(32) }, token: { set: true },
      state: { configured: true, ok: true, at: Date.now() / 1000, tunnels: 2, exposed: { 1: ['vw'] },
        unmatched: [{ what: 'legacy', why: 'ingress not readable (locally managed config.yml)' }] } }
    const base = fetch.getMockImplementation()
    vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
      if (url === '/api/settings/cftunnel') {
        calls.push({ url, method: init.method || 'GET', body: init.body ? JSON.parse(init.body) : null })
        return json(init.method === 'PUT' ? { ok: true } : cf)
      }
      if (url === '/api/settings/cftunnel/test') return json(cf.state)
      return base(url, init)
    }))
    const w = mount(ProductsSettings, { global: { stubs: { SecretField: true } } })
    await flushPromises()
    expect(w.get('[data-test=cf-unmatched]').text()).toContain('locally managed config.yml')
    await w.get('form.settings-form input[name=cf_account]').element.form.dispatchEvent(new Event('submit'))
    await flushPromises()
    expect(calls.find((c) => c.url === '/api/settings/cftunnel' && c.method === 'PUT').body).toEqual({ account_id: 'a'.repeat(32), token: null })
  })

  it('shows Traefik routers and marks an entrypoint LAN only', async () => {
    const base = fetch.getMockImplementation()
    vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
      if (url === '/api/settings/traefik') return json({ state: { configured: true, routers: 3, exposed: { 1: ['app'] }, entrypoints: ['lan', 'websecure'],
        unmatched: [{ what: 'wiki on host-c', router: 'wiki', why: 'HostRegexp rules cannot be checked, mark it by hand' }] } })
      return base(url, init)
    }))
    const w = mount(ProductsSettings, { global: { stubs: { SecretField: true } } })
    await flushPromises()
    expect(w.get('[data-test=traefik]').text()).toContain('3 routers, 1 containers internet-exposed')
    expect(w.get('[data-test=traefik-unmatched]').text()).toContain('wiki on host-c (router wiki)')
    await w.get('select[name=ep_lan]').setValue('lan')
    await flushPromises()
    expect(calls.find((c) => c.method === 'PUT').body).toEqual({ hosts: { 'old.example.org': 'public' }, entrypoints: { lan: 'lan' } })
  })
})
