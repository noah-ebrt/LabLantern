import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import FindingsView from '../src/views/FindingsView.vue'

vi.mock('vue-router', () => ({ useRoute: () => ({ query: {} }), useRouter: () => ({ replace: vi.fn(), push: vi.fn() }) }))

let urls
const json = (b, headers = {}) => new Response(JSON.stringify(b), { status: 200, headers: { 'content-type': 'application/json', ...headers } })
const group = (extra) => ({ key: 'image:x:latest', kind: 'image', title: 'Container x', subtitle: 'x:latest', target: 'image:x:latest',
  state: 'update', text: 'The registry has a newer image for this tag.', command: 'docker compose pull x && docker compose up -d x',
  counts: { kritisch: 1, hoch: 2, mittel: 0, info: 0, kev: 1, fixable: 3, total: 3 },
  packages: [{ component: 'brotli', installed_version: '1.2.0', fixed_version: '1.2.1', count: 1, severity: 'kritisch', kev: 1 }],
  packages_total: 1, ...extra })

beforeEach(() => {
  urls = []
  vi.stubGlobal('fetch', vi.fn(async (url) => {
    urls.push(url)
    if (url.startsWith('/api/findings/by-host')) return json([{ system_id: 7, system_name: 'host-a', total: 3, kritisch: 1, hoch: 2, mittel: 0, info: 0, kev: 1, fixable: 3, images: 1 }])
    if (url.startsWith('/api/findings/groups')) return json({ system_id: 7, system_name: 'host-a', groups: [group(), group({ key: 'image:y:latest', title: 'Container y', state: 'waiting', command: '', text: 'pulling changes nothing' }),
      group({ key: 'image:z:latest', title: 'Container z', state: 'stuck', text: 'The last update (Nov 10) left all 3 fixable findings here in place' }),
      group({ key: 'image:w:latest', title: 'Container w', counts: { kritisch: 0, hoch: 3, mittel: 0, info: 0, kev: 0, fixable: 3, stayed: 2, total: 3 } })] })
    if (url.startsWith('/api/findings')) return json([], { 'X-Total-Count': '0' })
    return json({})
  }))
})
afterEach(() => vi.unstubAllGlobals())

describe('Findings by host', () => {
  it('shows hosts with the active filters, then the groups of one host', async () => {
    const w = mount(FindingsView, { global: { stubs: { RouterLink: true } } })
    await flushPromises()   // By host ist die Standardansicht
    expect(w.findAll('[role=tablist][aria-label=View] button')[0].text()).toBe('By host')
    expect(urls.some((u) => u.startsWith('/api/findings/by-host?status=open'))).toBe(true)
    expect(w.text()).toContain('host-a')
    await w.get('tr.clickable').trigger('click')
    await flushPromises()
    expect(urls.some((u) => u.startsWith('/api/findings/groups?') && u.includes('system_id=7'))).toBe(true)
    expect(w.text()).toContain('Update fixes these')
    expect(w.text()).toContain('Waiting for a fix')
    // der letzte Pull ließ dieselben Funde zurück: kein Versprechen mehr
    expect(w.get('[data-test="group-image:z:latest"]').text()).toContain('Last update did not fix these')
    expect(w.get('[data-test="group-image:z:latest"]').text()).not.toContain('fixable now')
    expect(w.get('[data-test="group-image:w:latest"]').text()).toContain('Update may fix some of these · 2 of 3 stayed after the last update')
    expect(w.get('[data-test="group-image:x:latest"]').text()).toContain('docker compose pull x')
    await w.get('[data-test="group-image:x:latest"] .group-foot button').trigger('click')
    expect(w.text()).toContain('brotli')
  })
})
