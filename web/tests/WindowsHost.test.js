import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import HostDetailModal from '../src/components/HostDetailModal.vue'
import { setCsrf } from '../src/api.js'

let host
const json = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json' } })
const HOST = { id: 9, name: 'host-w', host_type: 'windows', status: 'active', online: true, agent_version: '0.21.0',
  containers_expected: { expected: [], missing: [], unknown: [] }, exposed_containers: [],
  inventory: { os_name: 'Windows 11 Pro 24H2', kernel: '10.0.26100.2314', arch: 'amd64', containers: [],
    software: [{ name: '7-Zip 24.08 (x64)', version: '24.08', publisher: 'Igor Pavlov' },
      { name: 'Mozilla Firefox (x64 en-US)', version: '131.0.3', publisher: 'Mozilla' }] } }

beforeEach(() => {
  setCsrf('tok')
  host = HOST
  vi.stubGlobal('fetch', vi.fn(async (url) => {
    if (url === '/api/systems/9') return json(host)
    if (url === '/api/systems/9/commands') return json([])
    return json({}, 404)
  }))
})
afterEach(() => { vi.unstubAllGlobals(); setCsrf(null) })

const open = async () => {
  const w = mount(HostDetailModal, { props: { systemId: 9 },
    global: { stubs: { RouterLink: true, HostCoverage: true, EarlyWarningWatch: true, Modal: { template: '<div><slot /></div>' } } } })
  await flushPromises()
  return w
}

describe('windows host details', () => {
  it('lists the installed programs and leaves out the container section', async () => {
    const w = await open()
    const programs = w.get('[data-test=software]')
    expect(programs.get('summary').text()).toBe('Installed programs (2)')
    expect(programs.findAll('tbody tr').map((tr) => tr.findAll('td').map((td) => td.text()))).toEqual(
      [['7-Zip 24.08 (x64)', '24.08', 'Igor Pavlov'], ['Mozilla Firefox (x64 en-US)', '131.0.3', 'Mozilla']])
    expect(w.text()).not.toContain('Containers (')
    expect(w.text()).not.toContain('No Docker containers reported')
  })

  it('keeps the container section for a Linux host and shows no program list', async () => {
    host = { ...HOST, host_type: 'linux' }
    const w = await open()
    expect(w.text()).toContain('Containers (0)')
    expect(w.find('[data-test=software]').exists()).toBe(false)
  })
})
