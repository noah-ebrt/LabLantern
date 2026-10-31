import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import ApplianceGuide from '../src/components/ApplianceGuide.vue'
import ConnectorDetailModal from '../src/components/ConnectorDetailModal.vue'

const json = (body) => new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } })
const watched = { feeds: 0, ai_configured: false, items: [] }

function serve(system) {
  vi.stubGlobal('fetch', vi.fn(async (url) => json(String(url).includes('/early-warnings/watched/') ? watched : system)))
}
async function open(system) {
  serve(system)
  const w = mount(ConnectorDetailModal, { props: { systemId: 9 }, global: { stubs: { RouterLink: true } } })
  await flushPromises()
  return w.text()
}
const base = { id: 9, name: 'dev', status: 'connector', last_seen: new Date().toISOString(), collection_errors: {} }

afterEach(() => vi.unstubAllGlobals())

describe('Synology und OPNsense', () => {
  it('Synology: Update, Speicher und Pakete, ohne Admin den Grund statt „keins“', async () => {
    let text = await open({ ...base, host_type: 'synology', inventory: { connector: {
      version: '7.2.2-72806 Update 3', model: 'DS920+', update: { available: true, version: '7.2.2-72806 Update 4' },
      storage: { error: '', pools: [{ name: '/volume1', kind: 'Volume', layout: 'BTRFS', status: 'normal', state: 'ok', percent: 96.2, size: 4e12, disks: [] }],
        disks: [{ name: 'Drive 2', model: 'WD40EFRX', size: 4e12, type: 'hdd', status: 'crashed', state: 'bad', temp: 41, pool: '' }] },
      packages: [{ id: 'ContainerManager', name: 'Container Manager', version: '24.0.2-1535' }] } } })
    expect(text).toContain('DS920+')
    expect(text).toContain('7.2.2-72806 Update 4')
    expect(text).toContain('96 %')
    expect(text).toContain('failing (crashed)')
    expect(text).toContain('Container Manager')
    text = await open({ ...base, host_type: 'synology', inventory: { connector: {
      version: '7.2.2', update: null, update_error: 'not readable: the DSM account is not an administrator',
      storage: { pools: [], disks: [], error: 'storage not readable: the DSM account is not an administrator' }, packages: null } } })
    expect(text).toContain('not an administrator')
    expect(text).not.toContain('none available')
  })

  it('OPNsense: nie geprüft heißt nicht „aktuell“', async () => {
    const text = await open({ ...base, host_type: 'opnsense', inventory: { connector: {
      version: '25.7.5', checked: false, updates: [], major: '', plugins: [{ name: 'os-wireguard', version: '2.6' }], packages: 120 } } })
    expect(text).toContain('never: run System → Firmware → Status → Check for updates')
    expect(text).toContain('os-wireguard')
  })

  it('Anleitung schickt Konto und Passwort getrennt', async () => {
    const fetch = vi.fn(async () => json({ ok: true, version: '7.2.2', findings: 0, system_id: 3 }))
    vi.stubGlobal('fetch', fetch)
    const w = mount(ApplianceGuide, { props: { kind: 'synology' } })
    await w.find('input[name="appliance_url"]').setValue('https://nas.lan:5001')
    await w.find('input[name="appliance_account"]').setValue('vulnwatch')
    await w.find('input[name="appliance_token"]').setValue('long random password')
    await w.find('form').trigger('submit')
    await flushPromises()
    const body = JSON.parse(fetch.mock.calls[0][1].body)
    expect(body).toMatchObject({ kind: 'synology', account: 'vulnwatch', token: 'long random password' })
    expect(w.emitted('saved')).toBeTruthy()
  })
})
