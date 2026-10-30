import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import SystemsView from '../src/views/SystemsView.vue'
import { setCsrf } from '../src/api.js'

vi.mock('../src/webauthn.js', () => ({
  usePasskey: vi.fn(async () => ({ id: 'cred-1', rawId: 'raw-1', response: {} })),
}))

let systemsList
let commandList

beforeEach(() => {
  commandList = []
  vi.stubGlobal('alert', () => {})
  setCsrf('csrf-tok')
  systemsList = [
    {
      id: 1,
      name: 'host-a',
      host_type: 'linux',
      ip: '192.0.2.10',
      status: 'active',
      agent_version: '0.2.0',
      enrolled_at: '2026-10-24T05:00:00Z',
      last_seen: '2026-10-24T05:30:00Z',
      age_hours: 0.1,
      is_stale: false,
      security_updates_count: 0,
      reboot_required: false,
      container_count: 5,
    },
    {
      id: 2,
      name: 'host-c',
      host_type: 'linux',
      ip: '192.0.2.67',
      status: 'pending',
      agent_version: '0.2.0',
      enrolled_at: '2026-10-24T05:10:00Z',
      last_seen: null,
      age_hours: null,
      is_stale: true,
      security_updates_count: 3,
      reboot_required: true,
      container_count: 2,
    },
  ]

  vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
    const json = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json' } })
    if (url === '/api/systems/agent-update') return json({ version: '0.4.0', update_cmd: null })
    if (url === '/api/systems' && (init.method || 'GET') === 'GET') {
      return json(systemsList)
    }
    if (url === '/api/systems/enrollment-token' && init.method === 'POST') {
      return json({
        token: 'test-token-123',
        expires_at: 1800000000,
        server_url: 'https://192.0.2.10:8443',
        ca_fingerprint: 'AA:BB:CC:DD',
        enroll_cmd: 'vulnwatch-agent enroll --server https://192.0.2.10:8443 --token test-token-123',
      })
    }
    if (url === '/api/systems/2/approve' && init.method === 'POST') {
      systemsList[1].status = 'active'
      return json({ ok: true })
    }
    if (url === '/api/systems/1/commands/prepare' && init.method === 'POST') {
      return json({ envelope: '{"type":"update_agent"}', options: {} })
    }
    if (url === '/api/systems/1/commands/confirm' && init.method === 'POST') {
      commandList.push({ id: 99, type: 'update_agent', status: 'queued' })
      systemsList[0].pending_action = 'update_agent'   // der Server meldet die laufende Aktion
      return json({ id: 99, status: 'queued' })
    }
    if (url === '/api/systems/1/commands' && (init.method || 'GET') === 'GET') {
      return json(commandList)
    }
    return json({}, 404)
  }))
})

afterEach(() => {
  vi.unstubAllGlobals()
  setCsrf(null)
})

describe('SystemsView', () => {
  it('zeigt registrierte Systeme mit Status an', async () => {
    const w = mount(SystemsView)
    await flushPromises()

    expect(w.text()).toContain('Systems & agents')
    expect(w.text()).toContain('host-a')
    expect(w.text()).toContain('Active')
    expect(w.text()).toContain('host-c')
    expect(w.text()).toContain('Waiting for approval')
  })

  it('erzeugt Einrichtungs-Token und Befehl im Dialog', async () => {
    const w = mount(SystemsView)
    await flushPromises()

    const addBtn = w.find('button.primary')
    await addBtn.trigger('click')
    await flushPromises()
    expect(w.text()).toContain('Add a host')
    await w.findAll('button.kind')[0].trigger('click')
    await flushPromises()

    expect(w.text()).toContain('Add a Linux host')
    expect(w.text()).toContain('test-token-123')
    expect(w.text()).toContain('AA:BB:CC:DD')
    expect(w.text()).toContain('vulnwatch-agent enroll')
  })

  it('zeigt für TrueNAS Felder, Vorbereitung und API-Beschreibung statt eines Agent-Befehls', async () => {
    const w = mount(SystemsView)
    await flushPromises()
    await w.find('button.primary').trigger('click')
    await w.findAll('button.kind')[1].trigger('click')
    await flushPromises()

    expect(w.text()).toContain('Add TrueNAS')
    expect(w.text()).toContain('Read-only Administrator')
    expect(w.find('input[name="appliance_url"]').exists()).toBe(true)
    expect(w.text()).toContain('auth.login_with_api_key')
    expect(w.text()).toContain('docs/INTEGRATIONS.md')
    expect(w.text()).not.toContain('vulnwatch-agent enroll')
  })

  it('gibt ausstehenden Agenten frei', async () => {
    const w = mount(SystemsView)
    await flushPromises()

    const approveBtn = w.find('.btn-approve')
    expect(approveBtn.exists()).toBe(true)
    await approveBtn.trigger('click')
    await flushPromises()

    expect(systemsList[1].status).toBe('active')
  })

  it('zeigt Update-Button an wenn Agent veraltet ist', async () => {
    systemsList[0].agent_outdated = true
    const w = mount(SystemsView)
    await flushPromises()

    const updateBtn = w.find('.btn-update')
    expect(updateBtn.exists()).toBe(true)
    expect(updateBtn.text()).toBe('Update')
    expect(updateBtn.attributes('disabled')).toBeUndefined()

    await updateBtn.trigger('click')
    for (let i = 0; i < 5; i++) await flushPromises()   // prepare → Passkey → confirm → Liste neu laden

    expect(w.find('.btn-update').attributes('disabled')).toBeDefined()
    expect(w.find('.btn-update').text()).toBe('Updating…')

    // Agent meldet die neue Version: Server hebt die Sperre auf, Live-Update lädt neu
    systemsList[0].pending_action = null
    systemsList[0].agent_outdated = false
    await w.vm.$nextTick()
    w.unmount()
  })
})

describe('SystemsView release card', () => {
  it('updates all outdated agents with one passkey touch and copies the manual command', async () => {
    systemsList[0].agent_outdated = true
    systemsList[1].status = 'active'
    systemsList[1].agent_outdated = true
    const calls = []
    const write = vi.fn(async () => {})
    vi.stubGlobal('navigator', { clipboard: { writeText: write } })
    const base = fetch.getMockImplementation()
    fetch.mockImplementation(async (url, init = {}) => {
      const json = (b) => new Response(JSON.stringify(b), { status: 200, headers: { 'content-type': 'application/json' } })
      calls.push(url)
      if (url === '/api/systems/agent-update') return json({ version: '0.13.0', update_cmd: 'curl … | sudo dpkg -i', last_check: null })
      if (url === '/api/systems/commands/update-all/prepare') return json({ batch_ids: [1, 2], single_ids: [], options: {} })
      if (url === '/api/systems/commands/update-all/confirm') return json({ created: ['host-a', 'host-c'], skipped: [] })
      return base(url, init)
    })
    const w = mount(SystemsView)
    await flushPromises()
    expect(w.text()).toContain('Agent 0.13.0 is available')
    const btn = w.findAll('button').find((b) => b.text().includes('Update all 2'))
    await btn.trigger('click')
    await flushPromises()
    expect(calls).toContain('/api/systems/commands/update-all/confirm')
    expect(calls.filter((u) => u.endsWith('/commands/prepare'))).toHaveLength(0)   // kein Touch je Host
    expect(w.text()).toContain('Update sent to host-a, host-c')
    await w.findAll('button').find((b) => b.text() === 'Copy').trigger('click')
    await flushPromises()
    expect(write).toHaveBeenCalledWith('curl … | sudo dpkg -i')
    expect(w.text()).toContain('Copied')
  })

  it('says when all agents are current', async () => {
    systemsList.splice(1, 1)
    systemsList[0].agent_version = '0.12.0'
    const base = fetch.getMockImplementation()
    fetch.mockImplementation(async (url, init = {}) => url === '/api/systems/agent-update'
      ? new Response(JSON.stringify({ version: '0.12.0', update_cmd: null, last_check: { ok: true, at: new Date().toISOString() } }), { status: 200, headers: { 'content-type': 'application/json' } })
      : base(url, init))
    const w = mount(SystemsView)
    await flushPromises()
    expect(w.text()).toContain('All agents run v0.12.0, the newest release')
    expect(w.text()).toContain('Checked for new releases')
  })
})
