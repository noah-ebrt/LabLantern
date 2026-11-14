import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import SystemsView from '../src/views/SystemsView.vue'
import { setCsrf } from '../src/api.js'

let calls
let confirmed
let windowsCmds

const WINDOWS = {
  setup_cmd: '$f="$env:TEMP\\lablantern-agent.exe"; & $f setup --master https://192.0.2.10:8443 --ca-fingerprint AA',
  install_cmd: '& $f enroll --server https://192.0.2.10:8443 --token once --ca-fingerprint AA',
  update_cmd: '& $f install',
  uninstall_cmd: '& "$env:ProgramFiles\\LabLantern\\lablantern-agent.exe" uninstall',
}

beforeEach(() => {
  setCsrf('tok')
  calls = []
  confirmed = []
  windowsCmds = WINDOWS
  vi.stubGlobal('confirm', (text) => { confirmed.push(text); return true })
  vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
    calls.push({ url, method: init.method || 'GET' })
    const json = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json' } })
    if (url === '/api/systems') {
      return json([{ id: 9, name: 'host-w', host_type: 'windows', status: 'active', state: 'online', online: true,
        agent_version: '0.20.0', agent_outdated: false, container_count: 0, security_updates_count: 0, last_seen: null, age_hours: null }])
    }
    if (url === '/api/systems/enrollment-token') {
      return json({ token: 'once', ca_fingerprint: 'AA', server_url: 'https://192.0.2.10:8443', enroll_cmd: 'lablantern-agent enroll',
        install_cmd: 'sudo dpkg -i', setup_cmd: 'sudo lablantern-agent setup', windows: windowsCmds })
    }
    if (url === '/api/pairings') return json([])
    if (url === '/api/systems/9') return json({ ok: true })
    return json({}, 404)
  }))
})

afterEach(() => {
  vi.unstubAllGlobals()
  setCsrf(null)
})

async function openWindows() {
  const w = mount(SystemsView, { global: { stubs: { RouterLink: true } } })
  await flushPromises()
  await w.find('button.primary').trigger('click')
  await w.findAll('button.kind').find((b) => b.text().includes('Windows')).trigger('click')
  await flushPromises()
  return w
}

describe('windows host', () => {
  it('shows one PowerShell command for setup, not the Linux one', async () => {
    const w = await openWindows()
    expect(w.text()).toContain('Add a Windows host')
    expect(w.find('[data-test=agent-setup-cmd]').text()).toBe(WINDOWS.setup_cmd)
    expect(w.text()).toContain('PowerShell (as administrator)')
    expect(w.text()).not.toContain('sudo')
    expect(w.find('[data-test=windows-manage]').text()).toContain(WINDOWS.uninstall_cmd)
    expect(w.find('[data-test=windows-manage]').text()).toContain(WINDOWS.update_cmd)
  })

  it('says so when the master has no Windows agent yet', async () => {
    windowsCmds = null
    const w = await openWindows()
    expect(w.find('[data-test=agent-setup-cmd]').exists()).toBe(false)
    expect(w.text()).toContain('No Windows agent on this master yet')
    expect(w.text()).not.toContain('sudo')
  })

  it('deletes a connected Windows host here and names the uninstall command, without a signed uninstall', async () => {
    const w = mount(SystemsView, { global: { stubs: { RouterLink: true } } })
    await flushPromises()
    await w.find('button.btn-delete').trigger('click')
    await flushPromises()
    expect(confirmed[0]).toContain('lablantern-agent.exe" uninstall')
    expect(calls.some((c) => c.url === '/api/systems/9' && c.method === 'DELETE')).toBe(true)
    expect(calls.some((c) => c.url.includes('passkey') || c.url.includes('command'))).toBe(false)
  })
})
