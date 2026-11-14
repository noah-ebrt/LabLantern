import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import HostCoverage from '../src/components/HostCoverage.vue'
import { setCsrf } from '../src/api.js'

let calls, row
const json = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json' } })
const checks = (status, detail = '') => Object.fromEntries(['paket_cve', 'sicherheitsupdates', 'reboot', 'container', 'images', 'versionen']
  .map((k) => [k, { status, detail }]))

beforeEach(() => {
  setCsrf('tok')
  calls = []
  row = { system_id: 7, system_name: 'test-vm', status: 'active', age_hours: 1, checks: checks('fehler', 'no SBOM'), last_scan: null }
  vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
    calls.push({ url, method: init.method || 'GET', body: init.body ? JSON.parse(init.body) : null })
    if (url === '/api/systems/7/coverage') return json(row)
    return json({ ok: true, id: 3 })
  }))
})
afterEach(() => { vi.unstubAllGlobals(); setCsrf(null) })

describe('HostCoverage checks', () => {
  it('shows Protection only for hosts that have the check', async () => {
    let w = mount(HostCoverage, { props: { systemId: 7 } })
    await flushPromises()
    expect(w.findAll('tbody th').map((th) => th.text())).not.toContain('Protection')
    row = { ...row, checks: { ...checks('ok', 'no'), schutz: { status: 'fund', detail: 'firewall off for the profile Public' } } }
    w = mount(HostCoverage, { props: { systemId: 7 } })
    await flushPromises()
    expect(w.findAll('tbody th').map((th) => th.text())).toEqual(
      ['Package CVEs', 'Security updates', 'Reboot', 'Protection', 'Containers', 'Container images', 'Versions'])
    expect(w.text()).toContain('firewall off for the profile Public')
  })
})

describe('HostCoverage exclusions', () => {
  it('excludes a host with a date and a reason', async () => {
    const w = mount(HostCoverage, { props: { systemId: 7 } })
    await flushPromises()
    await w.get('button[data-test=exclude]').trigger('click')
    await w.get('input[name=exclude_until]').setValue('2026-12-24')
    await w.get('input[name=exclude_reason]').setValue('stopped test VM')
    await w.get('form.exclude').trigger('submit')
    await flushPromises()
    expect(calls.find((c) => c.method === 'POST')).toEqual({ url: '/api/coverage/exclusions', method: 'POST',
      body: { subject: 'system:7', until: '2026-12-24', reason: 'stopped test VM' } })
  })

  it('shows an exclusion with its reason and can include the host again', async () => {
    row = { ...row, checks: checks('excluded', 'excluded until 2026-12-24: stopped test VM'),
      excluded: { id: 3, reason: 'stopped test VM', until: '2026-12-24T00:00:00+00:00', by: 'noah' } }
    const w = mount(HostCoverage, { props: { systemId: 7 } })
    await flushPromises()
    expect(w.get('[data-test=excluded]').text()).toContain('Excluded from coverage until 2026-12-24: stopped test VM')
    expect(w.text()).toContain('EXCLUDED')
    await w.get('button[data-test=include]').trigger('click')
    await flushPromises()
    expect(calls.some((c) => c.method === 'DELETE' && c.url === '/api/coverage/exclusions/3')).toBe(true)
  })
})
