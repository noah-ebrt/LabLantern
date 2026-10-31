import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import ScheduleSettings from '../src/components/ScheduleSettings.vue'
import ReportSettings from '../src/components/ReportSettings.vue'
import { setCsrf } from '../src/api.js'

let calls

beforeEach(() => {
  setCsrf('tok')
  calls = []
  vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
    const method = init.method || 'GET'
    calls.push({ url, method, body: init.body ? JSON.parse(init.body) : null })
    const json = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json' } })
    if (url === '/api/settings/schedule' && method === 'GET') {
      return json({ enabled: true, time: '04:00', next_run: '2026-10-25T04:00:00Z' })
    }
    if (url === '/api/settings/schedule' && method === 'PUT') {
      return json({ ok: true })
    }
    if (url === '/api/settings/short-schedule' && method === 'GET') {
      return json({ enabled: true, hours: 12, choices: [2, 3, 4, 6, 8, 12] })
    }
    if (url === '/api/settings/short-schedule' && method === 'PUT') {
      return json({ ok: true })
    }
    if (url === '/api/settings/report-policy' && method === 'GET') {
      return json({ frequency: 'daily', weekday: 0, paused_until: null })
    }
    if (url === '/api/settings/report-policy' && method === 'PUT') {
      return json({ ok: true })
    }
    return json({}, 404)
  }))
})

afterEach(() => {
  vi.unstubAllGlobals()
  setCsrf(null)
})

describe('ScheduleSettings', () => {
  it('zeigt den dominanten Toggle-Switch und die nächste Ausführung an', async () => {
    const w = mount(ScheduleSettings)
    await flushPromises()

    expect(w.text()).toContain('Scan schedule')
    expect(w.text()).toContain('Active')
    expect(w.get('input[role=switch]').element.checked).toBe(true)
    expect(w.get('input[name=time]').element.value).toBe('04:00')
    expect(w.text()).toContain('next Sun')
  })

  it('erlaubt das Umschalten und Speichern des Zeitplans', async () => {
    const w = mount(ScheduleSettings)
    await flushPromises()

    const toggle = w.get('input[role=switch]')
    await toggle.setValue(false)
    await flushPromises()

    expect(w.text()).toContain('Disabled')

    await w.find('form').trigger('submit')
    await flushPromises()

    const put = calls.find((c) => c.method === 'PUT' && c.url === '/api/settings/schedule')
    expect(put.body).toEqual({ enabled: false, time: '04:00' })
    const short = calls.find((c) => c.method === 'PUT' && c.url === '/api/settings/short-schedule')
    expect(short.body).toEqual({ enabled: true, hours: 12 })
    expect(w.text()).toContain('Schedule saved.')
    expect(calls.some((c) => c.url === '/api/settings/report-policy' && c.method === 'PUT')).toBe(false)
  })
})

describe('ReportSettings', () => {
  it('speichert Berichtshäufigkeit mit Wochentag und Pause', async () => {
    const w = mount(ReportSettings)
    await flushPromises()
    expect(w.text()).toContain('How often')
    await w.get('select[name=report_frequency]').setValue('weekly')
    await w.get('select[name=report_weekday]').setValue('4')
    await w.get('input[name=paused_until]').setValue('2026-12-24')
    await w.find('form').trigger('submit')
    await flushPromises()
    const put = calls.find((c) => c.url === '/api/settings/report-policy' && c.method === 'PUT')
    expect(put.body).toEqual({ frequency: 'weekly', weekday: 4, paused_until: '2026-12-24' })
  })

  it('leere Pause wird als null gespeichert', async () => {
    const w = mount(ReportSettings)
    await flushPromises()
    expect(w.find('select[name=report_weekday]').exists()).toBe(false)
    await w.find('form').trigger('submit')
    await flushPromises()
    const put = calls.find((c) => c.url === '/api/settings/report-policy' && c.method === 'PUT')
    expect(put.body).toEqual({ frequency: 'daily', weekday: 0, paused_until: null })
  })
})
