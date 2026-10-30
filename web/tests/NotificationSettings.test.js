import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import NotificationSettings from '../src/components/NotificationSettings.vue'
import { setCsrf } from '../src/api.js'

let calls, channels

beforeEach(() => {
  setCsrf('tok')
  calls = []
  channels = [{ index: 0, name: 'Handy', scheme: 'ntfy' }]
  vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
    const method = init.method || 'GET'
    calls.push({ url, method, body: init.body ? JSON.parse(init.body) : null })
    const json = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json' } })
    if (url === '/api/integrations/notifications' && method === 'GET') return json({ configured: true, channels })
    if (url.startsWith('/api/integrations/notifications') && method === 'POST') return json({ ok: true })
    if (url.startsWith('/api/integrations/notifications/') && method === 'DELETE') return json({ ok: true })
    if (url.startsWith('/api/integrations/notifications/') && method === 'PUT') return json({ ok: true })
    return json({}, 404)
  }))
})
afterEach(() => { vi.unstubAllGlobals(); setCsrf(null) })

describe('NotificationSettings', () => {
  it('zeigt nur Name und Typ, nie eine URL', async () => {
    const w = mount(NotificationSettings)
    await flushPromises()
    expect(w.text()).toContain('Handy')
    expect(w.text()).toContain('ntfy')
  })

  it('Formular ist standardmäßig ausgeblendet und öffnet sich per Klick auf „Add channel“', async () => {
    const w = mount(NotificationSettings)
    await flushPromises()
    expect(w.find('.add-channel-panel').exists()).toBe(false)
    await w.get('button[data-test=add-channel]').trigger('click')
    expect(w.find('.add-channel-panel').exists()).toBe(true)
  })

  it('fügt einen Kanal hinzu und leert das URL-Feld', async () => {
    const w = mount(NotificationSettings)
    await flushPromises()
    await w.get('button[data-test=add-channel]').trigger('click')
    await w.get('button[data-test=tab-apprise]').trigger('click')
    await w.get('input[name=name]').setValue('Mail')
    await w.get('input[name=url]').setValue('mailtos://u:GEHEIM@h?to=a@b.de')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(calls.find((c) => c.method === 'POST').body).toEqual({ name: 'Mail', url: 'mailtos://u:GEHEIM@h?to=a@b.de' })
    expect(w.find('.add-channel-panel').exists()).toBe(false)
    expect(w.html()).not.toContain('GEHEIM')
  })

  it('speichert Mail-Zugangsdaten über das SMTP-Formular und leert das Passwort', async () => {
    const w = mount(NotificationSettings)
    await flushPromises()
    await w.get('button[data-test=add-channel]').trigger('click')
    await w.get('select[name=provider]').setValue('custom')
    await w.get('input[name=host]').setValue('smtp.example.org')
    await w.get('input[name=username]').setValue('noah')
    await w.get('input[name=password]').setValue('GEHEIM')
    await w.get('input[name=from_addr]').setValue('vw@example.org')
    await w.get('input[name=to_addr]').setValue('noah@example.org')
    await w.find('form').trigger('submit')
    await flushPromises()
    const post = calls.find((c) => c.url === '/api/integrations/notifications/smtp')
    expect(post.body).toMatchObject({ host: 'smtp.example.org', port: 587, security: 'starttls', password: 'GEHEIM' })
  })

  it('belegt iCloud vor: nur Adresse, App-Passwort und Empfänger nötig', async () => {
    const w = mount(NotificationSettings)
    await flushPromises()
    await w.get('button[data-test=add-channel]').trigger('click')
    await w.get('select[name=provider]').setValue('icloud')
    expect(w.find('input[name=host]').exists()).toBe(false)
    await w.get('input[name=from_addr]').setValue('REDACTED.com')
    await w.get('input[name=password]').setValue('abcd-efgh-ijkl-mnop')
    await w.get('input[name=to_addr]').setValue('REDACTED.com')
    await w.find('form').trigger('submit')
    await flushPromises()
    const post = calls.find((c) => c.url === '/api/integrations/notifications/smtp')
    expect(post.body).toMatchObject({ host: 'smtp.mail.me.com', port: 587, security: 'starttls', username: 'REDACTED.com', from_addr: 'REDACTED.com' })
  })

  it('entfernt einen Kanal per Index', async () => {
    const w = mount(NotificationSettings)
    await flushPromises()
    vi.stubGlobal('confirm', () => false)   // abgebrochen: nichts passiert
    await w.findAll('button[data-test=remove-channel]').at(0).trigger('click')
    await flushPromises()
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false)
    vi.stubGlobal('confirm', () => true)
    await w.findAll('button[data-test=remove-channel]').at(0).trigger('click')
    await flushPromises()
    expect(calls.some((c) => c.method === 'DELETE' && c.url === '/api/integrations/notifications/0')).toBe(true)
  })

  it('stellt pro Kanal ein, ob er Bericht, Alarme oder beides bekommt', async () => {
    channels = [{ index: 0, name: 'Handy', scheme: 'ntfy', gets: 'both' }]
    const w = mount(NotificationSettings)
    await flushPromises()
    await w.get('select[data-test=channel-gets]').setValue('alerts')
    await flushPromises()
    const put = calls.find((c) => c.method === 'PUT')
    expect(put).toEqual({ url: '/api/integrations/notifications/0', method: 'PUT', body: { gets: 'alerts' } })
  })
})
