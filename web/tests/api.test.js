import { afterEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError, setCsrf } from '../src/api.js'

function stubFetch(status, body) {
  const fn = vi.fn(async () => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }))
  vi.stubGlobal('fetch', fn)
  return fn
}

afterEach(() => { vi.unstubAllGlobals(); setCsrf(null) })

describe('api', () => {
  it('sendet bei GET keinen CSRF-Header', async () => {
    const f = stubFetch(200, { ok: 1 })
    setCsrf('tok')
    await api.get('/api/state')
    expect(f.mock.calls[0][1].headers['X-CSRF-Token']).toBeUndefined()
  })
  it('sendet bei Schreibzugriffen den CSRF-Header und JSON', async () => {
    const f = stubFetch(200, { ok: true })
    setCsrf('tok')
    await api.put('/api/integrations/smtp', { host: 'h' })
    const [, init] = f.mock.calls[0]
    expect(init.method).toBe('PUT')
    expect(init.headers['X-CSRF-Token']).toBe('tok')
    expect(init.headers['Content-Type']).toBe('application/json')
    expect(init.body).toBe('{"host":"h"}')
    expect(init.credentials).toBe('same-origin')
  })
  it('wirft ApiError mit Status und deutscher Meldung', async () => {
    stubFetch(401, { detail: 'Anmeldung fehlgeschlagen' })
    await expect(api.post('/api/login', {})).rejects.toMatchObject({
      name: 'ApiError', status: 401, message: 'Anmeldung fehlgeschlagen',
    })
  })
  it('macht aus Validierungsfehlern (422) eine lesbare Meldung', async () => {
    stubFetch(422, { detail: [{ loc: ['body', 'port'], msg: 'Input should be greater than or equal to 1' }] })
    await expect(api.put('/x', {})).rejects.toSatisfy((e) => e instanceof ApiError && e.message.includes('port'))
  })
})
