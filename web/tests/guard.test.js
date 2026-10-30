import { describe, expect, it } from 'vitest'
import { routeFor } from '../src/guard.js'

const open = { setup_complete: false, authenticated: false }
const done = { setup_complete: true, authenticated: false }
const inn = { setup_complete: true, authenticated: true }

describe('routeFor', () => {
  it('leitet vor der Einrichtung alles auf /einrichtung', () => {
    expect(routeFor(open, '/')).toBe('/einrichtung')
    expect(routeFor(open, '/login')).toBe('/einrichtung')
  })
  it('lässt /einrichtung vor der Einrichtung zu', () => {
    expect(routeFor(open, '/einrichtung')).toBeNull()
  })
  it('sperrt /einrichtung nach der Einrichtung', () => {
    expect(routeFor(done, '/einrichtung')).toBe('/login')
    expect(routeFor(inn, '/einrichtung')).toBe('/')
  })
  it('schickt Abgemeldete auf /login', () => {
    expect(routeFor(done, '/')).toBe('/login')
    expect(routeFor(done, '/einstellungen')).toBe('/login')
  })
  it('schickt Angemeldete von /login auf die Übersicht', () => {
    expect(routeFor(inn, '/login')).toBe('/')
  })
  it('lässt Angemeldete überall sonst durch', () => {
    expect(routeFor(inn, '/einstellungen')).toBeNull()
  })
})
