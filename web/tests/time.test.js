import { afterEach, describe, expect, it } from 'vitest'
import { clock, fmtClock, parseTime } from '../src/time.js'

afterEach(() => { clock.timeZone = 'UTC' })

describe('time', () => {
  it('reads ISO values without offset as UTC', () => {
    expect(parseTime('2026-10-25T20:40:43.123456').toISOString()).toBe('2026-10-25T20:40:43.123Z')
    expect(parseTime('2026-10-25T20:40:43+00:00').toISOString()).toBe('2026-10-25T20:40:43.000Z')
    expect(parseTime(1761424843).toISOString()).toBe('2025-10-25T20:40:43.000Z')
    expect(parseTime(null)).toBeNull()
  })

  it('formats in the system time zone', () => {
    expect(fmtClock('2026-10-25T20:40:43')).toBe('20:40')
    clock.timeZone = 'Europe/Berlin'
    expect(fmtClock('2026-10-25T20:40:43')).toBe('21:40')
  })
})
