import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import AiLevelSettings from '../src/components/AiLevelSettings.vue'
import { estimate, fmtUsd, passesPerDay, priceOf, researchRunUsd, researchRunsPerMonth, taskMonthly } from '../src/aicost.js'
import { setCsrf } from '../src/api.js'

const basis = () => ({
  days: 14, search_usd: 0.01,
  classify: { model: 'claude-haiku-5-5', usd: 0.0007, per_day: 5, measured: 30 },
  research: { model: 'claude-sonnet-5-5', usd: 0.35, measured: 1 },
  verify: { model: 'claude-sonnet-5-5', usd: 0.15, per_day: 1, nvd_share: null, nvd_measured: 0, measured: 0 },
})

describe('cost per model', () => {
  const measured = () => ({
    ...basis(), prices: { 'claude-haiku-5-5': [0.1, 0.5], 'claude-sonnet-5-5': [2, 10], 'claude-sonnet-5': [3, 15] },
    verify: { model: 'claude-sonnet-5-5', price: [2, 10], usd: 0.14, tokens_in: 40000, tokens_out: 2000, searches: 4, per_day: 2, nvd_share: null },
  })
  const cfg = { level: 'full', pass_times: ['06:00', '15:00'], full_scan: { enabled: true, time: '03:00' }, research_days: 3, verify_searches: 4, verify_per_pass: 3 }

  it('finds the list price by the longest model prefix', () => {
    expect(priceOf(measured().prices, 'claude-sonnet-5-5-20260928')).toEqual([2, 10])
    expect(priceOf(measured().prices, 'gpt-x')).toBeNull()
  })

  it('prices a task for another model from the measured token use', () => {
    // 60 Prüfungen im Monat: Sonnet 0,08 + 0,02 + 0,04 Suche; Haiku 0,004 + 0,001 + 0,04
    expect(taskMonthly(measured(), cfg, { enabled: true, verify: true }, 'verify', 'claude-sonnet-5-5')).toBeCloseTo(60 * 0.14)
    expect(taskMonthly(measured(), cfg, { enabled: true, verify: true }, 'verify', 'claude-haiku-5-5')).toBeCloseTo(60 * 0.045)
    expect(taskMonthly(measured(), cfg, { enabled: true, verify: true }, 'verify', 'qwen3.8:27b')).toBeNull()
  })

  it('follows the searches per vendor check and the checks per pass', () => {
    const half = estimate(measured(), { ...cfg, verify_searches: 2 }).rows[2]
    expect(half.usd).toBeCloseTo(0.05 + 0.02)   // halb so viele Suchen lesen halb so viele Seiten
    const capped = estimate({ ...measured(), verify: { ...measured().verify, per_day: 9 } }, { ...cfg, verify_per_pass: 1 })
    expect(capped.rows[2].count).toBeCloseTo(90)   // 3 Durchgänge am Tag, je einer
  })
})

describe('estimate', () => {
  it('prices each level per month', () => {
    const full = estimate(basis(), { level: 'full', pass_times: ['06:00', '15:00'], research_days: 1 })
    expect(full.rows.map((r) => r.count)).toEqual([150, 30, 30])
    expect(full.total).toBeCloseTo(0.105 + 10.5 + 4.5)
    const balanced = estimate(basis(), { level: 'balanced', pass_times: ['06:00', '15:00'], research_days: 3 })
    expect(balanced.rows.map((r) => r.count)).toEqual([150, 10, 27])   // NVD-Anteil 10 % angenommen
    expect(balanced.total).toBeCloseTo(0.105 + 3.5 + 4.05)
    expect(estimate(basis(), { level: 'minimal', pass_times: ['06:00'], research_days: 3 }).total).toBeCloseTo(0.105)
  })

  it('uses the measured NVD share and respects switched-off steps', () => {
    const b = { ...basis(), verify: { ...basis().verify, nvd_share: 0.8 } }
    expect(estimate(b, { level: 'balanced', pass_times: ['06:00', '15:00'], research_days: 3 }).rows[2].count).toBeCloseTo(6)
    const off = estimate(basis(), { level: 'full', pass_times: ['06:00'], research_days: 1 }, { enabled: false, verify: false })
    expect(off.total).toBeCloseTo(0.105)
  })

  it('counts the full scan as a feed check and research runs every N days', () => {
    const scan = { enabled: true, time: '03:00' }
    expect(passesPerDay({ pass_times: ['06:00', '15:00'], full_scan: scan })).toBe(3)
    expect(passesPerDay({ pass_times: ['03:00', '15:00'], full_scan: scan })).toBe(2)   // dieselbe Uhrzeit zählt einmal
    expect(passesPerDay({ pass_times: [], full_scan: { ...scan, enabled: false } })).toBe(0)
    expect(researchRunsPerMonth(2, 1)).toBe(30)
    expect(researchRunsPerMonth(1, 3)).toBe(10)
    expect(researchRunsPerMonth(0, 1)).toBe(0)   // ohne Feed-Prüfung keine Recherche
  })

  it('has no total when a used model has no known price', () => {
    const b = { ...basis(), research: { model: 'gpt-x', usd: null, measured: 0 } }
    expect(estimate(b, { level: 'full', research_days: 1 }).total).toBeNull()
    expect(estimate(b, { level: 'minimal', research_days: 1 }).total).toBeCloseTo(0.105)
  })

  it('formats money', () => {
    expect([fmtUsd(null), fmtUsd(0), fmtUsd(0.004), fmtUsd(5.855), fmtUsd(120.4)]).toEqual(['—', '$0', '< $0.01', '$5.86', '$120'])
  })
})

describe('research cost with a search cap', () => {
  it('scales tokens and searches down, never up', () => {
    const r = { price: [2, 10], tokens_in: 75000, tokens_out: 3000, searches: 20, usd: 0.38 }
    expect(researchRunUsd(r, 30, 0.01)).toBeCloseTo(0.18 + 0.2)
    expect(researchRunUsd(r, 10, 0.01)).toBeCloseTo(0.09 + 0.1)
    expect(researchRunUsd({ ...r, price: null }, 10, 0.01)).toBe(0.38)   // ohne Preis: der gemessene Wert
  })
})

describe('AiLevelSettings', () => {
  let calls
  let server

  beforeEach(() => {
    setCsrf('tok')
    calls = []
    server = { full_scan: { enabled: true, time: '03:00' }, timezone: 'Europe/Berlin' }
    vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
      const method = init.method || 'GET'
      calls.push({ url, method, body: init.body ? JSON.parse(init.body) : null })
      const json = (b) => new Response(JSON.stringify(b), { status: 200, headers: { 'content-type': 'application/json' } })
      if (method === 'GET') return json({ level: 'full', pass_times: ['06:00', '15:00'], research_days: 1, max_searches: 15, kev: true, release_feeds: true,
        health_alerts: true, miss_check: true, research: { enabled: true, verify: true }, basis: basis(), ...server,
        release_feeds_found: [{ url: 'https://github.com/dani-garcia/vaultwarden/releases.atom', keywords: ['vaultwarden'] }] })
      return json({ ok: true })
    }))
  })
  afterEach(() => vi.unstubAllGlobals())

  it('shows a monthly cost per level and saves the choice with its suggested interval', async () => {
    const w = mount(AiLevelSettings)
    await flushPromises()
    expect(w.get('[data-test="cost-full"]').text()).toBe(`${fmtUsd(0.105 + 10.5 + 4.5)}/month`)
    expect(w.get('[data-test="cost-minimal"]').text()).toBe('$0.10/month')
    expect(w.get('[data-test="schedule"]').text()).toBe('Runs at: Full scan 03:00 + 06:00 + 15:00')
    expect(w.text()).toContain('Feed checks (Europe/Berlin)')
    expect(w.get('[data-test="save-level"]').attributes('disabled')).toBeDefined()   // nichts geändert
    await w.get('[data-test="level-balanced"]').trigger('click')
    expect(w.get('[data-test="research-days"]').element.value).toBe('3')
    expect(w.get('[data-test="breakdown"]').text()).toContain('10 runs')
    await w.get('[data-test="slot-on-1"] input').setValue(false)
    await w.get('[data-test="slot-time-0"]').setValue('07:30')
    expect(w.get('[data-test="schedule"]').text()).toBe('Runs at: Full scan 03:00 + 07:30')
    await w.get('[data-test="save-level"]').trigger('click')
    await flushPromises()
    expect(calls.at(-1)).toEqual({ url: '/api/early-warnings/ai-level', method: 'PUT', body: { level: 'balanced', pass_times: ['07:30'], research_days: 3,
      max_searches: 15, verify_repeat: 'never', verify_searches: 4, verify_per_pass: 3,
      kev: true, release_feeds: true, health_alerts: true, miss_check: true } })
    expect(w.text()).toContain('Saved.')
  })

  it('switches safety nets and lists the release feeds', async () => {
    const w = mount(AiLevelSettings)
    await flushPromises()
    expect(w.get('[data-test="release-feeds"]').text()).toContain('dani-garcia/vaultwarden')
    await w.get('[data-test="switch-miss_check"] input').setValue(false)
    await w.get('[data-test="max-searches"]').setValue(8)
    await w.get('[data-test="save-level"]').trigger('click')
    await flushPromises()
    expect(calls.at(-1).body).toMatchObject({ miss_check: false, max_searches: 8, kev: true })
    await w.get('[data-test="max-searches"]').setValue(40)
    expect(w.get('[data-test="save-level"]').attributes('disabled')).toBeDefined()
  })

  it('saves how the vendor check repeats, searches and how many run per feed check', async () => {
    const w = mount(AiLevelSettings)
    await flushPromises()
    expect(w.get('[data-test="verify-repeat"]').element.value).toBe('never')   // ein Server ohne den Wert: Vorgabe
    await w.get('[data-test="verify-repeat"]').setValue('new_cve')
    await w.get('[data-test="verify-searches"]').setValue(2)
    await w.get('[data-test="verify-per-pass"]').setValue(5)
    await w.get('[data-test="save-level"]').trigger('click')
    await flushPromises()
    expect(calls.at(-1).body).toMatchObject({ verify_repeat: 'new_cve', verify_searches: 2, verify_per_pass: 5 })
    await w.get('[data-test="verify-searches"]').setValue(11)
    expect(w.get('[data-test="save-level"]').attributes('disabled')).toBeDefined()
  })

  it('blocks invalid times and disables web research on minimal', async () => {
    const w = mount(AiLevelSettings)
    await flushPromises()
    await w.get('[data-test="slot-time-0"]').setValue('')
    expect(w.get('[data-test="save-level"]').attributes('disabled')).toBeDefined()
    expect(w.text()).toContain('Feed checks: a time as HH:MM')
    await w.get('[data-test="level-minimal"]').trigger('click')
    expect(w.get('[data-test="research-days"]').attributes('disabled')).toBeDefined()
  })

  it('says so when the full scan is off and no extra check is set', async () => {
    server = { full_scan: { enabled: false, time: '03:00' }, pass_times: [] }
    const w = mount(AiLevelSettings)
    await flushPromises()
    expect(w.get('[data-test="slot-full-scan"]').text()).toContain('switched off')
    expect(w.get('[data-test="slot-time-0"]').attributes('disabled')).toBeDefined()
    expect(w.get('[data-test="schedule"]').text()).toContain('No automatic feed checks')
    await w.get('[data-test="slot-on-1"] input').setValue(true)
    expect(w.get('[data-test="schedule"]').text()).toBe('Runs at: 15:00')
  })
})
