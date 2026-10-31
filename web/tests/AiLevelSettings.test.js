import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import AiLevelSettings from '../src/components/AiLevelSettings.vue'
import { estimate, fmtUsd, researchRunUsd, researchRunsPerMonth } from '../src/aicost.js'
import { setCsrf } from '../src/api.js'

const basis = () => ({
  days: 14, search_usd: 0.01,
  classify: { model: 'claude-haiku-5-5', usd: 0.0007, per_day: 5, measured: 30 },
  research: { model: 'claude-sonnet-5-5', usd: 0.35, measured: 1 },
  verify: { model: 'claude-sonnet-5-5', usd: 0.15, per_day: 1, nvd_share: null, nvd_measured: 0, measured: 0 },
})

describe('estimate', () => {
  it('prices each level per month', () => {
    const full = estimate(basis(), { level: 'full', pass_hours: 2, research_hours: 20 })
    expect(full.rows.map((r) => r.count)).toEqual([150, 36, 30])
    expect(full.total).toBeCloseTo(0.105 + 12.6 + 4.5)
    const balanced = estimate(basis(), { level: 'balanced', pass_hours: 2, research_hours: 72 })
    expect(balanced.rows.map((r) => r.count)).toEqual([150, 10, 27])   // NVD-Anteil 10 % angenommen
    expect(balanced.total).toBeCloseTo(0.105 + 3.5 + 4.05)
    expect(estimate(basis(), { level: 'minimal', pass_hours: 2, research_hours: 72 }).total).toBeCloseTo(0.105)
  })

  it('uses the measured NVD share and respects switched-off steps', () => {
    const b = { ...basis(), verify: { ...basis().verify, nvd_share: 0.8 } }
    expect(estimate(b, { level: 'balanced', pass_hours: 2, research_hours: 72 }).rows[2].count).toBeCloseTo(6)
    const off = estimate(basis(), { level: 'full', pass_hours: 2, research_hours: 20 }, { enabled: false, verify: false })
    expect(off.total).toBeCloseTo(0.105)
  })

  it('research runs at the first pass after its interval', () => {
    expect(researchRunsPerMonth(2, 20)).toBe(36)
    expect(researchRunsPerMonth(3, 20)).toBeCloseTo(720 / 21)
  })

  it('has no total when a used model has no known price', () => {
    const b = { ...basis(), research: { model: 'gpt-x', usd: null, measured: 0 } }
    expect(estimate(b, { level: 'full', pass_hours: 2, research_hours: 20 }).total).toBeNull()
    expect(estimate(b, { level: 'minimal', pass_hours: 2, research_hours: 20 }).total).toBeCloseTo(0.105)
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

  beforeEach(() => {
    setCsrf('tok')
    calls = []
    vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
      const method = init.method || 'GET'
      calls.push({ url, method, body: init.body ? JSON.parse(init.body) : null })
      const json = (b) => new Response(JSON.stringify(b), { status: 200, headers: { 'content-type': 'application/json' } })
      if (method === 'GET') return json({ level: 'full', pass_hours: 2, research_hours: 20, max_searches: 15, kev: true, release_feeds: true,
        health_alerts: true, miss_check: true, research: { enabled: true, verify: true }, basis: basis(),
        release_feeds_found: [{ url: 'https://github.com/dani-garcia/vaultwarden/releases.atom', keywords: ['vaultwarden'] }] })
      return json({ ok: true })
    }))
  })
  afterEach(() => vi.unstubAllGlobals())

  it('shows a monthly cost per level and saves the choice with its suggested interval', async () => {
    const w = mount(AiLevelSettings)
    await flushPromises()
    expect(w.get('[data-test="cost-full"]').text()).toBe('$17.20/month')
    expect(w.get('[data-test="cost-minimal"]').text()).toBe('$0.10/month')
    expect(w.get('[data-test="save-level"]').attributes('disabled')).toBeDefined()   // nichts geändert
    await w.get('[data-test="level-balanced"]').trigger('click')
    expect(w.get('[data-test="research-hours"]').element.value).toBe('72')
    expect(w.get('[data-test="breakdown"]').text()).toContain('10 runs')
    await w.get('[data-test="pass-hours"]').setValue(4)
    await w.get('[data-test="save-level"]').trigger('click')
    await flushPromises()
    expect(calls.at(-1)).toEqual({ url: '/api/early-warnings/ai-level', method: 'PUT', body: { level: 'balanced', pass_hours: 4, research_hours: 72,
      max_searches: 15, kev: true, release_feeds: true, health_alerts: true, miss_check: true } })
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

  it('blocks invalid intervals and disables research hours on minimal', async () => {
    const w = mount(AiLevelSettings)
    await flushPromises()
    await w.get('[data-test="pass-hours"]').setValue(0)
    expect(w.get('[data-test="save-level"]').attributes('disabled')).toBeDefined()
    expect(w.text()).toContain('Feed checks: 1–24 hours')
    await w.get('[data-test="level-minimal"]').trigger('click')
    expect(w.get('[data-test="research-hours"]').attributes('disabled')).toBeDefined()
  })
})
