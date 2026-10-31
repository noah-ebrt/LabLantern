import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import SettingsFinder from '../src/components/SettingsFinder.vue'
import { reveal } from '../src/reveal.js'
import { OLD_TABS, SETTINGS_INDEX, SETTINGS_TABS, findSettings } from '../src/settingsIndex.js'

describe('Find a setting', () => {
  it('finds by label and by words, label hits first', () => {
    expect(findSettings('smtp')[0].target).toBe('set-channels')
    expect(findSettings('pause')[0].target).toBe('set-pause')
    expect(findSettings('fritz')[0].target).toBe('set-fritz')
    expect(findSettings('ai cost')[0].target).toBe('set-ai-cost')
    expect(findSettings('nothing-like-this')).toEqual([])
  })

  it('points only at existing tabs, and old tab keys map to new ones', () => {
    const keys = SETTINGS_TABS.map((t) => t.key)
    expect(SETTINGS_INDEX.every((e) => keys.includes(e.tab))).toBe(true)
    expect(Object.values(OLD_TABS).every((k) => keys.includes(k))).toBe(true)
  })

  it('picks a hit with the keyboard and emits it', async () => {
    const w = mount(SettingsFinder)
    const input = w.get('[data-test=settings-finder]')
    await input.setValue('watchdog')
    expect(w.findAll('[role=option]').length).toBeGreaterThan(0)
    await input.trigger('keydown', { key: 'Enter' })
    expect(w.emitted('go')[0][0].target).toBe('set-watchdog')
  })
})

describe('reveal', () => {
  it('opens every details around the target and scrolls to it', async () => {
    document.body.innerHTML = '<details id="outer"><summary>o</summary><details id="inner"><summary>i</summary><p id="t">x</p></details></details>'
    const t = document.getElementById('t')
    t.scrollIntoView = vi.fn()
    reveal('t')
    expect(document.getElementById('outer').open).toBe(true)
    expect(document.getElementById('inner').open).toBe(true)
    expect(t.scrollIntoView).toHaveBeenCalled()
    expect(t.classList.contains('found')).toBe(true)
  })

  it('waits for a target that renders later', async () => {
    vi.useFakeTimers()
    document.body.innerHTML = ''
    reveal('late')
    const p = Object.assign(document.createElement('p'), { id: 'late' })
    p.scrollIntoView = vi.fn()
    document.body.append(p)
    vi.advanceTimersByTime(150)
    expect(p.scrollIntoView).toHaveBeenCalled()
    vi.useRealTimers()
    await flushPromises()
  })
})
