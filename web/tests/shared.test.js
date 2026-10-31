import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ref } from 'vue'
import Modal from '../src/components/Modal.vue'
import SettingsCard from '../src/components/SettingsCard.vue'
import { hostState, runBadge, runLabel } from '../src/labels.js'
import { useScanTrigger } from '../src/runSteps.js'
import { setCsrf } from '../src/api.js'

afterEach(() => {
  vi.unstubAllGlobals()
  setCsrf(null)
})

describe('Modal', () => {
  it('closes with Escape, the backdrop and the Close button', async () => {
    const w = mount(Modal, { props: { label: 'Test' }, slots: { default: '<p>Body</p>', actions: '<a class="extra">More</a>' }, attachTo: document.body })
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    await w.find('.modal-backdrop').trigger('click')
    await w.find('.modal-actions button').trigger('click')
    expect(w.emitted('close')).toHaveLength(3)
    expect(w.find('.extra').exists()).toBe(true)
    expect(w.find('[role=dialog]').attributes('aria-label')).toBe('Test')
    w.unmount()
  })

  it('leaves the footer to the dialog when footer=false', () => {
    const w = mount(Modal, { props: { footer: false } })
    expect(w.find('.modal-actions').exists()).toBe(false)
  })
})

describe('SettingsCard', () => {
  it('renders icon, title, subtitle and the badge/actions slots', () => {
    const w = mount(SettingsCard, { props: { icon: 'bell', title: 'Channels', subtitle: 'Where reports go' },
      slots: { badge: '<span class="badge ok">On</span>', actions: '<button>Add</button>', default: '<p>Body</p>' } })
    expect(w.find('h2').text()).toBe('Channels')
    expect(w.text()).toContain('Where reports go')
    expect(w.find('.badge').text()).toBe('On')
    expect(w.find('.head-actions button').text()).toBe('Add')
  })

  it('opens and scrolls to the details when the status badge has a target', async () => {
    const w = mount(SettingsCard, { props: { icon: 'bell', title: 'T', status: { tone: 'danger', text: '2 failing', target: 'why' } },
      slots: { default: '<details id="why"><summary>Why</summary>…</details>' }, attachTo: document.body })
    const details = document.getElementById('why')
    details.scrollIntoView = vi.fn()
    await w.get('a.badge').trigger('click')
    expect(details.open).toBe(true)
    expect(details.scrollIntoView).toHaveBeenCalled()
    w.unmount()
  })
})

describe('labels', () => {
  it('maps host and run states once for all views', () => {
    expect(hostState({ status: 'active', state: 'online', online: true })).toEqual({ tone: 'ok', text: 'connected' })
    expect(hostState({ status: 'active', state: 'offline' }).tone).toBe('bad')
    expect(hostState({ status: 'pending' })).toEqual({ tone: 'idle', text: 'pending' })
    expect(runLabel('partial')).toBe('Partial (errors)')
    expect(runBadge('running')).toBe('badge neutral')
  })
})

describe('useScanTrigger', () => {
  it('starts a run, reports it and calls after; errors go to the given ref', async () => {
    setCsrf('tok')
    let ok = true
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(ok ? { run_id: 9 } : { detail: 'A scan is already running' }),
      { status: ok ? 200 : 409, headers: { 'content-type': 'application/json' } })))
    const after = vi.fn()
    const error = ref('')
    const t = useScanTrigger({ after, error })
    await t.trigger()
    expect(t.message.value).toContain('Run #9 started')
    expect(after).toHaveBeenCalledOnce()
    ok = false
    await t.trigger()
    await flushPromises()
    expect(error.value).toContain('already running')
    expect(t.triggering.value).toBe(false)
  })
})
