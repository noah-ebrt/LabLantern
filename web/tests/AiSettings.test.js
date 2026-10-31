import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import AiSettings from '../src/components/AiSettings.vue'
import { setCsrf } from '../src/api.js'

let calls, ai

const baseAi = () => ({
  providers: [
    { id: 'anthropic', kind: 'anthropic', label: 'Anthropic', configured: true,
      key: { set: true, updated_at: '2026-10-30T12:00:00+00:00' },
      last_used: { at: '2026-10-30T12:05:00+00:00', task: 'classify', model: 'claude-haiku-5-5', ok: true },
      models: [{ id: 'claude-sonnet-5-5', name: 'Claude Sonnet 5.5', web: true },
               { id: 'claude-haiku-5-5', name: 'Claude Haiku 5.5', web: true }] },
    { id: 'openai', kind: 'openai', label: 'OpenAI', configured: false, key: { set: false, updated_at: null }, last_used: null, models: [] },
    { id: 'c1', kind: 'compat', label: 'Ollama', configured: true, key: { set: false, updated_at: null },
      display_url: 'http://10.0.0.5:11434/v1', last_used: null,
      models: [{ id: 'qwen3.8:27b', name: 'qwen3.8:27b', web: false }] },
  ],
  tasks: {
    classify: { ref: '', resolved: 'anthropic:claude-haiku-5-5', error: null },
    research: { ref: '', resolved: 'anthropic:claude-sonnet-5-5', error: null },
    verify: { ref: '', resolved: 'anthropic:claude-sonnet-5-5', error: null },
  },
})

beforeEach(() => {
  setCsrf('tok')
  calls = []
  ai = baseAi()
  vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
    const method = init.method || 'GET'
    calls.push({ url, method, body: init.body ? JSON.parse(init.body) : null })
    const json = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json' } })
    if (url === '/api/ai' && method === 'GET') return json(ai)
    if (url === '/api/ai/tasks' && method === 'PUT') return json({ ok: true })
    if (url === '/api/ai/providers/anthropic/test') return json({ ok: false, error: 'Anthropic: invalid x-api-key (HTTP 401)' })
    if (url.startsWith('/api/ai/providers/')) return json({ ok: true, models: [] })
    return json({}, 404)
  }))
})
afterEach(() => { vi.unstubAllGlobals(); setCsrf(null) })

const select = (w, task) => w.get(`select[data-test=task-${task}]`)
const values = (sel) => sel.findAll('option').map((o) => o.element.value)

describe('AiSettings', () => {
  it('renders resolved automatic model per task', async () => {
    const w = mount(AiSettings)
    await flushPromises()
    for (const t of ['classify', 'research', 'verify']) {
      expect(select(w, t).findAll('option')[0].text()).toMatch(/^Automatic . currently Claude (Haiku|Sonnet) 5\.5/)
      expect(select(w, t).element.value).toBe('')
    }
    expect(select(w, 'classify').findAll('option')[0].text()).toContain('Haiku')
    expect(w.text()).toContain('Classify feed advisories')
    expect(w.text()).toContain('Web research')
    expect(w.text()).toContain('Vendor check of critical and high matches')
  })

  it('shows "not available" when a task cannot resolve', async () => {
    ai.tasks.research = { ref: '', resolved: null, error: 'needs a provider with web search' }
    const w = mount(AiSettings)
    await flushPromises()
    expect(select(w, 'research').findAll('option')[0].text()).toBe('Automatic — not available')
  })

  it('web tasks do not offer compat or non-web models', async () => {
    ai.providers[0].models.push({ id: 'claude-old', name: 'Claude Old', web: false })
    const w = mount(AiSettings)
    await flushPromises()
    expect(values(select(w, 'classify'))).toEqual(['', 'anthropic:claude-sonnet-5-5', 'anthropic:claude-haiku-5-5', 'anthropic:claude-old', 'c1:qwen3.8:27b'])
    for (const t of ['research', 'verify']) {
      expect(values(select(w, t))).toEqual(['', 'anthropic:claude-sonnet-5-5', 'anthropic:claude-haiku-5-5'])
      expect(select(w, t).findAll('optgroup').map((g) => g.attributes('label'))).toEqual(['Anthropic'])
    }
  })

  it('shows task error from the API', async () => {
    ai.tasks.research = { ref: 'c1:x', resolved: null, error: 'needs a provider with web search' }
    const w = mount(AiSettings)
    await flushPromises()
    const err = w.get('[data-test=error-research]')
    expect(err.text()).toBe('needs a provider with web search')
    expect(err.classes()).toContain('text-danger')
    expect(w.find('[data-test=error-classify]').exists()).toBe(false)
  })

  it('saving sends refs with ollama ids containing colons unchanged', async () => {
    const w = mount(AiSettings)
    await flushPromises()
    await select(w, 'classify').setValue('c1:qwen3.8:27b')
    await select(w, 'verify').setValue('anthropic:claude-haiku-5-5')
    await w.get('button[data-test=save-tasks]').trigger('click')
    await flushPromises()
    const put = calls.find((c) => c.url === '/api/ai/tasks' && c.method === 'PUT')
    expect(put.body).toEqual({ classify: 'c1:qwen3.8:27b', research: '', verify: 'anthropic:claude-haiku-5-5' })
  })

  it('shows stored keys without a value and the last use', async () => {
    const w = mount(AiSettings)
    await flushPromises()
    expect(w.text()).toContain('Stored encrypted')
    expect(w.text()).toMatch(/last used .* with claude-haiku-5-5 \(classify\) — ok/)
    expect(w.get('input[name=anthropic_key]').element.value).toBe('')
  })

  it('shows the test result of a provider', async () => {
    const w = mount(AiSettings)
    await flushPromises()
    await w.get('button[data-test=test-anthropic]').trigger('click')
    await flushPromises()
    expect(w.text()).toContain('HTTP 401')
  })

  it('shows one provider at a time, starting with the first configured one', async () => {
    const w = mount(AiSettings)
    await flushPromises()
    expect(w.get('button[data-test=tab-anthropic]').attributes('aria-checked')).toBe('true')
    expect(w.find('form[data-test=form-anthropic]').exists()).toBe(true)
    expect(w.find('form[data-test=form-openai]').exists()).toBe(false)
    expect(w.find('form[data-test=form-c1]').exists()).toBe(false)
    await w.get('button[data-test=tab-openai]').trigger('click')
    expect(w.find('form[data-test=form-openai]').exists()).toBe(true)
    expect(w.find('form[data-test=form-anthropic]').exists()).toBe(false)
  })

  it('saves an OpenAI key and clears the field', async () => {
    const w = mount(AiSettings)
    await flushPromises()
    await w.get('button[data-test=tab-openai]').trigger('click')
    await w.get('input[name=openai_key]').setValue('sk-test-123')
    await w.get('form[data-test=form-openai]').trigger('submit')
    await flushPromises()
    const put = calls.find((c) => c.url === '/api/ai/providers/openai' && c.method === 'PUT')
    expect(put.body).toEqual({ api_key: 'sk-test-123' })
    expect(w.get('input[name=openai_key]').element.value).toBe('')
  })

  it('saves the compatible endpoint with name and base URL, key optional', async () => {
    ai.providers[2] = { id: 'c1', kind: 'compat', label: 'Custom endpoint', configured: false, key: { set: false, updated_at: null }, last_used: null, models: [] }
    const w = mount(AiSettings)
    await flushPromises()
    await w.get('button[data-test=tab-c1]').trigger('click')
    expect(w.get('input[name=c1_base_url]').attributes('placeholder')).toBe('http://192.168.1.10:11434/v1')
    expect(w.text()).toContain('API key (optional)')
    await w.get('input[name=c1_name]').setValue('Ollama')
    await w.get('input[name=c1_base_url]').setValue('http://10.0.0.5:11434/v1')
    await w.get('form[data-test=form-c1]').trigger('submit')
    await flushPromises()
    const put = calls.find((c) => c.url === '/api/ai/providers/c1' && c.method === 'PUT')
    expect(put.body).toEqual({ name: 'Ollama', base_url: 'http://10.0.0.5:11434/v1' })
  })

  it('shows an error with a retry instead of an empty card when the settings cannot be loaded', async () => {
    let fail = true
    const ok = globalThis.fetch
    vi.stubGlobal('fetch', vi.fn(async (url, init) => (fail && url === '/api/ai'
      ? new Response(JSON.stringify({ detail: 'Internal Server Error' }), { status: 500, headers: { 'content-type': 'application/json' } })
      : ok(url, init))))
    const w = mount(AiSettings)
    await flushPromises()
    expect(w.get('[data-test=load-error]').text()).toContain('Could not load the AI settings')
    fail = false
    await w.get('[data-test=load-retry]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test=load-error]').exists()).toBe(false)
    expect(w.text()).toContain('Anthropic API key')
  })
})
