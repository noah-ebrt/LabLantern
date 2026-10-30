import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import ConnectorDetailModal from '../src/components/ConnectorDetailModal.vue'

const day = 86400e3
const ha = {
  id: 7, name: 'homeassistant', host_type: 'homeassistant', status: 'connector', last_seen: new Date().toISOString(),
  collection_errors: {},
  inventory: { connector: {
    version: '2026.10.1', state: 'RUNNING', safe_mode: false, recovery_mode: false,
    updates: [{ entity_id: 'update.core', state: 'on', name: 'Home Assistant Core', version: '2026.10.1', latest: '2026.10.3' },
      { entity_id: 'update.os', state: 'off', name: 'Home Assistant Operating System', version: '16.2', latest: '16.2' }],
    backup: { present: true, times: [new Date(Date.now() - day).toISOString(), new Date(Date.now() - day).toISOString(),
      new Date(Date.now() + day).toISOString()] },
    disks: [{ entity_id: 'sensor.d', name: 'Config disk', percent: 41.2 }],
    batteries: [{ entity_id: 'sensor.a', name: 'IKEA switch', level: 80, low: false },
      { entity_id: 'sensor.b', name: 'Wohnungstür', level: 9, low: false }],
    integrations: ['matter', 'nuki', 'shelly'],
  } },
}

const watched = { feeds: 3, ai_configured: true, items: [
  { keyword: 'home assistant', product: 'Home Assistant Core', version: '2026.10.1', group: 'Updates (core, OS, add-ons, firmware)', title_only: true },
  { keyword: 'nuki', product: 'Home Assistant integration nuki', version: '', group: 'Integrations', title_only: true }] }

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async (url) => new Response(JSON.stringify(String(url).includes('/early-warnings/watched/') ? watched : ha),
    { status: 200, headers: { 'content-type': 'application/json' } })))
})

describe('ConnectorDetailModal', () => {
  it('zeigt auch, was keinen Fund ergibt: Backup, Platte, alle Batterien, Integrationen', async () => {
    const w = mount(ConnectorDetailModal, { props: { systemId: 7 }, global: { stubs: { RouterLink: true } } })
    await flushPromises()
    const text = w.text()
    expect(text).toContain('Updates (1 open of 2)')
    expect(text).toContain('2026.10.3')
    expect(text).toContain('41 % used')
    expect(text).toContain('Next automatic backup')
    expect(text).not.toContain('failed')
    expect(text.indexOf('Wohnungstür')).toBeLessThan(text.indexOf('IKEA switch'))   // niedrigste zuerst
    expect(text).toContain('Watched by the early warning (2)')
    expect(text).toContain('Integrations (1)')
    expect(text).toContain('nuki')
  })

  it('zeigt fünf Batterien, auf Wunsch alle, und sortiert um', async () => {
    const many = Array.from({ length: 8 }, (_, i) => ({ entity_id: `sensor.b${i}`, name: `Sensor ${i}`, level: 90 - i * 10, low: false }))
    ha.inventory.connector.batteries = many
    const w = mount(ConnectorDetailModal, { props: { systemId: 7 }, global: { stubs: { RouterLink: true } } })
    await flushPromises()
    expect(w.text()).toContain('Sensor 7')        // 20 %, niedrigste zuerst
    expect(w.text()).not.toContain('Sensor 0')    // 90 %, erst mit „Show all“
    await w.findAll('button.link').find((b) => b.text().startsWith('Show all')).trigger('click')
    expect(w.text()).toContain('Sensor 0')
    await w.find('button.sort').trigger('click')
    expect(w.text().indexOf('Sensor 0')).toBeLessThan(w.text().indexOf('Sensor 7'))
  })
})
