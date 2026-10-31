import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import StorageView from '../src/components/StorageView.vue'
import { fmtBytes, groups } from '../src/storage.js'

const st = {
  error: '',
  pools: [{ name: 'tank', kind: 'ZFS pool', layout: 'RAIDZ1', status: 'degraded', state: 'bad', percent: 91.4, size: 12e12, disks: ['sda', 'sdb', 'sdc'] }],
  disks: [
    { name: 'sda', model: 'WD40EFRX', size: 4e12, type: 'hdd', state: 'ok', status: 'online', temp: 34, pool: 'tank' },
    { name: 'sdb', model: 'WD40EFRX', size: 4e12, type: 'hdd', state: 'warn', status: 'warning', temp: null, pool: 'tank' },
    { name: 'sdc', model: 'WD40EFRX', size: 4e12, type: 'hdd', state: 'bad', status: 'faulted', temp: null, pool: 'tank' },
    { name: 'nvme0n1', model: 'SN770', size: 1e12, type: 'nvme', state: 'unknown', status: '', temp: null, pool: '' },
  ],
}

describe('StorageView', () => {
  it('ein Symbol je Laufwerk, in der Farbe seines Zustands, nach Pool gruppiert', () => {
    const w = mount(StorageView, { props: { storage: st } })
    expect(w.findAll('[data-test="pool-tank"] .disk')).toHaveLength(3)
    expect(w.find('[data-test="disk-sdc"]').classes()).toContain('bad')
    expect(w.find('[data-test="disk-sdb"]').classes()).toContain('warn')
    expect(w.find('[data-test="disk-nvme0n1"]').classes()).toEqual(expect.arrayContaining(['unknown', 'nvme']))
    expect(w.find('[data-test="pool-Not in a pool"]').exists()).toBe(true)
    expect(w.find('[data-test="disk-sda"]').attributes('aria-label')).toBe('sda · WD40EFRX · 4.0 TB · HDD · 34 °C · healthy')
    expect(w.text()).toContain('RAIDZ1')
    expect(w.text()).toContain('91 %')
  })

  it('Hilfsfunktionen', () => {
    expect(fmtBytes(4000787030016)).toBe('4.0 TB')
    expect(fmtBytes(500e9)).toBe('500 GB')
    expect(groups({ pools: [], disks: [] })).toEqual([])
  })
})
