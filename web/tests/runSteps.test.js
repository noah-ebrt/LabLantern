import { describe, expect, it } from 'vitest'
import { currentStep, hostInScan, percent, stepState, stepSummary } from '../src/runSteps.js'

const scanning = (p) => ({ phase: 'scanning', progress: p })

describe('runSteps', () => {
  it('maps run phases and worker steps to the five steps', () => {
    expect(currentStep(null)).toBe(null)
    expect(currentStep({ phase: 'collecting' })).toBe('collecting')
    expect(currentStep(scanning({}))).toBe('database')
    expect(currentStep(scanning({ step: 'image' }))).toBe('scan')
    expect(stepState('canary', scanning({ step: 'image' }))).toBe('done')
    expect(stepState('scan', scanning({ step: 'image' }))).toBe('active')
    expect(stepState('saving', scanning({ step: 'image' }))).toBe('pending')
    expect(stepState('scan', null)).toBe('pending')
  })

  it('shows which host is being scanned in database order (uppercase before lowercase)', () => {
    const run = scanning({ step: 'image', host: 'host-a', host_index: 2, hosts_total: 4, image_index: 3, images_total: 14 })
    expect(hostInScan('NAS', run).state).toBe('done')           // 'N' < 'h'
    expect(hostInScan('host-a', run)).toEqual({ state: 'active', text: 'scanning image 3 of 14' })
    expect(hostInScan('host-c', run).state).toBe('pending')
    expect(hostInScan('host-c', { phase: 'collecting' })).toBe(null)
    expect(stepSummary(run)).toBe('host-a · host 2/4 · image 3/14')
  })

  it('progress grows monotonically through the steps', () => {
    const seq = [
      { phase: 'collecting', systems_reported: 1, systems_total: 4 },
      scanning({ step: 'database' }), scanning({ step: 'canary' }),
      scanning({ step: 'host', host_index: 1, hosts_total: 2, images_total: 0 }),
      scanning({ step: 'image', host_index: 2, hosts_total: 2, image_index: 5, images_total: 10 }),
      scanning({ step: 'saving' }),
    ].map(percent)
    expect([...seq].sort((a, b) => a - b)).toEqual(seq)
    expect(seq.at(-1)).toBeLessThan(100)
  })
})
