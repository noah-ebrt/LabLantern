// Speicher von NAS-Geräten (storage.py auf dem Server): Größen, Zustände, Gruppierung nach Pool

export function fmtBytes(n) {
  if (n == null) return ''
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  let i = 0
  let v = n
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i++ }
  return `${v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`
}

export const STATE_TEXT = { ok: 'healthy', warn: 'warning', bad: 'failing', unknown: 'state unknown' }
export const DISK_TYPE = { hdd: 'HDD', ssd: 'SSD', nvme: 'NVMe' }

// Pools mit ihren Laufwerken, dann die Laufwerke ohne Pool. Volumes haben keine eigenen Laufwerke.
export function groups(st) {
  const pools = st?.pool_list || st?.pools || []
  const disks = st?.disks || []
  const byName = new Map(disks.map((d) => [d.name, d]))
  const used = new Set()
  const out = pools.map((p) => {
    const members = (p.disks || []).map((n) => byName.get(n)).filter(Boolean)
    members.forEach((d) => used.add(d.name))
    return { ...p, members }
  })
  const rest = disks.filter((d) => !used.has(d.name))
  if (rest.length) out.push({ name: 'Not in a pool', kind: '', layout: '', state: null, percent: null, members: rest, loose: true })
  return out
}

export function storageCounts(st) {
  const pools = st?.pool_list || st?.pools || []
  const disks = st?.disks || []
  const failing = [...pools, ...disks].filter((x) => x.state === 'bad').length
  const warning = [...pools, ...disks].filter((x) => x.state === 'warn').length
  return { pools: pools.length, disks: disks.length, failing, warning }
}

export function countsText(st) {
  const c = storageCounts(st)
  const parts = [`${c.pools} pool${c.pools === 1 ? '' : 's'}`, `${c.disks} drive${c.disks === 1 ? '' : 's'}`]
  if (c.failing) parts.push(`${c.failing} failing`)
  if (c.warning) parts.push(`${c.warning} warning`)
  return parts.join(' · ')
}
