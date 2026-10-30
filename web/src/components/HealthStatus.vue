<script setup>
import { computed, ref } from 'vue'
import { fmtMs, fmtPct, stateOf } from '../health.js'
import { fmtDateTime, timeAgo } from '../time.js'
import HealthMonitorDetail from './HealthMonitorDetail.vue'
import Icon from './Icon.vue'
import StatTile from './StatTile.vue'
import StateBadge from './StateBadge.vue'
import UptimeBar from './UptimeBar.vue'

// Reiter „Status“: Kennzahlen, alle Monitore mit 24-h-Balken, aufklappbare Details, letzte Ausfälle
const props = defineProps({ data: { type: Object, required: true }, refresh: { type: Number, default: 0 } })
const emit = defineEmits(['configure'])

const FILTERS = [['all', 'All'], ['problems', 'Problems'], ['critical', 'Critical']]
const filter = ref('all')
const open = ref(null)
const ORDER = { down: 0, degraded: 1, unknown: 2, up: 3, paused: 4 }

const monitors = computed(() => {
  let list = [...props.data.monitors]
  if (filter.value === 'problems') list = list.filter((m) => ['down', 'degraded', 'unknown'].includes(m.state) || m.warning)
  if (filter.value === 'critical') list = list.filter((m) => m.critical)
  return list.sort((a, b) => ORDER[a.state] - ORDER[b.state] || a.name.localeCompare(b.name))
})
const s = computed(() => props.data.summary)
const avgUptime = computed(() => {
  const v = props.data.monitors.map((m) => m.uptime['24h']).filter((x) => x != null)
  return v.length ? v.reduce((a, b) => a + b, 0) / v.length : null
})
</script>

<template>
  <p v-if="!data.engine.ok" class="message error" role="alert">
    Health checks are not running (last round {{ data.engine.last_tick ? timeAgo(data.engine.last_tick) : 'never' }}).
    Every host shows as unknown until they run again, and the API reports the same.
  </p>

  <div class="tiles">
    <StatTile label="Up" :value="s.up" tone="ok" :hint="`of ${s.total} hosts`" />
    <StatTile label="Degraded" :value="s.degraded" :tone="s.degraded ? 'warning' : ''" hint="failing checks, not down yet" />
    <StatTile label="Down" :value="s.down" :tone="s.down ? 'danger' : ''" :hint="s.down ? 'confirmed outages' : 'nothing down'" />
    <StatTile label="Availability 24 h" :value="fmtPct(avgUptime)" :hint="`${s.unknown} unknown · ${s.paused} paused`" />
  </div>

  <section class="card monitors">
    <div class="card-header">
      <h2>Hosts</h2>
      <div class="seg" role="group" aria-label="Filter">
        <button v-for="[k, l] in FILTERS" :key="k" type="button" :class="['seg-btn', { active: filter === k }]" @click="filter = k">{{ l }}</button>
      </div>
    </div>

    <div v-if="!data.monitors.length" class="empty-state">
      <p>No hosts monitored yet. Agent hosts appear here on their own; other devices you add under Settings.</p>
      <button type="button" class="btn-sm" @click="emit('configure')"><Icon name="plus" :size="14" />Add a host</button>
    </div>
    <p v-else-if="!monitors.length" class="sub">Nothing matches this filter.</p>

    <ul class="rows">
      <li v-for="m in monitors" :key="m.id" :class="['row', m.state, { open: open === m.id }]">
        <button type="button" class="row-head" :aria-expanded="open === m.id" @click="open = open === m.id ? null : m.id">
          <span class="who">
            <i class="pulse" :style="{ background: stateOf(m.state).color }" aria-hidden="true" />
            <span class="name">{{ m.name }}</span>
            <span v-if="m.auto" class="tag">Agent</span>
            <span v-if="m.critical" class="tag crit">Critical</span>
            <span class="host">{{ m.host || '—' }}</span>
          </span>
          <span class="state"><StateBadge :state="m.state" /><span v-if="m.warning" class="warn" :title="m.warning"><Icon name="bell" :size="13" />{{ m.warning }}</span></span>
          <span class="nums">
            <span><small>Latency</small>{{ fmtMs(m.latency_ms) }}</span>
            <span><small>24 h</small>{{ fmtPct(m.uptime['24h']) }}</span>
            <span><small>7 d</small>{{ fmtPct(m.uptime['7d']) }}</span>
            <span><small>30 d</small>{{ fmtPct(m.uptime['30d']) }}</span>
          </span>
          <UptimeBar class="bar" compact :segments="m.segments" :label="`${m.name}: availability over 24 hours`" />
          <Icon name="chevron" :size="16" class="chev" />
        </button>
        <HealthMonitorDetail v-if="open === m.id" :monitor="m" :refresh="refresh" />
      </li>
    </ul>
  </section>

  <section v-if="data.incidents.length" class="card">
    <div class="card-header"><h2>Recent outages</h2></div>
    <ul class="incidents">
      <li v-for="(e, i) in data.incidents" :key="i">
        <span class="when">{{ fmtDateTime(e.ts) }}</span><b>{{ e.name }}</b><span class="sub">{{ e.detail || 'went down' }}</span>
      </li>
    </ul>
  </section>
</template>

<style scoped>
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 0.9rem; }
.monitors { display: flex; flex-direction: column; margin-bottom: 0; }
.card-header { flex-wrap: wrap; }
.empty-state { display: flex; flex-direction: column; align-items: flex-start; gap: 0.7rem; padding: 1rem; border: 1px dashed var(--line-strong); border-radius: var(--radius-sm); color: var(--muted); font-size: 0.88rem; }
.empty-state p { margin: 0; }
.rows { list-style: none; margin: 0; padding: 0; }
.row { border-top: 1px solid var(--line); }
.row:first-child { border-top: 0; }
.row-head {
  display: grid; grid-template-columns: minmax(180px, 1.4fr) minmax(110px, auto) auto minmax(140px, 1fr) 16px;
  align-items: center; gap: 0.5rem 1.1rem; width: 100%; padding: 0.75rem 0.25rem; min-height: 0;
  background: transparent; border: 0; border-radius: 0; text-align: left; font-weight: 400;
}
.row-head:hover:not(:disabled) { background: color-mix(in srgb, var(--text) 3%, transparent); border-color: transparent; }
.row-head:active:not(:disabled) { transform: none; }
.who { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; min-width: 0; }
.pulse { width: 9px; height: 9px; border-radius: 50%; flex: none; }
.row.down .pulse { box-shadow: 0 0 0 0 color-mix(in srgb, var(--danger) 60%, transparent); animation: ping 1.6s infinite; }
@keyframes ping { 70% { box-shadow: 0 0 0 7px transparent; } }
.name { font-weight: 600; color: var(--text); }
.host { flex-basis: 100%; padding-left: 1.05rem; font: 0.76rem var(--mono); color: var(--muted); }
.tag { font-size: 0.68rem; padding: 0.05rem 0.4rem; border-radius: var(--radius-pill); border: 1px solid var(--line-strong); color: var(--text-2); }
.tag.crit { color: var(--high); border-color: color-mix(in srgb, var(--high) 35%, transparent); }
.state { display: flex; flex-direction: column; align-items: flex-start; gap: 0.25rem; }
.warn { display: inline-flex; gap: 0.3rem; align-items: center; font-size: 0.74rem; color: var(--warn); max-width: 22ch; }
.nums { display: flex; gap: 1rem; font-variant-numeric: tabular-nums; font-size: 0.84rem; color: var(--text); }
.nums span { display: flex; flex-direction: column; min-width: 3.6rem; }
.nums small { font-size: 0.68rem; color: var(--muted); }
.chev { color: var(--muted); transition: transform 0.2s var(--ease); transform: rotate(90deg); }
.open .chev { transform: rotate(-90deg); }
.row.open { padding-bottom: 0.6rem; }
.incidents { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.5rem; font-size: 0.85rem; }
.incidents li { display: flex; gap: 0.75rem; flex-wrap: wrap; align-items: baseline; }
.when { font: 0.76rem var(--mono); color: var(--muted); min-width: 11.5rem; }
.sub { color: var(--muted); font-size: 0.8rem; }
@media (max-width: 900px) {
  .row-head { grid-template-columns: minmax(0, 1fr) auto 16px; }
  .nums, .bar { grid-column: 1 / -1; }
  .chev { grid-row: 1; grid-column: 3; }
}
</style>
