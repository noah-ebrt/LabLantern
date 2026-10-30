<script setup>
import { computed, ref, watch } from 'vue'
import { api } from '../api.js'
import { KINDS, SERIES_COLORS, fmtDuration, fmtMs, fmtPct, stateOf } from '../health.js'
import { fmtClock, fmtDateTime, fmtDay, timeAgo } from '../time.js'
import LineChart from './LineChart.vue'
import StateBadge from './StateBadge.vue'
import UptimeBar from './UptimeBar.vue'

// Aufgeklappter Monitor: Verfügbarkeit und Latenz im gewählten Zeitraum, Prüfungen, Zustandswechsel
const props = defineProps({ monitor: { type: Object, required: true }, refresh: { type: Number, default: 0 } })
const RANGES = [['24h', '24 h'], ['7d', '7 days'], ['30d', '30 days'], ['90d', '90 days']]
const range = ref('24h')
const hist = ref(null)
const error = ref('')

async function load() {
  try {
    hist.value = await api.get(`/api/health/monitors/${props.monitor.id}/history?range=${range.value}`)
    error.value = ''
  } catch (e) {
    error.value = e.message
  }
}
watch([range, () => props.refresh], load, { immediate: true })

const label = (t) => (range.value === '24h' ? fmtClock(t) : fmtDay(t))
const points = computed(() => {
  if (!hist.value) return []
  const n = hist.value.segments.length
  return Array.from({ length: n }, (_, i) => {
    const t = hist.value.start + (i + 0.5) * hist.value.bucket_s
    return { label: label(t), title: fmtDateTime(t) }
  })
})
const latency = computed(() => (hist.value?.checks || [])
  .filter((c) => c.latency.some((v) => v != null))
  .map((c, i) => ({ key: String(c.id), label: c.label, color: SERIES_COLORS[i % SERIES_COLORS.length], values: c.latency })))
const downtime = computed(() => hist.value?.durations?.down ?? 0)
const outages = computed(() => (hist.value?.events || []).filter((e) => e.state === 'down').length)
</script>

<template>
  <div class="detail">
    <div class="detail-head">
      <div class="seg" role="group" aria-label="Time range">
        <button v-for="[k, l] in RANGES" :key="k" type="button" :class="['seg-btn', { active: range === k }]" @click="range = k">{{ l }}</button>
      </div>
      <p v-if="hist" class="facts-line">
        <span><b>{{ fmtPct(hist.uptime) }}</b> available</span>
        <span><b>{{ fmtDuration(downtime) }}</b> down</span>
        <span><b>{{ outages }}</b> {{ outages === 1 ? 'outage' : 'outages' }}</span>
      </p>
    </div>
    <p v-if="error" class="message error">{{ error }}</p>
    <template v-if="hist">
      <UptimeBar :segments="hist.segments" :start="label(hist.start)" :label="`Availability over ${range}`" />

      <section v-if="latency.length" class="block">
        <h4>Response time</h4>
        <LineChart :points="points" :series="latency" unit=" ms" :digits="1" :legend="latency.length > 1" />
      </section>

      <section class="block">
        <h4>Checks</h4>
        <div class="table-wrap">
          <table class="checks">
            <thead><tr><th>Check</th><th>State</th><th>Latency</th><th>Last result</th><th>Note</th></tr></thead>
            <tbody>
              <tr v-for="c in monitor.checks" :key="c.id">
                <td><span class="kind">{{ c.label }}</span><span class="sub">{{ KINDS[c.kind]?.label }} · every {{ c.interval_s }} s</span></td>
                <td><StateBadge :state="c.state" :stale="c.stale" /></td>
                <td class="num">{{ fmtMs(c.latency_ms) }}</td>
                <td class="sub">{{ c.last_checked ? timeAgo(c.last_checked) : 'not yet' }}</td>
                <td class="note">{{ c.error || '–' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="block">
        <h4>State changes</h4>
        <ul v-if="hist.events.length" class="events">
          <li v-for="(e, i) in hist.events" :key="i">
            <span class="when">{{ fmtDateTime(e.ts) }}</span>
            <span class="change"><i :style="{ background: stateOf(e.prev).color }" />{{ stateOf(e.prev).label }} → <i :style="{ background: stateOf(e.state).color }" /><b>{{ stateOf(e.state).label }}</b></span>
            <span v-if="e.detail" class="sub">{{ e.detail }}</span>
          </li>
        </ul>
        <p v-else class="sub">No state changes in this period.</p>
      </section>
    </template>
  </div>
</template>

<style scoped>
.detail { display: flex; flex-direction: column; gap: 1.1rem; padding: 1rem 0 0.4rem; }
.detail-head { display: flex; justify-content: space-between; align-items: center; gap: 0.75rem; flex-wrap: wrap; }
.facts-line { display: flex; gap: 1.1rem; margin: 0; font-size: 0.82rem; color: var(--muted); flex-wrap: wrap; }
.facts-line b { color: var(--text); font-weight: 600; font-variant-numeric: tabular-nums; }
.block { display: flex; flex-direction: column; gap: 0.6rem; }
h4 { margin: 0; font-size: 0.72rem; font-weight: 600; letter-spacing: 0.09em; text-transform: uppercase; color: var(--text-2); }
.checks { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
.checks th { text-align: left; font-weight: 500; font-size: 0.75rem; color: var(--muted); padding: 0.35rem 0.6rem 0.35rem 0; }
.checks td { padding: 0.5rem 0.6rem 0.5rem 0; border-top: 1px solid var(--line); vertical-align: top; }
.kind { display: block; color: var(--text); }
.sub { display: block; font-size: 0.76rem; color: var(--muted); }
.num { font-variant-numeric: tabular-nums; white-space: nowrap; }
.note { color: var(--text-2); max-width: 36ch; overflow-wrap: anywhere; }
.events { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.45rem; max-height: 260px; overflow-y: auto; }
.events li { display: grid; grid-template-columns: 11.5rem 1fr; gap: 0.1rem 0.75rem; font-size: 0.83rem; }
.events .sub { grid-column: 2; }
.when { font: 0.76rem var(--mono); color: var(--muted); padding-top: 0.1rem; }
.change { display: inline-flex; align-items: center; gap: 0.35rem; color: var(--text-2); }
.change i { width: 7px; height: 7px; border-radius: 50%; display: inline-block; }
.change b { color: var(--text); font-weight: 500; }
@media (max-width: 640px) { .events li { grid-template-columns: 1fr; } .events .sub { grid-column: 1; } }
</style>
