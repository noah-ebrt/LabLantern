<script setup>
import { computed, onMounted, ref } from 'vue'
import { api } from '../api.js'
import { useLive } from '../live.js'
import { fmtClock, fmtDay } from '../time.js'
import { RUN_TRIGGER, runLabel } from '../labels.js'
import LineChart from '../components/LineChart.vue'

// Verlauf (PLAN Abschnitt 7): Funde je Stufe, Zeit bis zur Behebung, Laufdauer, Abdeckung
const DAYS = [[30, '30 days'], [90, '90 days'], [365, '1 year']]
const days = ref(90)
const data = ref(null)
const loading = ref(true)
const error = ref('')

async function load() {
  try {
    data.value = await api.get(`/api/history?days=${days.value}`)
    error.value = ''
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

const runs = computed(() => data.value?.runs || [])
const points = computed(() => runs.value.map((r) => ({
  label: `#${r.id} · ${fmtDay(r.started_at)}`,   // mehrere Läufe am Tag: die Nummer unterscheidet sie
  title: `Run #${r.id} · ${fmtDay(r.started_at)}, ${fmtClock(r.started_at)}`,
  extra: `${RUN_TRIGGER[r.trigger] || r.trigger} · ${String(runLabel(r.status) ?? '').toLowerCase()}`,
})))
const sev = (key) => runs.value.map((r) => r.counts?.[key] ?? null)
const findings = computed(() => [
  { key: 'k', label: 'Critical', color: 'var(--crit)', values: sev('kritisch') },
  { key: 'h', label: 'High', color: 'var(--high)', values: sev('hoch') },
])
const medium = computed(() => [{ key: 'm', label: 'Medium', color: 'var(--med)', values: sev('mittel') }])
const coverage = computed(() => [{ key: 'c', label: 'Coverage', color: 'var(--ok)', values: runs.value.map((r) => r.coverage_percent) }])
// Abdeckung wird erst seit einem bestimmten Lauf je Lauf gespeichert: das sagen statt eine leere Fläche zu zeigen
const coverageSince = computed(() => {
  const first = runs.value.find((r) => r.coverage_percent != null)
  return first && first !== runs.value[0] ? first.id : null
})
const duration = computed(() => [{ key: 'd', label: 'Duration', color: 'var(--info)', values: runs.value.map((r) => r.duration_min) }])

const ttf = computed(() => data.value?.time_to_fix || [])
// Unter zwei Tagen in Stunden, sonst in Tagen: „0 d“ sagt nichts
const ttfHours = computed(() => Math.max(0, ...ttf.value.map((w) => w.median_days)) < 2)
const ttfPoints = computed(() => ttf.value.map((w) => ({
  label: fmtDay(w.week), title: `Week of ${fmtDay(w.week)}`, extra: `${w.fixed} critical/high fixed`,
})))
const ttfSeries = computed(() => [{
  key: 't', label: 'Median time to fix', color: 'var(--high)',
  values: ttf.value.map((w) => (ttfHours.value ? Math.round(w.median_days * 240) / 10 : w.median_days)),
}])

const latest = computed(() => runs.value[runs.value.length - 1] || null)

onMounted(load)
useLive(['runs'], load, 3000)
</script>

<template>
  <div class="header-row">
    <div>
      <h1>History</h1>
      <p class="subtitle">How findings, coverage and run times develop over the finished runs</p>
    </div>
    <div>
      <select v-model.number="days" aria-label="Period" @change="load">
        <option v-for="[d, l] in DAYS" :key="d" :value="d">{{ l }}</option>
      </select>
    </div>
  </div>
  <p v-if="error" class="message error" role="alert">{{ error }}</p>

  <div v-if="loading" class="card empty">Loading history…</div>
  <div v-else-if="data && runs.length < 2" class="card empty">The history fills in after two finished runs in this period.</div>
  <div v-else-if="data" class="grid">
    <section class="card">
      <div class="card-header">
        <h2 class="panel-title">Critical &amp; high open</h2>
        <span v-if="latest" class="now"><b class="crit">{{ latest.counts?.kritisch ?? 0 }}</b> · <b class="high">{{ latest.counts?.hoch ?? 0 }}</b></span>
      </div>
      <LineChart :points="points" :series="findings" legend />
    </section>
    <section class="card">
      <div class="card-header">
        <h2 class="panel-title">Medium open</h2>
        <span v-if="latest" class="now"><b>{{ (latest.counts?.mittel ?? 0).toLocaleString('en-GB') }}</b></span>
      </div>
      <LineChart :points="points" :series="medium" />
    </section>
    <section class="card">
      <div class="card-header">
        <h2 class="panel-title">Coverage</h2>
        <span class="subtext">{{ coverageSince ? `checked without error · recorded since run #${coverageSince}` : 'checked without error' }}</span>
      </div>
      <LineChart :points="points" :series="coverage" unit="%" :max="100" :digits="1" />
    </section>
    <section class="card">
      <div class="card-header">
        <h2 class="panel-title">Run duration</h2>
        <span class="subtext">from start to report</span>
      </div>
      <LineChart :points="points" :series="duration" unit=" min" />
    </section>
    <section class="card wide">
      <div class="card-header">
        <h2 class="panel-title">Time to fix</h2>
        <span class="subtext">median age of critical/high findings when they were resolved, per week</span>
      </div>
      <LineChart v-if="ttf.length" :points="ttfPoints" :series="ttfSeries" :unit="ttfHours ? ' h' : ' d'" :digits="1" />
      <p v-else class="empty">No critical or high finding was resolved in this period yet.</p>
    </section>
  </div>
</template>

<style scoped>
.grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; }
.grid .card { margin: 0; }
.wide { grid-column: 1 / -1; }
.header-row select { width: auto; }
.grid .card-header { flex-wrap: wrap; row-gap: 0.25rem; }
.grid .panel-title { white-space: nowrap; }
.now { font: 0.875rem var(--mono); color: var(--muted); font-variant-numeric: tabular-nums; }
.now b { font-weight: 600; color: var(--text); }
.now b.crit { color: var(--crit); }
.now b.high { color: var(--high); }
@media (max-width: 900px) { .grid { grid-template-columns: minmax(0, 1fr); } }
</style>
