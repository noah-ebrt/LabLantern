<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { api } from '../api.js'
import { useLive } from '../live.js'
import { parseTime } from '../time.js'
import { STEPS, percent as pct, stepNumber, stepState } from '../runSteps.js'

const emit = defineEmits(['done'])
const run = ref(null)
const now = ref(Date.now())
let tick = null

async function refresh() {
  const was = run.value
  run.value = (await api.get('/api/overview')).active_run
  if (was && !run.value) emit('done')
}

// Schritte und Fortschritt kommen aus runSteps.js (dieselbe Logik wie in der Pipeline)
const stepNo = computed(() => stepNumber(run.value))
const percent = computed(() => pct(run.value))

const since = (from) => {
  const s = Math.max(0, Math.round((now.value - from) / 1000))
  return s < 60 ? `${s} s` : `${Math.floor(s / 60)} min ${String(s % 60).padStart(2, '0')} s`
}
const elapsed = computed(() => (run.value ? since(parseTime(run.value.started_at).getTime()) : ''))
const stepAge = computed(() => (run.value?.progress?.at ? since(run.value.progress.at * 1000) : ''))

onMounted(() => {
  refresh()
  tick = setInterval(() => { now.value = Date.now() }, 1000)   // nur die Uhr, keine Serveranfragen
})
onBeforeUnmount(() => clearInterval(tick))
// Fortschritt per Live-Update: Reports der Agenten (systems) und Schritte des Workers (runs)
useLive(['runs', 'systems'], refresh, 150)
defineExpose({ refresh })
</script>

<template>
  <section v-if="run" class="card progress" role="status" aria-live="polite">
    <div class="head">
      <strong>Run #{{ run.run_id }}</strong>
      <span class="step-name">Step {{ stepNo }} of {{ STEPS.length }} · {{ STEPS[stepNo - 1]?.label }}</span>
      <span class="elapsed mono">{{ elapsed }}</span>
    </div>

    <p class="now">
      <template v-if="run.phase === 'collecting'">
        {{ run.systems_reported }} of {{ run.systems_total }} hosts have sent fresh data
        <span class="subtext">Connected agents answer within seconds; the scan starts after {{ Math.ceil((run.timeout_in || 0) / 60) }} min at the latest.</span>
      </template>
      <template v-else-if="run.progress?.step === 'host' || run.progress?.step === 'image'">
        <span class="strong">{{ run.progress.host }}</span>
        <span class="subtext">
          host {{ run.progress.host_index }} of {{ run.progress.hosts_total }}
          <template v-if="run.progress.step === 'image'"> · image {{ run.progress.image_index }} of {{ run.progress.images_total }}: <span class="mono">{{ run.progress.text.replace('Scanning image ', '') }}</span></template>
          <template v-else> · installed packages<template v-if="run.progress.images_total">, then {{ run.progress.images_total }} images</template></template>
          · this step {{ stepAge }}
        </span>
      </template>
      <template v-else-if="run.progress?.step === 'scan'">
        <span class="strong">SBOM {{ run.progress.done }} of {{ run.progress.total }}</span>
        <span class="subtext">
          <template v-if="run.progress.reused">{{ run.progress.reused }} unchanged since the last scan, result reused · </template>
          <span v-if="run.progress.done" class="mono">{{ run.progress.text.replace('Scanned ', '') }}</span>
          · this step {{ stepAge }}
        </span>
      </template>
      <template v-else>
        {{ run.progress?.text || 'Waiting for the worker to pick up the run…' }}
        <span v-if="stepAge" class="subtext">this step {{ stepAge }}</span>
      </template>
    </p>

    <div class="bar" role="progressbar" :aria-valuenow="percent" aria-valuemin="0" aria-valuemax="100">
      <div class="fill" :style="{ width: percent + '%' }" />
    </div>
    <ol class="steps" aria-hidden="true">
      <li v-for="st in STEPS" :key="st.key" :class="{ done: stepState(st.key, run) === 'done', current: stepState(st.key, run) === 'active' }">{{ st.label }}</li>
    </ol>
  </section>
</template>

<style scoped>
.progress { display: grid; gap: 0.5rem; color: var(--text-2); }
.head { display: flex; align-items: baseline; gap: 0.75rem; flex-wrap: wrap; }
.head strong { color: var(--text); }
.step-name { flex: 1; }
.elapsed { color: var(--text); }
.now { margin: 0; display: flex; flex-direction: column; gap: 0.125rem; }
.now .subtext { display: block; }
.bar { height: 6px; background: var(--ground); border-radius: var(--radius-pill); overflow: hidden; }
.fill { height: 100%; background: var(--invert); border-radius: var(--radius-pill); transition: width 0.6s var(--ease); }
.steps { list-style: none; margin: 0; padding: 0; display: flex; gap: 0.5rem 1rem; flex-wrap: wrap; font-size: 0.6875rem; color: var(--muted); }
.steps li { display: inline-flex; align-items: center; gap: 0.25rem; }
.steps li::before { content: ''; width: 7px; height: 7px; border-radius: 50%; border: 1px solid var(--line-strong); }
.steps li.done { color: var(--text-2); }
.steps li.done::before { background: var(--ok); border-color: var(--ok); }
.steps li.current { color: var(--text); font-weight: 600; }
.steps li.current::before { background: var(--text); border-color: var(--text); }
</style>
