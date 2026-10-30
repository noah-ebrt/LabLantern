<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import { api } from '../api.js'
import { CHECK_NAMES, POSTURE, hostState, runLabel } from '../labels.js'
import Icon from './Icon.vue'
import HostDetailModal from './HostDetailModal.vue'
import RunDetailModal from './RunDetailModal.vue'
import { ago, fmtClock, fmtDateTime, fmtWeekdayTime, hoursSince, parseTime } from '../time.js'
import { STEPS, currentStep, hostInScan, stepNumber, stepSummary } from '../runSteps.js'
import Modal from './Modal.vue'

// Gesamtablauf als Knoten-Canvas (wie n8n): Agenten → Zeitplan → Lauf → Canary → Ergebnis → Bericht.
// Liest nur, was /api/overview und /api/systems liefern; Knoten lassen sich verschieben.
const props = defineProps({
  data: { type: Object, required: true },
  systems: { type: Array, default: () => [] },
  triggering: { type: Boolean, default: false },
})
const emit = defineEmits(['trigger', 'changed'])

const NODE_W = 200
const NODE_H = 58
const ROW = 86      // Abstand der Agenten untereinander (Knoten + Notiz)
const PAD_X = 24
const PAD_TOP = 34

const claude = ref(null)
const hostId = ref(null)
const runId = ref(null)
const info = ref(null)

// ---------- Breite messen, Spalten verteilen ----------
const wrap = ref(null)
const width = ref(1200)
let observer = null
// Der Canvas existiert nur in der breiten Ansicht: die Messung folgt ihm, wenn er (wieder) erscheint
watch(wrap, (el) => {
  observer?.disconnect()
  if (!el) return
  width.value = el.clientWidth || width.value
  if (typeof ResizeObserver !== 'undefined') {
    observer = new ResizeObserver(([e]) => { width.value = e.contentRect.width })
    observer.observe(el)
  }
})
onMounted(async () => {
  try {
    claude.value = await api.get('/api/integrations/claude')
  } catch {
    claude.value = null
  }
})
onBeforeUnmount(() => observer?.disconnect())

// Schmale Bildschirme: statt des Canvas (braucht ~1300 px, nur seitlich scrollbar) eine senkrechte Schrittliste
const COMPACT = '(max-width: 720px)'
const media = typeof window !== 'undefined' && window.matchMedia ? window.matchMedia(COMPACT) : null
const compact = ref(media?.matches ?? false)
const onMedia = (e) => { compact.value = e.matches }
media?.addEventListener?.('change', onMedia)
onBeforeUnmount(() => media?.removeEventListener?.('change', onMedia))

const colGap = computed(() => Math.max(230, (width.value - 2 * PAD_X - NODE_W) / 5))
const colX = (c) => PAD_X + c * colGap.value

// ---------- verschobene Knoten (nur in diesem Browser) ----------
const STORE = 'vw.flow.offsets'
const offsets = reactive((() => {
  try {
    return JSON.parse(localStorage.getItem(STORE) || '{}')
  } catch {
    return {}
  }
})())
const saveOffsets = () => {
  try {
    localStorage.setItem(STORE, JSON.stringify(offsets))
  } catch {
    /* privates Fenster: Anordnung gilt nur bis zum Neuladen */
  }
}
function resetLayout() {
  for (const k of Object.keys(offsets)) delete offsets[k]
  saveOffsets()
}
const moved = computed(() => Object.keys(offsets).length > 0)

let drag = null
let dragged = false
function onDown(e, node) {
  if (e.button !== 0 || e.target.closest('.node-action')) return
  drag = { id: node.id, x: e.clientX, y: e.clientY, start: { ...(offsets[node.id] || { dx: 0, dy: 0 }) } }
  dragged = false
  e.currentTarget.setPointerCapture?.(e.pointerId)
}
function onMove(e) {
  if (!drag) return
  const dx = e.clientX - drag.x
  const dy = e.clientY - drag.y
  if (!dragged && Math.hypot(dx, dy) < 4) return
  dragged = true
  offsets[drag.id] = { dx: drag.start.dx + dx, dy: drag.start.dy + dy }
}
function onUp() {
  if (drag && dragged) saveOffsets()
  drag = null
}

// ---------- Zustand ableiten ----------
const run = computed(() => props.data.active_run)
const step = computed(() => currentStep(run.value))   // collecting | database | canary | scan | saving | null
const FLOW = { done: 'ok', active: 'active', pending: 'idle' }
const last = computed(() => props.data.last_run)
const nextRun = computed(() => (props.data.next_run ? fmtWeekdayTime(props.data.next_run) : null))
const short = computed(() => props.data.short_run || null)
// Nächster Lauf, ob täglich oder kurz: was zuerst kommt, steht über dem Zeitplan
const nextAny = computed(() => {
  const daily = props.data.next_run ? { at: props.data.next_run, kind: 'full' } : null
  const quick = short.value?.next_run ? { at: short.value.next_run, kind: 'short' } : null
  return [daily, quick].filter(Boolean).sort((a, b) => parseTime(a.at) - parseTime(b.at))[0] || null
})
const ew = computed(() => props.data.early_warning || null)

const agents = computed(() => props.systems.filter((s) => s.status === 'active').map((s) => {
  const cov = props.data.coverage.find((c) => c.system_id === s.id)
  const seen = parseTime(s.last_seen)
  const scanned = parseTime(cov?.last_scan?.at)
  const host = hostState(s)
  let flow, sub
  if (host.tone === 'bad') {
    flow = 'bad'; sub = host.text
  } else if (step.value === 'collecting') {
    // bereit = frischer Report samt Image-SBOMs; die Liste liefert der Server, sonst Näherung über last_seen
    const ready = run.value.ready_ids ? run.value.ready_ids.includes(s.id) : seen && seen >= parseTime(run.value.started_at)
    flow = ready ? 'ok' : 'active'; sub = ready ? 'ready for this run' : 'asked for fresh data…'
  } else if (hostInScan(s.name, run.value)) {
    const h = hostInScan(s.name, run.value)
    flow = FLOW[h.state]; sub = h.text
  } else if (run.value) {
    flow = 'ok'; sub = 'data handed to the scan'
  } else if (seen && (!scanned || seen > scanned)) {
    flow = 'wait'; sub = 'new data, waits for next run'
  } else {
    flow = 'idle'; sub = scanned ? `scanned in run #${cov.last_scan.run_id}` : 'not scanned yet'
  }
  return {
    id: `agent-${s.id}`, kind: 'host', sysId: s.id, icon: 'systems', title: s.name, sub,
    note: `last report ${ago(s.age_hours)}`,
    state: host.tone,
    flow,
  }
}))

const waiting = computed(() => agents.value.filter((a) => a.flow === 'wait').length)

const stages = computed(() => {
  const d = props.data
  const r = run.value
  const l = last.value
  const notify = l?.notify_status || ''
  const db = l?.db_status || {}
  const workerAge = d.worker.age_seconds
  return {
    schedule: {
      id: 'schedule', kind: 'info', icon: 'clock', title: 'Schedule', col: 1,
      note: nextAny.value ? `next ${nextAny.value.kind === 'short' ? 'short run' : 'full run'} ${fmtWeekdayTime(nextAny.value.at)}` : 'automatic runs off',
      sub: r?.phase === 'collecting' ? `collecting ${r.systems_reported ?? 0}/${r.systems_total ?? 0}`
        : r ? 'run in progress' : waiting.value ? `${waiting.value} host${waiting.value > 1 ? 's' : ''} waiting` : 'all data scanned',
      state: r?.phase === 'collecting' ? 'active' : waiting.value ? 'wait' : 'ok',
      action: !r,
    },
    run: {
      id: 'run', kind: 'run', icon: 'runs', col: 2,
      title: r ? `Run #${r.run_id}` : l ? `Run #${l.id}` : 'Scan run',
      runId: r?.run_id ?? l?.id ?? null,
      note: r ? `started ${fmtClock(r.started_at)} · step ${stepNumber(r)}/${STEPS.length}` : l ? `finished ${fmtClock(l.finished_at || l.started_at)} · ${ago(hoursSince(l.finished_at || l.started_at))}` : 'never ran',
      sub: r ? stepSummary(r) : l ? `${runLabel(l.status)} · ${l.trigger}` : 'start one with Scan now',
      state: r ? 'active' : workerAge === null || workerAge > 300 ? 'bad' : !l ? 'idle' : l.status === 'success' ? 'ok' : l.status === 'partial' ? 'warn' : 'bad',
    },
    canary: {
      id: 'canary', kind: 'info', icon: 'shield', title: 'Canary & DB', col: 3,
      note: l ? (d.canary_status === 'ok' ? 'scanner verified' : 'scanner not verified') : '–',
      sub: !l ? 'no run yet' : `${d.canary_status === 'ok' ? 'passed' : 'failed'} · DB ${db.ok ? (db.age_hours != null ? ago(db.age_hours).replace(' ago', ' old') : 'ok') : 'problem'}`,
      ...(['database', 'canary'].includes(step.value) ? {
        state: 'active', sub: step.value === 'database' ? 'updating vulnerability DB…' : 'canary test running…',
      } : ['scan', 'saving'].includes(step.value) ? {
        state: 'ok', sub: 'checked · result with the report',
      } : {
        state: !l ? 'idle' : d.canary_status === 'ok' && db.ok !== false ? 'ok' : 'bad',
      }),
    },
    ai: (() => {
      const e = ew.value
      const c = e?.counts || {}
      const passed = e?.at ? ago(hoursSince(new Date(e.at * 1000).toISOString())) : null
      return {
        id: 'ai', kind: 'info', icon: 'sparkles', title: 'AI early warning', col: 3,
        note: passed ? `last pass ${passed}` : 'not run yet',
        sub: !e?.ai_configured ? 'no Claude key: review by hand'
          : c.betroffen ? `${c.betroffen} affect${c.betroffen === 1 ? 's' : ''} you` + (c.unklar ? ` · ${c.unklar} to review` : '')
            : c.unklar ? `${c.unklar} to review · none affecting you` : 'nothing affects you',
        state: !e?.ai_configured || e.feed_errors ? 'warn' : c.betroffen ? 'bad' : c.unklar ? 'wait' : e.at ? 'ok' : 'idle',
      }
    })(),
    result: {
      id: 'result', kind: 'info', icon: 'findings', title: 'Result', col: 4,
      note: `coverage ${d.coverage_percent}%`,
      sub: step.value === 'saving' ? 'rating findings…' : r ? `previous: ${d.findings.kritisch} critical · ${d.findings.hoch} high`
        : `${d.findings.kritisch} critical · ${d.findings.hoch} high`,
      state: step.value === 'saving' ? 'active' : r ? 'idle' : { gruen: 'ok', gelb: 'warn', rot: 'bad' }[d.ampel] ?? 'idle',
    },
    notify: {
      id: 'notify', kind: 'info', icon: 'bell', title: 'Report', col: 5,
      note: l ? fmtClock(l.finished_at || l.started_at) : '–',
      sub: r ? 'sent after the run' : !notify ? 'nothing sent' : notify === 'sent' ? 'sent' : 'sending failed',
      state: r ? 'idle' : !notify ? 'idle' : notify === 'sent' ? 'ok' : 'bad',
    },
  }
})

// ---------- Anordnung ----------
const layout = computed(() => {
  const n = Math.max(agents.value.length, 1)
  const mainY = PAD_TOP + ((n - 1) * ROW) / 2
  const aiY = mainY + Math.max(ROW, 96)
  const at = (node, x, y) => {
    const o = offsets[node.id] || { dx: 0, dy: 0 }
    return { ...node, x: x + o.dx, y: y + o.dy }
  }
  const nodes = agents.value.map((a, i) => at(a, colX(0), PAD_TOP + i * ROW))
  const s = stages.value
  for (const st of [s.schedule, s.run, s.canary, s.result, s.notify]) nodes.push(at(st, colX(st.col), mainY))
  nodes.push(at(s.ai, colX(s.ai.col), aiY))
  const byId = Object.fromEntries(nodes.map((x) => [x.id, x]))
  const height = Math.max(...nodes.map((x) => x.y + NODE_H)) + 24
  return { nodes, byId, height }
})

const edges = computed(() => {
  const r = run.value
  const st = stages.value
  const list = agents.value.map((a) => ({ id: `e-${a.id}`, from: a.id, to: 'schedule', state: a.flow }))
  list.push(
    // Kanten folgen dem aktuellen Schritt: bis hierher fertig, hier aktiv, dahinter noch nicht
    { id: 'e-s-r', from: 'schedule', to: 'run', state: step.value === 'collecting' ? 'active' : r ? 'ok' : 'idle' },
    { id: 'e-r-c', from: 'run', to: 'canary', state: ['database', 'canary'].includes(step.value) ? 'active' : r ? (step.value === 'collecting' ? 'idle' : 'ok') : st.run.state === 'idle' ? 'idle' : 'ok' },
    { id: 'e-c-res', from: 'canary', to: 'result', state: ['scan', 'saving'].includes(step.value) ? 'active' : r ? 'idle' : st.canary.state === 'ok' ? 'ok' : st.canary.state },
    { id: 'e-res-n', from: 'result', to: 'notify', state: r ? 'idle' : st.notify.state === 'ok' ? 'ok' : st.notify.state },
    { id: 'e-s-ai', from: 'schedule', to: 'ai', state: st.ai.state === 'idle' ? 'idle' : 'ok' },
    { id: 'e-ai-res', from: 'ai', to: 'result', state: { bad: 'bad', warn: 'wait' }[st.ai.state] || (st.ai.state === 'idle' ? 'idle' : 'ok') },
  )
  const { byId } = layout.value
  return list.filter((e) => byId[e.from] && byId[e.to]).map((e) => {
    const a = byId[e.from]
    const b = byId[e.to]
    const x1 = a.x + NODE_W
    const y1 = a.y + NODE_H / 2
    const x2 = b.x
    const y2 = b.y + NODE_H / 2
    const c = Math.max(40, Math.abs(x2 - x1) / 2)
    return { ...e, d: `M ${x1} ${y1} C ${x1 + c} ${y1}, ${x2 - c} ${y2}, ${x2} ${y2}` }
  })
})

// ---------- Klicks ----------
function open(node) {
  if (dragged) {
    dragged = false
    return
  }
  if (node.kind === 'host') hostId.value = node.sysId
  else if (node.kind === 'run' && node.runId) runId.value = node.runId
  else info.value = node.id === 'run' ? 'schedule' : node.id
}

// Reihenfolge der Schrittliste: der Weg eines Laufs; die Frühwarnung läuft daneben und fließt ins Ergebnis
const steps = computed(() => {
  const s = stages.value
  return [s.schedule, s.run, s.canary, { ...s.ai, side: true }, s.result, s.notify]
})

const failing = computed(() => props.data.coverage.flatMap((s) => Object.entries(s.checks)
  .filter(([, c]) => c.status === 'fehler').map(([k, c]) => ({ host: s.system_name, check: k, detail: c.detail }))))
</script>

<template>
  <section class="card flow">
    <div class="card-header">
      <h2 class="panel-title">Pipeline · agents to report</h2>
      <span class="head-right">
        <span v-if="!compact" class="hint">click a node for details, drag to arrange</span>
        <button v-if="moved && !compact" type="button" class="btn-sm secondary" @click="resetLayout"><Icon name="refresh" :size="13" /> Reset layout</button>
      </span>
    </div>

    <div v-if="compact" class="vflow">
      <ul class="vhosts" aria-label="Agents">
        <li v-for="a in agents" :key="a.id">
          <button type="button" :class="['vhost', a.state]" :aria-label="`${a.title}: ${a.sub}, ${a.note}`" @click="open(a)">
            <i class="vdot" />
            <span class="vhost-text"><span class="title">{{ a.title }}</span><span class="sub">{{ a.sub }}</span></span>
          </button>
        </li>
      </ul>
      <ol class="vsteps">
        <li v-for="n in steps" :key="n.id" :class="['vstep', n.state, { side: n.side }]">
          <i class="vdot" aria-hidden="true" />
          <button type="button" class="vstep-body" :aria-label="`${n.title}: ${n.sub}`" @click="open(n)">
            <span class="glyph"><Icon :name="n.icon" :size="15" /></span>
            <span class="text">
              <span class="title">{{ n.title }}</span>
              <span class="sub">{{ n.sub }}</span>
              <span class="vnote">{{ n.side ? `alongside the run · ${n.note}` : n.note }}</span>
            </span>
            <Icon name="chevron" :size="14" class="vchev" />
          </button>
          <button v-if="n.action" type="button" class="btn-sm vaction" :disabled="triggering" @click="emit('trigger')">
            <Icon name="play" :size="12" />{{ triggering ? 'Queuing…' : 'Scan latest data' }}
          </button>
        </li>
      </ol>
    </div>

    <div v-else ref="wrap" class="canvas-wrap">
      <div class="canvas" :style="{ height: layout.height + 'px', minWidth: colX(5) + NODE_W + PAD_X + 'px' }"
           @pointermove="onMove" @pointerup="onUp" @pointercancel="onUp">
        <svg class="edges" aria-hidden="true">
          <path v-for="e in edges" :key="e.id" :d="e.d" :class="['edge', e.state]" />
        </svg>

        <div v-for="n in layout.nodes" :key="n.id" class="node-wrap" :style="{ transform: `translate(${n.x}px, ${n.y}px)`, width: NODE_W + 'px' }">
          <span class="note">{{ n.note }}</span>
          <div role="button" tabindex="0" :class="['node', n.state]"
               :aria-label="`${n.title}: ${n.sub}`"
               @pointerdown="onDown($event, n)" @click="open(n)"
               @keydown.enter.prevent="open(n)" @keydown.space.prevent="open(n)">
            <i class="port in" /><i class="port out" />
            <span class="glyph"><Icon :name="n.icon" :size="16" /></span>
            <span class="text">
              <span class="title">{{ n.title }}</span>
              <span class="sub">{{ n.sub }}</span>
            </span>
            <i class="dot" />
            <button v-if="n.action" type="button" class="node-action" :disabled="triggering"
                    title="Scan and rate the data the agents last reported on their own, without asking them first (like the short run)"
                    @click.stop="emit('trigger')"><Icon name="play" :size="11" />{{ triggering ? '…' : 'Scan latest data' }}</button>
          </div>
        </div>
      </div>
    </div>

    <p class="legend-line">
      <template v-if="!compact">   <!-- Linien gibt es nur im Canvas -->
        <span><i class="lg ok" />done</span>
        <span><i class="lg wait" />new data waiting</span>
        <span><i class="lg active" />in progress</span>
        <span><i class="lg bad" />problem</span>
        <span class="lg-sep" aria-hidden="true" />
      </template>
      <span><i class="ld ok" />ok</span>
      <span><i class="ld active" />running</span>
      <span><i class="ld warn" />waiting or needs attention</span>
      <span><i class="ld bad" />error or critical findings</span>
      <span><i class="ld" />not run yet</span>
    </p>
  </section>

  <HostDetailModal v-if="hostId" :system-id="hostId" @close="hostId = null" @changed="emit('changed')" />
  <RunDetailModal v-if="runId" :run-id="runId" @close="runId = null">
    <template #actions>
      <RouterLink class="btn-link" :to="{ path: '/laeufe', query: { run: runId } }">All runs</RouterLink>
    </template>
  </RunDetailModal>

  <Modal v-if="info" :label="stages[info].title" @close="info = null">
    <h2>{{ stages[info].title }}</h2>

    <template v-if="info === 'schedule'">
      <p class="explain">Agents send a full report about once an hour and check in every 5 minutes. New data waits here
        until the next run. The daily run and "Scan now" at the top are complete runs: they ask every agent for fresh
        data first (waiting at most 10 minutes), then scan, check image versions and run the AI early warning.
        The short run and "Scan latest data" skip the asking and scan what the agents last reported on their own;
        they only notify when something new is critical or high, or a check fails.</p>
      <dl>
        <dt>Next full run (daily)</dt><dd>{{ data.next_run ? fmtDateTime(data.next_run) : 'disabled' }}</dd>
        <dt>Next short run</dt><dd>{{ short?.enabled ? `${short.next_run ? fmtDateTime(short.next_run) : '–'} · every ${short.hours} h` : 'disabled' }}</dd>
        <dt>Hosts with new data</dt><dd>{{ waiting }} of {{ agents.length }}</dd>
        <template v-if="run?.phase === 'collecting'">
          <dt>Reported for run #{{ run.run_id }}</dt><dd>{{ run.systems_reported }} of {{ run.systems_total }}</dd>
          <dt>Scan starts at the latest in</dt><dd>{{ Math.ceil((run.timeout_in || 0) / 60) }} min</dd>
        </template>
      </dl>
    </template>

    <template v-else-if="info === 'ai'">
      <p class="explain">Security feeds are read every 2 hours and at the start of every full run. Only entries from the
        last 30 days that name a product from your inventory go to Claude, which extracts affected versions; the
        comparison with your installed versions is plain code. An entry is affected, not affected or needs review (the advisory gives no comparable versions), never
        silently dropped. Affected entries become findings (high when exploited, otherwise info); the AI can never
        remove or downgrade a finding.</p>
      <dl>
        <dt>Last pass</dt><dd>{{ ew?.at ? fmtDateTime(new Date(ew.at * 1000).toISOString()) : 'never' }}</dd>
        <dt>Last 30 days</dt><dd>{{ ew?.counts?.betroffen || 0 }} affected · {{ ew?.counts?.unklar || 0 }} to review · {{ ew?.counts?.nicht_betroffen || 0 }} not affected</dd>
        <dt>Claude API key</dt><dd>{{ claude === null ? 'unknown' : claude.configured ? `stored (${claude.model})` : 'not set' }}</dd>
        <dt>Feeds</dt><dd>{{ ew?.feed_errors ? `${ew.feed_errors} could not be read` : 'all readable' }}</dd>
      </dl>
      <RouterLink to="/fruehwarnungen" class="btn-link" @click="info = null">Open early warnings</RouterLink>
    </template>

    <template v-else-if="info === 'canary'">
      <p class="explain">Every run also scans a package with a known vulnerability, and the vulnerability database must be
        current. If either fails, the run is not trusted and the posture turns red.</p>
      <dl>
        <dt>Canary</dt><dd>{{ data.canary_status === 'ok' ? 'passed' : 'failed' }}</dd>
        <dt>Vulnerability DB</dt>
        <dd>{{ last?.db_status?.ok ? 'current' : 'problem' }}<template v-if="last?.db_status?.age_hours != null">, built {{ ago(last.db_status.age_hours) }}</template><template v-if="last?.db_status?.reason"> · {{ last.db_status.reason }}</template></dd>
        <dt>Worker</dt><dd>{{ data.worker.age_seconds === null ? 'never seen' : data.worker.age_seconds < 120 ? 'active' : `last seen ${Math.round(data.worker.age_seconds / 60)} min ago` }}</dd>
      </dl>
    </template>

    <template v-else-if="info === 'result'">
      <dl>
        <dt>Posture</dt><dd>{{ POSTURE[data.ampel]?.text ?? '–' }}</dd>
        <dt>Open findings</dt><dd>{{ data.findings.kritisch }} critical · {{ data.findings.hoch }} high · {{ data.findings.mittel }} medium · {{ data.findings.info }} info</dd>
        <dt>Coverage</dt><dd>{{ data.coverage_percent }}% checked without error</dd>
      </dl>
      <template v-if="failing.length">
        <h3>Could not be checked ({{ failing.length }})</h3>
        <ul class="fails">
          <li v-for="(f, i) in failing" :key="i"><strong>{{ f.host }}</strong> · {{ CHECK_NAMES[f.check] || f.check }}<span class="subtext">{{ f.detail }}</span></li>
        </ul>
      </template>
    </template>

    <template v-else-if="info === 'notify'">
      <p class="explain">After each run the report goes to every configured channel (mail, push).</p>
      <dl><dt>Last run</dt><dd>{{ last?.notify_status || 'nothing sent' }}</dd></dl>
    </template>

    <template #actions>
      <button v-if="info === 'schedule' && !run" class="primary" :disabled="triggering" @click="emit('trigger'); info = null"><Icon name="play" :size="13" /> Scan latest data</button>
      <RouterLink v-if="info === 'result'" class="btn-link" to="/funde">Show findings</RouterLink>
      <RouterLink v-if="['schedule', 'ai', 'notify'].includes(info)" class="btn-link" to="/einstellungen">Settings</RouterLink>
    </template>
  </Modal>
</template>

<style scoped>
.head-right { display: inline-flex; align-items: center; gap: 0.75rem; }
.canvas-wrap {
  overflow-x: auto; border: 1px solid var(--line); border-radius: var(--radius-sm);
  background-color: var(--ground);
  background-image: radial-gradient(color-mix(in srgb, var(--line-strong) 70%, transparent) 1px, transparent 1px);
  background-size: 18px 18px;
}
.canvas { position: relative; touch-action: none; user-select: none; }
.edges { position: absolute; inset: 0; width: 100%; height: 100%; overflow: visible; pointer-events: none; }

.edge { fill: none; stroke: var(--line-strong); stroke-width: 1.5; }
.edge.ok { stroke: color-mix(in srgb, var(--ok) 65%, var(--line-strong)); }
.edge.wait { stroke: var(--warn); stroke-dasharray: 5 4; }
.edge.bad { stroke: color-mix(in srgb, var(--danger) 70%, var(--line-strong)); }
.edge.warn { stroke: var(--warn); }
.edge.active { stroke: var(--ok); stroke-width: 2; stroke-dasharray: 6 6; animation: flow 0.9s linear infinite; }
@keyframes flow { to { stroke-dashoffset: -12; } }

.node-wrap { position: absolute; left: 0; top: 0; }
.note {
  position: absolute; bottom: calc(100% + 4px); left: 2px; right: 0;
  font: 0.68rem var(--mono); color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.node {
  position: relative; display: flex; align-items: center; gap: 0.6rem; height: 58px; padding: 0 0.7rem 0 0.55rem;
  background: var(--surface-2); border: 1px solid var(--line-strong); border-radius: 10px;
  cursor: grab; color: var(--text); transition: border-color 0.15s, background-color 0.15s;
}
.node:hover { background: var(--surface-3); }
.node:active { cursor: grabbing; }
.node:focus-visible { outline: 2px solid var(--text-2); outline-offset: 2px; }
.node.active { border-color: color-mix(in srgb, var(--ok) 55%, var(--line-strong)); }
.node.wait { border-color: color-mix(in srgb, var(--warn) 45%, var(--line-strong)); }
.node.bad { border-color: color-mix(in srgb, var(--danger) 45%, var(--line-strong)); }

.glyph {
  flex: none; display: grid; place-items: center; width: 34px; height: 34px; border-radius: 8px;
  background: var(--surface); border: 1px solid var(--line); color: var(--text-2);
}
.text { min-width: 0; flex: 1; display: flex; flex-direction: column; gap: 0.1rem; }
.title { font-size: 0.86rem; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.sub { font-size: 0.72rem; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

.dot { position: absolute; top: 7px; right: 7px; width: 7px; height: 7px; border-radius: 50%; background: var(--muted); }
.node.ok .dot { background: var(--ok); }
.node.warn .dot, .node.wait .dot { background: var(--warn); }
.node.bad .dot { background: var(--danger); }
.node.active .dot { background: var(--ok); animation: pulse 1.2s ease-in-out infinite; }
@keyframes pulse { 50% { box-shadow: 0 0 0 4px color-mix(in srgb, var(--ok) 25%, transparent); } }

.port { position: absolute; top: 50%; width: 9px; height: 9px; margin-top: -5px; border-radius: 50%; background: var(--surface-3); border: 1px solid var(--line-strong); }
.port.in { left: -5px; }
.port.out { right: -5px; }

.node-action {
  position: absolute; bottom: -11px; right: 10px; display: inline-flex; align-items: center; gap: 0.25rem;
  min-height: 0; padding: 0.12rem 0.5rem; border-radius: 999px; font-size: 0.68rem; font-weight: 600;
  color: var(--ground); background: var(--text); border: 1px solid var(--text); cursor: pointer;
}
.node-action:disabled { opacity: 0.6; cursor: default; }

.legend-line { gap: 0.35rem 1rem; }
.legend-line span { display: inline-flex; align-items: center; gap: 0.4rem; }
.lg { display: inline-block; width: 18px; border-top: 2px solid var(--line-strong); }
.lg.ok { border-color: var(--ok); }
.lg.wait { border-top-style: dashed; border-color: var(--warn); }
.lg.active { border-top-style: dashed; border-color: var(--ok); }
.lg.bad { border-color: var(--danger); }
/* Schrittliste für schmale Bildschirme: gleiche Zustände und Farben wie die Knoten */
.vflow { display: flex; flex-direction: column; gap: 1rem; }
.vhosts { list-style: none; margin: 0; padding: 0; display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0.5rem; }
.vhost {
  width: 100%; min-height: 44px; display: flex; align-items: center; gap: 0.55rem; padding: 0.5rem 0.65rem; text-align: left;
  color: var(--text); background: var(--surface-2); border: 1px solid var(--line-strong); border-radius: var(--radius-sm);
}
.vhost-text { display: flex; flex-direction: column; min-width: 0; }
.vsteps { list-style: none; margin: 0; padding: 0; position: relative; }
.vsteps::before { content: ''; position: absolute; left: 3px; top: 1.2rem; bottom: 1.2rem; width: 1px; background: var(--line-strong); }
.vstep { position: relative; display: grid; grid-template-columns: 7px minmax(0, 1fr); column-gap: 0.85rem; padding: 0.3rem 0; }
.vstep > .vdot { margin-top: 1.35rem; position: relative; z-index: 1; box-shadow: 0 0 0 3px var(--surface); }
.vstep.side .vstep-body { margin-left: 0.9rem; border-style: dashed; }
.vstep-body {
  width: 100%; min-height: 52px; display: flex; align-items: center; gap: 0.65rem; padding: 0.6rem 0.7rem; text-align: left;
  color: var(--text); background: var(--surface-2); border: 1px solid var(--line-strong); border-radius: var(--radius-sm);
}
.vstep.active .vstep-body { border-color: color-mix(in srgb, var(--ok) 55%, var(--line-strong)); }
.vstep.wait .vstep-body { border-color: color-mix(in srgb, var(--warn) 45%, var(--line-strong)); }
.vstep.bad .vstep-body { border-color: color-mix(in srgb, var(--danger) 45%, var(--line-strong)); }
.vstep-body .text { display: flex; flex-direction: column; gap: 0.1rem; min-width: 0; flex: 1; }
.vstep-body .sub { white-space: normal; }
.vnote { font-family: var(--mono); font-size: 0.68rem; color: var(--muted); }
.vchev { color: var(--muted); flex: none; }
.vaction { grid-column: 2; justify-self: start; margin-top: 0.4rem; }
.vdot { width: 7px; height: 7px; flex: none; border-radius: 50%; background: var(--muted); }
.ok > .vdot, .vhost.ok .vdot { background: var(--ok); }
.warn > .vdot, .wait > .vdot, .vhost.warn .vdot, .vhost.wait .vdot { background: var(--warn); }
.bad > .vdot, .vhost.bad .vdot { background: var(--danger); }
.active > .vdot, .vhost.active .vdot { background: var(--ok); animation: pulse 1.2s ease-in-out infinite; }

/* Punkte oben rechts an den Knoten: gleiche Farben wie .node .dot */
.lg-sep { width: 1px; height: 0.85rem; background: var(--line-strong); }
.ld { display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: var(--muted); }
.ld.ok { background: var(--ok); }
.ld.active { background: var(--ok); animation: pulse 1.2s ease-in-out infinite; }
.ld.warn { background: var(--warn); }
.ld.bad { background: var(--danger); }

.explain { color: var(--text-2); font-size: 0.9rem; margin: 0 0 0.9rem; }
dl { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 0.4rem 1rem; margin: 0 0 1rem; font-size: 0.88rem; }
dt { color: var(--muted); }
dd { margin: 0; word-break: break-word; }
.fails { list-style: none; margin: 0; padding: 0; max-height: 260px; overflow: auto; font-size: 0.85rem; }
.fails li { padding: 0.45rem 0; border-top: 1px solid var(--line); }
.fails .subtext { display: block; margin-top: 0.15rem; word-break: break-word; }

@media (prefers-reduced-motion: reduce) {
  .edge.active, .node.active .dot, .ld.active, .active > .vdot, .vhost.active .vdot { animation: none; }
}
</style>
