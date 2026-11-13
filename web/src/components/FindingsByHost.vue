<script setup>
// Ansicht „By host“: Zahlen je Host, dann die Funde eines Hosts gruppiert nach Maßnahme (Image, Kernel, Pakete …).
// Die Filter der Fundliste gelten hier gleich (params kommt aus FindingsView).
import { label, fmtNum as fmt } from '../labels.js'
import { ref, watch } from 'vue'
import { api } from '../api.js'
import Icon from './Icon.vue'

const props = defineProps({ params: { type: Object, required: true }, hostId: { type: [String, Number], default: '' } })
const emit = defineEmits(['open-host', 'show-findings'])

const hosts = ref([])
const detail = ref(null)
const loading = ref(false)
const error = ref('')
const openGroup = ref(null)
const copied = ref(null)

const STATES = {
  update: ['Update fixes these', 'ok'],
  stuck: ['Last update did not fix these', 'wait'],   // neueres Image da, aber dieselben Funde blieben schon einmal
  tag: ['Change the tag', 'warn'],
  rebuild: ['Rebuild the image', 'warn'],
  waiting: ['Waiting for a fix', 'wait'],
  manual: ['Manual steps', 'muted'],
  unknown: ['Not checked against the registry', 'muted'],
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const q = new URLSearchParams(props.params)
    q.delete('system_id')
    if (props.hostId) {
      q.set('system_id', props.hostId)
      detail.value = await api.get(`/api/findings/groups?${q}`)
    } else {
      detail.value = null
      hosts.value = await api.get(`/api/findings/by-host?${q}`)
    }
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

async function copy(g) {
  try {
    await navigator.clipboard.writeText(g.command)
    copied.value = g.key
    setTimeout(() => { if (copied.value === g.key) copied.value = null }, 1600)
  } catch { /* ohne Clipboard-Rechte bleibt der Befehl markierbar */ }
}

watch(() => [props.params, props.hostId], () => { openGroup.value = null; load() }, { immediate: true, deep: true })
defineExpose({ load })
</script>

<template>
  <p v-if="error" class="message error" role="alert">{{ error }}</p>

  <!-- Übersicht: ein Host je Zeile -->
  <template v-if="!hostId">
    <div v-if="loading && !hosts.length" class="empty">Loading hosts…</div>
    <div v-else-if="hosts.length" class="table-wrap" :class="{ stale: loading }">
      <table class="data-table">
        <thead>
          <tr>
            <th>Host</th>
            <th class="num">Critical</th>
            <th class="num">High</th>
            <th class="num">Medium</th>
            <th class="num">KEV</th>
            <th class="num" title="An update fixes it now: host package update or a newer image for the tag">Fixable now</th>
            <th class="num">Images</th>
            <th><span class="sr-only">Open</span></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="h in hosts" :key="h.system_id" class="clickable" @click="emit('open-host', h.system_id)">
            <td class="strong">{{ h.system_name }}</td>
            <td class="num" :class="{ crit: h.kritisch }">{{ fmt(h.kritisch) }}</td>
            <td class="num" :class="{ high: h.hoch }">{{ fmt(h.hoch) }}</td>
            <td class="num">{{ fmt(h.mittel) }}</td>
            <td class="num">{{ fmt(h.kev) }}</td>
            <td class="num text-success">{{ fmt(h.fixable) }}</td>
            <td class="num">{{ fmt(h.images) }}</td>
            <td class="row-action"><button class="btn-sm" @click.stop="emit('open-host', h.system_id)">Open</button></td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else class="empty">No findings match these filters.</div>
  </template>

  <!-- Ein Host: Gruppen mit je einer Maßnahme -->
  <template v-else>
    <div v-if="loading && !detail" class="empty">Loading groups…</div>
    <template v-else-if="detail">
      <p class="subtitle host-head">{{ detail.system_name }} · {{ detail.groups.length }} groups, most urgent first</p>
      <div v-if="!detail.groups.length" class="empty">No findings match these filters.</div>
      <article v-for="g in detail.groups" :key="g.key" class="group" :class="{ stale: loading }" :data-test="`group-${g.key}`">
        <header class="group-head">
          <div class="group-title">
            <span class="strong">{{ g.title }}</span>
            <span v-if="g.subtitle" class="subtext truncate" :title="g.subtitle">{{ g.subtitle }}</span>
          </div>
          <div class="group-counts">
            <span v-if="g.counts.kev" class="badge-kev" title="Known exploited (CISA KEV)">{{ g.counts.kev }} KEV</span>
            <span v-for="sev in ['kritisch', 'hoch', 'mittel']" v-show="g.counts[sev]" :key="sev" :class="`badge-sev ${sev}`">{{ fmt(g.counts[sev]) }} {{ label(sev) }}</span>
            <span v-if="g.counts.info" class="subtext">{{ fmt(g.counts.info) }} info</span>
          </div>
        </header>
        <div class="group-action" :class="STATES[g.state]?.[1]">
          <span class="state">{{ g.state === 'update' && g.counts.stayed ? 'Update may fix some of these' : STATES[g.state]?.[0] || g.state }}<template v-if="g.counts.fixable && g.state === 'update'"> · {{ g.counts.stayed ? `${fmt(g.counts.stayed)} of ${fmt(g.counts.fixable)} stayed after the last update` : `${fmt(g.counts.fixable)} fixable now` }}</template></span>
          <p class="action-text">{{ g.text }}</p>
          <span v-if="g.command" class="action-cmd">
            <code class="mono">{{ g.command }}</code>
            <button class="btn-sm" @click="copy(g)"><Icon :name="copied === g.key ? 'check' : 'copy'" :size="13" />{{ copied === g.key ? 'Copied' : 'Copy' }}</button>
          </span>
          <span v-if="g.command" class="subtext">Run it on {{ detail.system_name }}. General advice: check it fits your setup before running it.</span>
        </div>
        <footer class="group-foot">
          <button class="btn-sm" :aria-expanded="openGroup === g.key" @click="openGroup = openGroup === g.key ? null : g.key">
            {{ openGroup === g.key ? 'Hide' : 'Show' }} {{ fmt(g.packages_total) }} {{ g.packages_total === 1 ? 'package' : 'packages' }}
          </button>
          <button v-if="g.target" class="btn-sm" @click="emit('show-findings', { systemId: detail.system_id, target: g.target })">All {{ fmt(g.counts.total) }} findings in the list</button>
        </footer>
        <table v-if="openGroup === g.key" class="data-table pkgs">
          <thead><tr><th>Package</th><th>Installed</th><th>Fix</th><th class="num">Findings</th><th>Worst</th></tr></thead>
          <tbody>
            <tr v-for="p in g.packages" :key="p.component + p.installed_version">
              <td class="strong truncate" :title="p.component">{{ p.component }}</td>
              <td class="mono subtext">{{ p.installed_version }}</td>
              <td><span v-if="p.fixed_version" class="mono text-success">{{ p.fixed_version }}</span><span v-else class="text-muted">none yet</span></td>
              <td class="num">{{ fmt(p.count) }}</td>
              <td><span :class="`badge-sev ${p.severity}`">{{ label(p.severity) }}</span><span v-if="p.kev" class="badge-kev">KEV</span></td>
            </tr>
            <tr v-if="g.packages_total > g.packages.length"><td colspan="5" class="subtext">{{ fmt(g.packages_total - g.packages.length) }} more: open the list to see all.</td></tr>
          </tbody>
        </table>
      </article>
    </template>
  </template>
</template>

<style scoped>
.num { text-align: right; font-family: var(--mono); font-size: 0.8125rem; white-space: nowrap; }
.num.crit { color: var(--crit); }
.num.high { color: var(--high); }
.row-action { text-align: right; }
.clickable { cursor: pointer; }
.clickable:hover td { background: var(--surface-2); }
.stale { opacity: 0.55; transition: opacity 0.2s; }
.host-head { margin: 0 0 0.75rem; }
.group { border: 1px solid var(--line); border-radius: var(--radius-sm); padding: 0.75rem 1rem; margin-bottom: 0.75rem; }
.group-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; flex-wrap: wrap; }
.group-title { display: flex; flex-direction: column; min-width: 0; }
.group-title .truncate { max-width: 70ch; }
.group-counts { display: flex; gap: 0.375rem; align-items: center; flex-wrap: wrap; }
.group-action { margin-top: 0.625rem; padding: 0.5rem 0.75rem; border-radius: var(--radius-sm); border-left: 3px solid var(--line-strong); background: var(--surface-2); }
.group-action.ok { border-left-color: var(--ok); }
.group-action.warn { border-left-color: var(--high); }
.group-action.wait { border-left-color: var(--med); }
.state { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-2); }
.action-text { margin: 0.25rem 0 0.5rem; font-size: 0.875rem; color: var(--text-2); max-width: 100ch; line-height: 1.5; }
.action-cmd { display: flex; align-items: center; gap: 0.25rem; max-width: 80ch; margin-bottom: 0.25rem; padding: 0.25rem 0.25rem 0.25rem 0.5rem;
  border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--surface); }
.action-cmd code { flex: 1; min-width: 0; overflow-x: auto; white-space: nowrap; font-size: 0.75rem; color: var(--text); }
.group-foot { display: flex; gap: 0.25rem; margin-top: 0.5rem; flex-wrap: wrap; }
.pkgs { margin-top: 0.5rem; }
.pkgs .truncate { max-width: 40ch; }
.sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
</style>
