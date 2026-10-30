<script setup>
import { computed, onMounted, ref } from 'vue'
import { api } from '../api.js'
import { signedCommand } from '../commands.js'
import { useLive } from '../live.js'
import { fmtClockSec } from '../time.js'
import EarlyWarningWatch from './EarlyWarningWatch.vue'
import HostCoverage from './HostCoverage.vue'
import Modal from './Modal.vue'

// Host-Popup (Inventar, Befehle, Neustart/Update); genutzt von Systeme und Übersicht
const props = defineProps({ systemId: { type: Number, required: true } })
const emit = defineEmits(['close', 'changed'])

const system = ref(null)
const update = ref(null)
const loading = ref(true)
const error = ref('')

// Befehle an den Agenten (feste Liste; der Agent prüft sie selbst noch einmal)
const QUERIES = [
  { id: 'uptime', label: 'Uptime' },
  { id: 'disk_usage', label: 'Disk usage' },
  { id: 'failed_units', label: 'Failed services' },
  { id: 'listening_ports', label: 'Open ports' },
]
const commands = ref([])
const cmdError = ref('')
const versions = ref(null)       // Zeile je Image aus /api/versions (Registry-Abgleich)
const containerMsg = ref('')

// Soll/Ist und Internet-Erreichbarkeit je Container
const diff = computed(() => system.value?.containers_expected || { missing: [], unknown: [], expected: [] })
const exposed = computed(() => new Set(system.value?.exposed_containers || []))
// Von NPM bzw. der FRITZ!Box erkannt: gilt ohne Haken, von Hand nicht abwählbar
const autoExposed = computed(() => system.value?.exposed_auto || {})
const viaTexts = (name) => system.value?.exposed_via?.[name] || autoExposed.value[name] || []
function containerState(c) {
  if (diff.value.unknown.includes(c.name)) return { cls: 'warning', text: 'unexpected' }
  if (c.state !== 'running') return { cls: 'neutral', text: c.state }
  return { cls: 'ok', text: 'running' }
}
// Digests kürzen (der volle Wert steht im Tooltip), sonst schiebt ein sha256 die Tabelle aus dem Dialog
const shortImage = (img) => (img || '').replace(/(sha256:[0-9a-f]{12})[0-9a-f]{52}/, '$1…')
const versionOf = (c) => versions.value?.rows?.find((r) => r.containers.includes(c.name))
const VERSION_BADGE = { current: 'ok', outdated: 'danger', 'newer-version': 'warning', unknown: 'danger', pending: 'neutral', local: 'neutral' }
const VERSION_TEXT = { current: 'current', outdated: 'outdated', 'newer-version': 'newer version', unknown: 'not checkable', pending: 'queued', local: 'built locally' }

async function acceptContainers() {
  if (!confirm('Use the containers running right now as the expected state of this host?')) return
  containerMsg.value = ''
  try {
    await api.post(`/api/systems/${props.systemId}/containers/expected`)
    await refresh()
  } catch (e) {
    containerMsg.value = e.message
  }
}

async function toggleExposed(name) {
  const next = new Set(exposed.value)
  next.has(name) ? next.delete(name) : next.add(name)
  containerMsg.value = ''
  try {
    await api.put(`/api/systems/${props.systemId}/exposed`, { containers: [...next] })
    await refresh()
  } catch (e) {
    containerMsg.value = e.message
  }
}

function commandLabel(c) {
  if (c.type === 'report_now') return 'Report now'
  if (c.type === 'reboot') return 'Reboot'
  if (c.type === 'update_agent') return `Update agent to v${c.params?.version}`
  return QUERIES.find((q) => q.id === c.params?.name)?.label || c.params?.name
}

const ACTION_LABELS = { update_agent: 'Updating…', reboot: 'Rebooting…', uninstall: 'Removing…' }
const busy = (s) => !!s?.pending_action
const busyLabel = (s) => ACTION_LABELS[s?.pending_action] || ''

// Neue Ergebnisse kommen per Live-Update (Thema "commands"), kein Nachfragen im Takt
async function loadCommands() {
  try {
    commands.value = await api.get(`/api/systems/${props.systemId}/commands`)
  } catch (e) {
    cmdError.value = e.message
  }
}

async function refresh() {
  try {
    system.value = await api.get(`/api/systems/${props.systemId}`)
  } catch (e) {
    if (e.status === 404) emit('close')   // System wurde gelöscht
    else error.value = e.message
  }
}

async function sendCommand(type, query = null) {
  cmdError.value = ''
  try {
    await api.post(`/api/systems/${props.systemId}/commands`, query ? { type, query } : { type })
    await loadCommands()
  } catch (e) {
    cmdError.value = e.message
  }
}

// Neustart und Update: der Server bereitet den Befehl vor, der Passkey signiert genau diesen, der Agent prüft selbst
async function sendSigned(type) {
  if (type === 'reboot' && !confirm(`Reboot ${system.value.name} in 30 seconds?`)) return
  cmdError.value = ''
  try {
    await signedCommand(props.systemId, type)
    await Promise.all([loadCommands(), refresh()])
    emit('changed')
  } catch (e) {
    cmdError.value = e.message
  }
}

onMounted(async () => {
  try {
    await Promise.all([refresh(), loadCommands()])
    update.value = await api.get('/api/systems/agent-update').catch(() => null)
    const v = await api.get('/api/versions').catch(() => null)
    versions.value = v?.systems?.[String(props.systemId)] || null
  } finally {
    loading.value = false
  }
})
useLive(['systems'], refresh)
useLive(['commands'], loadCommands)
</script>

<template>
  <Modal size="lg" :label="system ? `Host ${system.name}` : 'Host'" @close="emit('close')">
    <div v-if="loading" class="empty">Loading system data…</div>
    <p v-else-if="error" class="message error" role="alert">{{ error }}</p>
    <div v-else-if="system">
      <h2>System inventory: {{ system.name }}</h2>
      <p class="subtitle">{{ system.inventory?.os_name }} · Kernel {{ system.inventory?.kernel }} ({{ system.inventory?.arch }})</p>
      <p class="subtext">Problems also appear as <RouterLink :to="{ path: '/funde', query: { q: system.name } }" @click="emit('close')">findings</RouterLink>.</p>

      <HostCoverage :system-id="systemId" />

      <template v-if="system.status === 'active' && system.host_type !== 'collector'">
        <h3>Actions</h3>
        <div class="cmd-bar">
          <button class="btn-sm primary" @click="sendCommand('report_now')">Report now</button>
          <button v-for="q in QUERIES" :key="q.id" class="btn-sm secondary" @click="sendCommand('query', q.id)">{{ q.label }}</button>
        </div>
        <div class="cmd-bar">
          <button v-if="system.agent_outdated" class="btn-sm" :disabled="busy(system)" title="Requires a passkey touch" @click="sendSigned('update_agent')">{{ system.pending_action === 'update_agent' ? 'Updating…' : `Update agent to v${update?.version}` }}</button>
          <button class="btn-sm btn-revoke" :disabled="busy(system)" title="Requires a passkey touch" @click="sendSigned('reboot')">{{ system.pending_action === 'reboot' ? 'Rebooting…' : 'Reboot host…' }}</button>
          <span v-if="busy(system)" class="subtext">{{ busyLabel(system) }} Other actions unlock when the agent reports back.</span>
          <span class="subtext">Reboot and update need a passkey touch; the agent verifies it itself.</span>
        </div>
        <p class="subtext">
          {{ system.online ? 'Agent connected: answers within seconds.' : 'Agent not connected right now (needs v0.7 or newer): commands expire after 5 minutes.' }}
        </p>
        <p v-if="cmdError" class="text-danger">{{ cmdError }}</p>
        <div v-for="c in commands" :key="c.id" class="cmd-entry">
          <div>
            <strong>{{ commandLabel(c) }}</strong>
            <span :class="['badge', c.status === 'done' ? 'ok' : ['failed', 'rejected', 'expired'].includes(c.status) ? 'danger' : '']">{{ c.status }}</span>
            <span class="subtext">{{ c.created_by }} · {{ fmtClockSec(c.created_at) }}</span>
          </div>
          <pre v-if="c.output" class="cmd">{{ c.output }}</pre>
        </div>
      </template>

      <h3>Containers ({{ system.inventory?.containers?.length || 0 }})</h3>
      <div class="cmd-bar">
        <span v-if="diff.missing.length" class="badge danger">missing: {{ diff.missing.join(', ') }}</span>
        <span v-if="diff.unknown.length" class="badge warning">unexpected: {{ diff.unknown.join(', ') }}</span>
        <span v-if="!diff.missing.length && !diff.unknown.length" class="subtext">All {{ diff.expected.length }} expected containers are running.</span>
        <button v-if="diff.missing.length || diff.unknown.length" class="btn-sm" @click="acceptContainers">Accept running containers as expected</button>
        <label class="chk" :title="viaTexts('(host)').join(' · ') || 'Services of the host itself (not in a container) are reachable from the internet'">
          <input type="checkbox" :checked="exposed.has('(host)') || !!autoExposed['(host)']" :disabled="!!autoExposed['(host)']" @change="toggleExposed('(host)')" />Host internet-exposed
          <span v-if="autoExposed['(host)']" class="via">{{ viaTexts('(host)').join(' · ') }}</span>
        </label>
      </div>
      <p v-if="containerMsg" class="text-danger">{{ containerMsg }}</p>
      <div v-if="system.inventory?.containers?.length" class="table-wrap">
        <table class="data-table containers">
          <thead>
            <tr>
              <th>Name</th>
              <th>Image</th>
              <th>Status</th>
              <th title="Registry check every 6 hours">Version</th>
              <th title="Raises severities (CVSS 7+ with fix: high, 9+: critical). Detected from NPM and the FRITZ!Box; tick by hand what they cannot see">Internet</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="c in system.inventory.containers" :key="c.id">
              <td class="strong name">{{ c.name }} <span v-if="c.runtime === 'podman'" class="badge neutral" title="Container runs under Podman">podman</span></td>
              <td class="img"><code :title="c.image">{{ shortImage(c.image) }}</code></td>
              <td class="st"><span :class="['badge', containerState(c).cls]">{{ containerState(c).text }}</span></td>
              <td class="ver">
                <template v-if="versionOf(c)">
                  <span :class="['badge', VERSION_BADGE[versionOf(c).status]]" :title="versionOf(c).detail">{{ VERSION_TEXT[versionOf(c).status] }}</span>
                  <span class="subtext mono">{{ versionOf(c).running }}{{ versionOf(c).newer && versionOf(c).newer !== versionOf(c).running ? ` → ${versionOf(c).newer}` : '' }}</span>
                </template>
                <span v-else class="subtext">{{ c.state === 'running' ? 'not checked yet' : '–' }}</span>
              </td>
              <td class="net" :title="viaTexts(c.name).join(' · ')">
                <input type="checkbox" :checked="exposed.has(c.name) || !!autoExposed[c.name]" :disabled="!!autoExposed[c.name]"
                       :aria-label="`${c.name} reachable from the internet`" @change="toggleExposed(c.name)" />
                <span v-if="autoExposed[c.name]" class="via">{{ viaTexts(c.name).join(' · ') }}</span>
              </td>
            </tr>
            <tr v-for="name in diff.missing" :key="`missing-${name}`">
              <td class="strong">{{ name }}</td>
              <td class="subtext">expected, not running</td>
              <td><span class="badge danger">missing</span></td>
              <td /><td />
            </tr>
          </tbody>
        </table>
      </div>
      <p v-else class="empty">No Docker containers reported.</p>

      <EarlyWarningWatch :system-id="systemId" />
    </div>
    <template #actions>
      <slot name="actions" />
    </template>
  </Modal>
</template>

<style scoped>
.cmd-bar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 8px 0; }
.cmd-entry { margin: 10px 0; }
.cmd-entry .badge { margin: 0 6px; }
.cmd-bar .badge { align-self: center; }
.chk { display: inline-flex; flex-direction: row; align-items: center; margin-left: 0.25rem; gap: 0.35rem; font-size: 0.85rem; color: var(--muted); }
.chk input, td input[type=checkbox] { width: auto; margin: 0; }
.net, .name, .ver .badge { white-space: nowrap; }
.img code { white-space: nowrap; }
/* Schmal: jede Zeile ein Eintrag – Name und Status oben, Image darunter, Version und Internet unten */
@media (max-width: 640px) {
  .containers thead { display: none; }
  .containers tr { display: grid; grid-template-columns: minmax(0, 1fr) auto; grid-template-areas: "name st" "img img" "ver net";
                   gap: 0.3rem 0.75rem; align-items: center; padding: 0.75rem 0; border-bottom: 1px solid var(--line); }
  .containers tbody tr:last-child { border-bottom: none; }
  .containers td { display: block; padding: 0; border: none; }
  .containers td:nth-child(1) { grid-area: name; white-space: normal; }
  .containers td:nth-child(2) { grid-area: img; }
  .containers td:nth-child(3) { grid-area: st; }
  .containers td:nth-child(4) { grid-area: ver; }
  .containers td:nth-child(5) { grid-area: net; justify-self: end; }
  .containers td:nth-child(5):not(:empty)::before { content: 'Internet'; margin-right: 0.4rem; font-size: 0.78rem; color: var(--muted); }
  .img code { white-space: normal; word-break: break-all; }
}
.via { margin-left: 0.35rem; font-size: 0.72rem; color: var(--muted); }
</style>
