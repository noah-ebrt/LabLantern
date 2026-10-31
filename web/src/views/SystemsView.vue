<script setup>
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import { api } from '../api.js'
import Icon from '../components/Icon.vue'
import { useLive } from '../live.js'
import { usePasskey } from '../webauthn.js'
import { signedCommand } from '../commands.js'
import { timeAgo } from '../time.js'
import { APPLIANCE_KINDS, hostVersion } from '../labels.js'
import ApplianceGuide from '../components/ApplianceGuide.vue'
import ConnectorDetailModal from '../components/ConnectorDetailModal.vue'
import HostDetailModal from '../components/HostDetailModal.vue'
import Modal from '../components/Modal.vue'

const systems = ref([])
const update = ref(null)
const error = ref('')
const loading = ref(false)

// Add System Modal State
const showAddModal = ref(false)
const enrollData = ref(null)
const enrollLoading = ref(false)
const copied = ref(false)

// Host-Popup (Inventar und Befehle)
const openId = ref(null)

// Neustart, Update, Entfernen aus der Liste: Passkey signiert, der Agent prüft selbst
async function sendSigned(type, sys) {
  error.value = ''
  try {
    const res = await signedCommand(sys.id, type)
    await loadSystems()
    return res
  } catch (e) {
    error.value = e.message
    return null
  }
}

// Laufende gefährliche Aktionen meldet der Server je System (pending_action). Die Knöpfe bleiben gesperrt,
// bis der Agent fertig ist, scheitert oder nicht antwortet – auch nach Neuladen und in anderen Tabs.
const ACTION_LABELS = { update_agent: 'Updating…', reboot: 'Rebooting…', uninstall: 'Removing…' }
const busy = (s) => !!s?.pending_action
const busyLabel = (s) => ACTION_LABELS[s?.pending_action] || ''

async function updateAgent(s) {
  if (!busy(s)) await sendSigned('update_agent', s)
}

// Alle veralteten Agenten: ab 0.13 ein Passkey-Touch für alle, ältere Agenten je ein Touch nacheinander
const outdated = computed(() => systems.value.filter((s) => s.status === 'active' && s.agent_outdated && !s.needs_reenroll))
const updatingAll = ref(false)
const updateAllMsg = ref('')
async function updateAll() {
  error.value = ''
  updatingAll.value = true
  updateAllMsg.value = ''
  try {
    const p = await api.post('/api/systems/commands/update-all/prepare')
    const done = []
    if (p.options) {
      updateAllMsg.value = `Confirm with your passkey: one touch updates ${p.batch_ids.length} host${p.batch_ids.length === 1 ? '' : 's'}…`
      const credential = await usePasskey(p.options)
      done.push(...(await api.post('/api/systems/commands/update-all/confirm', { credential })).created)
    }
    for (const [i, id] of p.single_ids.entries()) {
      const s = systems.value.find((x) => x.id === id)
      updateAllMsg.value = `${s?.name || id}: agent before 0.13 needs its own passkey touch (${i + 1} of ${p.single_ids.length})…`
      await signedCommand(id, 'update_agent')
      done.push(s?.name || String(id))
    }
    updateAllMsg.value = `Update sent to ${done.join(', ')}. Each agent installs the signed package and reports back with the new version.`
    await loadSystems()
  } catch (e) {
    error.value = e.message
    updateAllMsg.value = ''
  } finally {
    updatingAll.value = false
  }
}

const copiedUpdate = ref(false)
async function copyUpdate() {
  try {
    await navigator.clipboard.writeText(update.value.update_cmd)
    copiedUpdate.value = true
    setTimeout(() => (copiedUpdate.value = false), 2500)
  } catch {
    error.value = 'Copying needs a secure context (https) – select the command and copy it by hand.'
  }
}
const lastCheck = computed(() => update.value?.last_check || null)

// Endet eine Aktion ohne Erfolg, sagen wir es (die Ursache steht im Befehlsverlauf)
async function reportFinished(before) {
  for (const s of systems.value) {
    const prev = before.find((x) => x.id === s.id)
    if (!prev?.pending_action || s.pending_action) continue
    try {
      const c = (await api.get(`/api/systems/${s.id}/commands`)).find((x) => x.type === prev.pending_action)
      if (c && ['failed', 'rejected', 'expired'].includes(c.status)) {
        error.value = `${s.name}: ${ACTION_LABELS[c.type].replace('…', '')} failed${c.output ? ` – ${c.output}` : ''}`
      }
    } catch {
      /* Verlauf zeigt es ohnehin */
    }
  }
}

// Neue Hosts per `vulnwatch-agent setup`: Code vergleichen, dann mit Passkey freigeben
const pairings = ref([])

async function loadPairings() {
  try {
    pairings.value = await api.get('/api/pairings')
  } catch {
    /* Liste ist optional */
  }
}

async function approvePairing(p) {
  error.value = ''
  try {
    const o = await api.post(`/api/pairings/${p.id}/approve/options`)
    const body = o.passkey ? { credential: await usePasskey(o.options) } : {}
    await api.post(`/api/pairings/${p.id}/approve`, body)
    await Promise.all([loadPairings(), loadSystems()])
  } catch (e) {
    error.value = e.message
  }
}

async function rejectPairing(p) {
  if (!confirm(`Reject the pairing request from ${p.hostname} (${p.ip})?`)) return
  await api.post(`/api/pairings/${p.id}/reject`)
  await loadPairings()
}

// silent: Live-Aktualisierung ohne „Loading…“-Flackern und ohne eine Fehlermeldung zu löschen
async function loadSystems(silent = false) {
  if (!silent) {
    loading.value = true
    error.value = ''
  }
  try {
    const before = systems.value
    systems.value = await api.get('/api/systems')
    await loadAppliances()
    update.value = await api.get('/api/systems/agent-update')
    reportFinished(before)
  } catch (e) {
    if (!silent) error.value = e.message
  } finally {
    loading.value = false
  }
}

// Live-Updates vom Server
useLive(['systems'], () => loadSystems(true))
useLive(['pairings'], loadPairings)
useLive(['commands'], () => loadSystems(true))

// Hinzufügen: erst die Art des Hosts, dann deren Anleitung. Geräte ohne Agent laufen über ihre API (Connector).
const HOST_KINDS = [
  { kind: 'linux', title: 'Linux server', text: 'Agent with pairing: packages, containers, images, updates, reboot. Needs systemd and curl.' },
  { kind: 'truenas', title: 'TrueNAS', text: 'Read through the TrueNAS API: version, system update, apps, alerts. No agent on the NAS.' },
  { kind: 'homeassistant', title: 'Home Assistant', text: 'Read through the Home Assistant API: Core, OS, add-ons and firmware updates.' },
  { kind: 'proxmox', title: 'Proxmox VE', text: 'Read through the PVE API: version and updates per node, and which VMs and LXCs have no agent yet.' },
  { kind: 'collector', title: 'Other device (collector script)', text: 'Unraid, Synology, OpenWrt …: a small cron script sends packages and containers. No agent, no commands.' },
]
const addKind = ref(null)
const connectorId = ref(null)   // Detailansicht eines Geräts ohne Agent
const editEntry = ref(null)
const appliances = ref([])
const notice = ref('')

async function loadAppliances() {
  if (!systems.value.some((s) => s.connector)) return (appliances.value = [])
  appliances.value = await api.get('/api/settings/appliances').catch(() => [])
}
const applianceOf = (s) => appliances.value.find((a) => a.system_id === s.id)

function openAddModal() {
  addKind.value = null
  editEntry.value = null
  showAddModal.value = true
}

function chooseKind(kind) {
  addKind.value = kind
  Object.assign(collector, { name: '', error: '', data: null })
  if (kind === 'linux') startLinux()
}

// Collector-Gerät (PLAN-extensions C): Token nur einmal sichtbar, danach nur ein neues ausstellbar
const collector = reactive({ name: '', busy: false, error: '', data: null })

async function createCollector() {
  collector.busy = true
  collector.error = ''
  try {
    collector.data = await api.post('/api/collector/systems', { name: collector.name.trim() })
    await loadSystems(true)
  } catch (e) {
    collector.error = e.message
  } finally {
    collector.busy = false
  }
}

async function collectorToken(s) {
  if (!confirm(`Create a new token for ${s.name}? The current one stops working.`)) return
  try {
    Object.assign(collector, { name: s.name, error: '', data: await api.post(`/api/collector/systems/${s.id}/token`) })
    addKind.value = 'collector'
    showAddModal.value = true
  } catch (e) {
    error.value = e.message
  }
}

function editAppliance(s) {
  editEntry.value = applianceOf(s)
  addKind.value = s.connector.kind
  showAddModal.value = true
}

async function applianceSaved(text) {
  showAddModal.value = false
  notice.value = text
  await loadSystems(true)
}

async function testAppliance(s, trust = false) {
  error.value = ''
  notice.value = ''
  try {
    const a = applianceOf(s)
    const r = trust ? await api.put(`/api/settings/appliances/${s.id}`, { kind: a.kind, name: a.name, url: a.url, token: null, trust_certificate: true })
      : await api.post(`/api/settings/appliances/${s.id}/test`)
    if (r.ok) notice.value = `${s.name}: read, ${r.findings} open update(s) or alert(s).`
    else error.value = `${s.name} could not be read: ${r.error}`
    await loadSystems(true)
  } catch (e) {
    error.value = e.message
  }
}

function trustCertificate(s) {
  if (!confirm(`Trust the certificate ${s.name} presents now? If you did not replace it yourself, compare its fingerprint on the device first.`)) return
  testAppliance(s, true)
}

async function startLinux() {
  enrollLoading.value = true
  enrollData.value = null
  copied.value = false
  try {
    enrollData.value = await api.post('/api/systems/enrollment-token', {})
  } catch (e) {
    error.value = e.message
  } finally {
    enrollLoading.value = false
  }
}

function copyCommand(text) {
  if (!text) return
  navigator.clipboard.writeText(text)
  copied.value = true
  setTimeout(() => (copied.value = false), 2500)
}

async function approveSystem(id) {
  try {
    await api.post(`/api/systems/${id}/approve`, {})
    await loadSystems()
    
  } catch (e) {
    error.value = e.message
  }
}

async function revokeSystem(id) {
  if (!confirm('Really revoke agent access for this system?')) return
  try {
    await api.post(`/api/systems/${id}/revoke`, {})
    await loadSystems()
  } catch (e) {
    error.value = e.message
  }
}

// Löschen heißt überall weg: Ist der Agent verbunden, entfernt er sich (mit Passkey) selbst vom Host,
// danach löscht der Server den Eintrag. Sonst bleiben nur die Daten hier zu löschen.
async function deleteSystem(id) {
  const sys = systems.value.find((x) => x.id === id)
  if (sys?.online && sys.status === 'active') {
    if (!confirm(`Remove the agent from ${sys.name} completely (services, configuration, token, passkey list) and delete all its data here? This needs a passkey touch.`)) return
    // Der Eintrag verschwindet per Live-Update, sobald der Agent sich entfernt hat
    await sendSigned('uninstall', sys)
    return
  }
  if (sys?.status === 'connector') {
    if (!confirm(`Remove the connection to ${sys.name} and delete its findings?`)) return
    await api.del(`/api/settings/appliances/${id}`)
    await loadSystems()
    return
  }
  if (!confirm(`${sys?.name || 'This system'} is not connected, so vulnwatch can only delete its data here.\nOn the host, remove the agent yourself: sudo apt purge vulnwatch-agent (or sudo rpm -e vulnwatch-agent).\n\nDelete the data now?`)) return
  try {
    await api.del(`/api/systems/${id}`)
    await loadSystems()
  } catch (e) {
    error.value = e.message
  }
}

function viewDetails(id) {
  openId.value = id
}

const STATE_BADGES = {
  pending: { text: 'Waiting for approval', cls: 'badge pending' },
  revoked: { text: 'Revoked', cls: 'badge danger' },
  initializing: { text: 'Initializing', cls: 'badge pending initializing', title: 'Approved – waiting for the first report (up to 3 minutes)' },
  error: { text: 'Error (no report)', cls: 'badge danger', title: 'The agent did not report within 3 minutes after approval' },
  offline: { text: 'Error (offline)', cls: 'badge danger', title: 'No report for more than 24 hours' },
  online: { text: 'Active', cls: 'badge ok' },
}

function statusBadge(s) {
  if (s.state && STATE_BADGES[s.state]) return STATE_BADGES[s.state]
  // ältere Server ohne `state`
  if (s.status === 'pending') return STATE_BADGES.pending
  if (s.status === 'revoked') return STATE_BADGES.revoked
  if (s.is_stale) return STATE_BADGES.offline
  return STATE_BADGES.online
}

onMounted(() => {
  loadSystems()
  loadPairings()
  const open = Number(new URLSearchParams(window.location.search).get('open'))   // Link aus der Übersicht
  if (open) viewDetails(open)
})
</script>

<template>
  <div class="header-row">
    <div>
      <h1>Systems & agents</h1>
      <p class="subtitle">Linux hosts with an agent, and devices read through their API</p>
    </div>
    <div>
      <button class="primary" @click="openAddModal">+ Add host</button>
    </div>
  </div>

  <p v-if="error" class="message error" role="alert">{{ error }}</p>
  <p v-if="notice" class="message ok" role="status">{{ notice }}</p>
  <section v-if="pairings.length" class="card pairings">
    <div class="card-header">
      <h2 class="panel-title">Pending pairings</h2>
      <span class="hint">Approve only if the code is identical to the one shown on the host</span>
    </div>
    <div v-for="p in pairings" :key="p.id" class="pairing">
      <div class="pairing-main">
        <span class="strong">{{ p.hostname }}</span>
        <span class="subtext">{{ p.ip }} · agent v{{ p.agent_version || '?' }}<template v-if="p.replaces_existing"> · replaces the existing agent of {{ p.hostname }} (history is kept)</template></span>
      </div>
      <span class="pair-code" aria-label="Pairing code">{{ p.code }}</span>
      <div class="actions">
        <button class="btn-sm primary" @click="approvePairing(p)">Codes match – approve</button>
        <button class="btn-sm btn-delete" @click="rejectPairing(p)">Reject</button>
      </div>
    </div>
  </section>

  <section v-if="systems.some((s) => s.needs_reenroll)" class="notice">
    <strong>Set up again:</strong> {{ systems.filter((s) => s.needs_reenroll).map((s) => s.name).join(', ') }}
    still runs a very old agent without certificate pinning. Set it up again via “+ Add host” → Linux server.
  </section>
  <section v-if="update && outdated.length" class="card release" aria-labelledby="release-title">
    <div class="release-head">
      <div>
        <h2 id="release-title" class="release-title">Agent {{ update.version }} is available</h2>
        <p class="subtext">{{ outdated.length }} of {{ systems.filter((s) => s.status === 'active').length }} hosts run an older agent:
          {{ outdated.map((s) => `${s.name} (v${s.agent_version})`).join(', ') }}. Configuration and token stay.</p>
      </div>
      <button class="primary" :disabled="updatingAll || outdated.every(busy)" @click="updateAll">
        <Icon name="download" :size="15" />{{ updatingAll ? 'Updating…' : outdated.length === 1 ? 'Update agent' : `Update all ${outdated.length}` }}
      </button>
    </div>
    <p v-if="updateAllMsg" class="message" role="status">{{ updateAllMsg }}</p>
    <details v-if="update.update_cmd" class="manual">
      <summary>Update by hand instead (e.g. when a host is not connected)</summary>
      <div class="cmd-block">
        <div class="cmd-bar-top">
          <span class="mono">bash · run on the host</span>
          <button class="btn-sm" @click="copyUpdate"><Icon :name="copiedUpdate ? 'check' : 'copy'" :size="14" />{{ copiedUpdate ? 'Copied' : 'Copy' }}</button>
        </div>
        <pre class="cmd-text">{{ update.update_cmd }}</pre>
      </div>
      <p class="subtext">Downloads the package from this master, checks its SHA-256 and installs it with dpkg or rpm.</p>
    </details>
  </section>
  <p v-else-if="update && systems.length" class="release-ok subtext">
    <Icon name="check" :size="14" />All agents run v{{ update.version }}, the newest release.
    <template v-if="lastCheck">
      <span v-if="lastCheck.ok">Checked for new releases {{ timeAgo(lastCheck.at) }}.</span>
      <span v-else class="text-danger">Last release check failed {{ timeAgo(lastCheck.at) }}: {{ lastCheck.error }}</span>
    </template>
  </p>

  <div v-if="loading" class="empty">Loading systems…</div>

  <div v-else-if="systems.length" class="card">
    <div class="table-wrap">
    <table class="data-table">
      <thead>
        <tr>
          <th>System name</th>
          <th>IP address</th>
          <th>Status</th>
          <th>Container</th>
          <th>Security updates</th>
          <th>Last seen</th>
          <th class="text-right">Actions</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="s in systems" :key="s.id">
          <td class="strong">
            <a href="#" @click.prevent="s.connector ? (connectorId = s.id) : viewDetails(s.id)">{{ s.name }}</a>
            <span v-if="s.connector" class="subtext">{{ hostVersion(s) }} · read via API<template v-if="applianceOf(s)"> · {{ applianceOf(s).url }}</template></span>
            <span v-else-if="s.host_type === 'collector'" class="subtext">collector script, no agent</span>
            <span v-else class="subtext">v{{ s.agent_version || '0.1.0' }}<template v-if="s.agent_outdated"> · outdated</template><template v-if="s.online"> · connected</template></span>
          </td>
          <td>{{ s.ip || '–' }}</td>
          <td>
            <span :class="statusBadge(s).cls" :title="statusBadge(s).title">{{ statusBadge(s).text }}</span>
          </td>
          <td>{{ s.container_count }}</td>
          <td>
            <button v-if="s.security_updates_count > 0" class="count-link text-danger" :title="`Show which updates ${s.name} needs`"
                    @click="viewDetails(s.id)">{{ s.security_updates_count }}</button>
            <span v-else>{{ s.security_updates_count }}</span>
            <span v-if="s.reboot_required" class="badge-reboot">Reboot!</span>
            <span v-for="(msg, k) in s.collection_errors || {}" :key="k" class="badge danger" :title="msg">Data error: {{ k }}</span>
          </td>
          <td>{{ s.last_seen ? `${s.age_hours} h ago` : 'never' }}</td>
          <td class="action-cell text-right">
            <div class="actions-inline">
              <button v-if="s.status === 'active' && s.agent_outdated && !s.needs_reenroll" class="btn-sm btn-update" :disabled="busy(s)" :title="busy(s) ? busyLabel(s) : `Update agent to v${update?.version || ''} (requires passkey)`" @click="updateAgent(s)">{{ s.pending_action === 'update_agent' ? 'Updating…' : 'Update' }}</button>
              <template v-if="s.connector && applianceOf(s)">
                <button class="btn-sm" @click="testAppliance(s)">Test</button>
                <button v-if="s.collection_errors?.connector?.includes('certificate changed')" class="btn-sm" @click="trustCertificate(s)">Trust new certificate</button>
                <button class="btn-sm" @click="editAppliance(s)">Edit</button>
              </template>
              <button v-if="s.host_type === 'collector'" class="btn-sm" data-test="collector-token" @click="collectorToken(s)">New token</button>
              <button v-if="s.status === 'active'" class="btn-sm" @click="viewDetails(s.id)">Manage</button>
              <button v-if="s.status === 'pending'" class="btn-sm btn-approve" @click="approveSystem(s.id)">Approve</button>
              <button v-if="s.status === 'active'" class="btn-sm btn-revoke" @click="revokeSystem(s.id)">Revoke</button>
              <button class="btn-sm btn-delete" :disabled="busy(s)" @click="deleteSystem(s.id)">{{ s.pending_action === 'uninstall' ? 'Removing…' : 'Delete' }}</button>
            </div>
          </td>
        </tr>
      </tbody>
    </table>
    </div>
  </div>

  <div v-else class="card empty">
    <p>No systems connected yet.</p>
    <button class="primary" @click="openAddModal">Add the first host</button>
  </div>

  <!-- Add System Modal -->
  <Modal v-if="showAddModal" class="setup-modal" size="lg" @close="showAddModal = false">
    <template v-if="!addKind">
      <h2>Add a host</h2>
      <p class="subtitle">Choose what kind of host it is. Each kind has its own guide.</p>
      <div class="kinds">
        <button v-for="k in HOST_KINDS" :key="k.kind" type="button" class="kind" @click="chooseKind(k.kind)">
          <strong>{{ k.title }}</strong><span class="subtext">{{ k.text }}</span>
        </button>
      </div>
    </template>

    <template v-else-if="addKind === 'collector'">
      <button v-if="!collector.data" type="button" class="link back" @click="addKind = null">← Other kind of host</button>
      <h2>Add a device with a collector script</h2>
      <p class="subtitle">For devices where the agent can't run. A cron script on the device sends its OS version, packages
        and containers to vulnwatch. vulnwatch never sends anything back: no commands, no updates.
        Examples for Unraid, Synology and OpenWrt are in <code>collectors/</code> in the repository; the format is
        <code>docs/collector-schema.json</code>.</p>
      <form v-if="!collector.data" class="collector-form" data-test="collector-form" @submit.prevent="createCollector">
        <label>Device name <input v-model="collector.name" name="collector_name" required maxlength="100" pattern="[A-Za-z0-9][A-Za-z0-9._\-]*" placeholder="unraid" /></label>
        <button class="primary" :disabled="collector.busy || !collector.name.trim()">Create token</button>
        <p v-if="collector.error" class="text-danger">{{ collector.error }}</p>
      </form>
      <ol v-else class="steps" data-test="collector-setup">
        <li>
          <div class="step-head">
            <strong>Run this once on {{ collector.data.name }}</strong>
            <span class="subtext">Fetches the root certificate, checks its fingerprint and stores address and token in
              <code>/etc/vulnwatch-collector</code> (Unraid: set <code>VW_DIR=/boot/config/vulnwatch</code> first, /etc is lost on reboot).
              The token is shown only now.</span>
          </div>
          <div v-if="collector.data.setup_cmd" class="cmd-block">
            <div class="cmd-bar-top">
              <span class="mono">sh</span>
              <button class="btn-sm" @click="copyCommand(collector.data.setup_cmd)">
                <Icon :name="copied ? 'check' : 'copy'" :size="14" />{{ copied ? 'Copied' : 'Copy' }}
              </button>
            </div>
            <pre class="cmd-text">{{ collector.data.setup_cmd }}</pre>
          </div>
          <p v-else class="text-danger">Root certificate unreadable: token <code>{{ collector.data.token }}</code>, address {{ collector.data.server_url }}.</p>
        </li>
        <li>
          <div class="step-head">
            <strong>Copy the collector script for the device and add its cron line</strong>
            <span class="subtext">The script's header has the cron line. Reports more often than every 5 minutes are refused;
              no report for 24 hours shows as an error.</span>
          </div>
        </li>
      </ol>
    </template>

    <template v-else-if="addKind !== 'linux'">
      <button v-if="!editEntry" type="button" class="link back" @click="addKind = null">← Other kind of host</button>
      <h2>{{ editEntry ? `Edit ${editEntry.name}` : `Add ${APPLIANCE_KINDS[addKind]}` }}</h2>
      <p class="subtitle">No agent: vulnwatch reads the device through its own API, with a read-only account.</p>
      <ApplianceGuide :kind="addKind" :entry="editEntry" @saved="applianceSaved" />
    </template>

    <template v-else>
    <button type="button" class="link back" @click="addKind = null">← Other kind of host</button>
    <h2>Add a Linux host</h2>
    <p class="subtitle">Three steps. The host needs systemd and <code>curl</code>; the agent installs as a signed package.</p>

    <div v-if="enrollLoading" class="empty">Preparing…</div>
    <ol v-else-if="enrollData" class="steps">
      <li v-if="enrollData.setup_cmd">
        <div class="step-head">
          <strong>Run this on the new host</strong>
          <span class="subtext">Downloads and verifies the package, installs it and starts pairing.</span>
        </div>
        <div class="cmd-block">
          <div class="cmd-bar-top">
            <span class="mono">bash</span>
            <button class="btn-sm" @click="copyCommand(enrollData.setup_cmd)">
              <Icon :name="copied ? 'check' : 'copy'" :size="14" />{{ copied ? 'Copied' : 'Copy' }}
            </button>
          </div>
          <pre class="cmd-text">{{ enrollData.setup_cmd }}</pre>
        </div>
      </li>
      <li v-else>
        <div class="step-head">
          <strong>No agent packages on this master yet</strong>
          <span class="subtext">The stack builds and signs the agent when it starts; that takes a few minutes the first time.
            If it does not appear, check <code>docker compose logs agent-build agent-sign</code> in <code>deploy/</code> and
            <RouterLink to="/einstellungen" @click="showAddModal = false">Settings → Agent releases</RouterLink>.</span>
        </div>
      </li>
      <li>
        <div class="step-head">
          <strong>Note the pairing code the host prints</strong>
          <span class="subtext">It looks like <span class="mono">ABC-DEF</span>. A different code below means the host is not talking to this master.</span>
        </div>
      </li>
      <li>
        <div class="step-head">
          <strong>Compare and approve</strong>
          <span class="subtext">Approval needs your passkey.</span>
        </div>
        <div v-if="pairings.length" class="modal-pairings">
          <div v-for="p in pairings" :key="p.id" class="pairing">
            <div class="pairing-main"><span class="strong">{{ p.hostname }}</span><span class="subtext">{{ p.ip }}</span></div>
            <span class="pair-code">{{ p.code }}</span>
            <button class="btn-sm primary" @click="approvePairing(p)">Codes match – approve</button>
            <button class="btn-sm btn-delete" @click="rejectPairing(p)">Reject</button>
          </div>
        </div>
        <p v-else class="waiting"><span class="pulse" />Waiting for the host to ask for pairing…</p>
      </li>
    </ol>

    <details v-if="enrollData" class="alt">
      <summary>Alternative: one-time token instead of pairing</summary>
      <p class="hint">For hosts where nobody can compare a code. The token is valid for 60 minutes; approve the host afterwards in the list.</p>
      <div class="cmd-block">
        <div class="cmd-bar-top">
          <span class="mono">bash</span>
          <button class="btn-sm" @click="copyCommand(enrollData.install_cmd || enrollData.enroll_cmd)"><Icon name="copy" :size="14" />Copy</button>
        </div>
        <pre class="cmd-text">{{ enrollData.install_cmd || enrollData.enroll_cmd }}</pre>
      </div>
      <p class="subtext">CA fingerprint <span class="mono">{{ enrollData.ca_fingerprint }}</span></p>
    </details>
    </template>

  </Modal>

  <ConnectorDetailModal v-if="connectorId" :system-id="connectorId" @close="connectorId = null" />
  <HostDetailModal v-if="openId" :system-id="openId" @close="openId = null" @changed="loadSystems(true)" />
</template>

<style scoped>
.collector-form { display: flex; gap: 0.75rem; align-items: flex-end; flex-wrap: wrap; }
.collector-form label { display: flex; flex-direction: column; gap: 0.25rem; }
.pairings .pairing, .modal-pairings .pairing { display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; padding: 0.7rem 0; border-top: 1px solid var(--line); }
.pairing-main { flex: 1; min-width: 180px; display: flex; flex-direction: column; }
.pair-code { font: 600 1.35rem/1 var(--mono); letter-spacing: 0.12em; color: var(--text); padding: 0.35rem 0.7rem; border: 1px solid var(--line-strong); border-radius: 8px; background: var(--ground); }
.alt { margin: 1rem 0; color: var(--text-2); }
.alt summary { cursor: pointer; }
.setup-modal .subtitle { margin-bottom: 1.25rem; }
.setup-modal .back { margin-bottom: 0.4rem; font-size: 0.8rem; }
/* Art des Hosts wählen: eine Kachel je Art */
.kinds { display: grid; grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr)); gap: 0.75rem; }
.kind { display: flex; flex-direction: column; align-items: flex-start; gap: 0.35rem; text-align: left; padding: 0.9rem 1rem;
  min-height: 0; background: var(--surface-2); border: 1px solid var(--line); border-radius: var(--radius); color: var(--text); }
.kind:hover { border-color: var(--line-strong); background: var(--surface-3); }
.kind .subtext { white-space: normal; line-height: 1.45; }
.steps { list-style: none; counter-reset: step; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 1.1rem; }
.steps > li { counter-increment: step; position: relative; padding-left: 2.4rem; }
.steps > li::before {
  content: counter(step); position: absolute; left: 0; top: 0; width: 1.6rem; height: 1.6rem; border-radius: 50%;
  display: grid; place-items: center; font: 600 0.8rem var(--mono); color: var(--text); background: var(--surface-3); border: 1px solid var(--line-strong);
}
.step-head { display: flex; flex-direction: column; gap: 0.1rem; margin-bottom: 0.55rem; }
.release { display: flex; flex-direction: column; gap: 0.8rem; }
.release-head { display: flex; justify-content: space-between; align-items: center; gap: 1rem; flex-wrap: wrap; }
.release-title { margin: 0; font-size: 1rem; font-weight: 600; }
.release .message { margin: 0; }
.manual summary { cursor: pointer; color: var(--text-2); font-size: 0.85rem; width: fit-content; }
.manual summary:hover { color: var(--text); }
.manual[open] summary { margin-bottom: 0.6rem; }
.manual .subtext { margin-top: 0.45rem; }
.release-ok { display: flex; align-items: center; gap: 0.45rem; flex-wrap: wrap; margin: 0 0 1.1rem; }
.release-ok :deep(svg) { color: var(--ok); }
.cmd-block { border: 1px solid var(--line-strong); border-radius: 10px; background: var(--ground); overflow: hidden; }
.cmd-bar-top { display: flex; justify-content: space-between; align-items: center; padding: 0.35rem 0.5rem 0.35rem 0.8rem; border-bottom: 1px solid var(--line); color: var(--muted); font-size: 0.75rem; }
.cmd-text { margin: 0; padding: 0.75rem 0.85rem; max-height: 9.5rem; overflow: auto; font: 0.76rem/1.55 var(--mono); color: var(--text-2); white-space: pre-wrap; word-break: break-all; }
.waiting { display: flex; align-items: center; gap: 0.6rem; color: var(--muted); margin: 0; }
.pulse { width: 8px; height: 8px; border-radius: 50%; background: var(--text-2); animation: pulse 1.6s var(--ease) infinite; }
@keyframes pulse { 50% { opacity: 0.25; transform: scale(0.75); } }
.badge.initializing::before { animation: pulse 1.4s var(--ease) infinite; }
.alt .cmd-block { margin: 0.6rem 0; }
.count-link { min-height: 0; padding: 0; border: none; background: none; font: inherit; font-variant-numeric: tabular-nums;
              text-decoration: underline; text-underline-offset: 3px; cursor: pointer; }
.count-link:hover { text-decoration-thickness: 2px; }
</style>
