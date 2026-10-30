<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { api } from '../api.js'
import { useLive } from '../live.js'
import { fmtDateTime, timeAgo } from '../time.js'
import Icon from './Icon.vue'
import SecretField from './SecretField.vue'
import SettingsCard from './SettingsCard.vue'
import SettingsEntry from './SettingsEntry.vue'
import SettingsList from './SettingsList.vue'
import SettingsSection from './SettingsSection.vue'

// Produktstände (Registry, endoflife.date) und Internet-Erreichbarkeit aus Nginx Proxy Manager und der FRITZ!Box
const versions = ref(null)
const npm = ref(null)
const fritz = ref(null)
const fform = reactive({ url: '', user: '', password: '' })
const systems = ref([])
const form = reactive({ url: '', email: '', password: '', system_id: null })
const message = ref(null)
const busy = ref(false)

async function load() {
  const [v, n, s, f] = await Promise.all([api.get('/api/versions'), api.get('/api/settings/npm'), api.get('/api/systems'),
    api.get('/api/settings/fritzbox')])
  versions.value = v
  npm.value = n
  fritz.value = f
  if (f.config && !fform.url) Object.assign(fform, { url: f.config.url, user: f.config.user })
  systems.value = s.filter((x) => x.status === 'active')
  if (n.config && !form.url) Object.assign(form, { url: n.config.url, email: n.config.email, system_id: n.config.system_id })
}

const totals = computed(() => {
  const out = { current: 0, outdated: 0, 'newer-version': 0, unknown: 0, pending: 0, local: 0 }
  for (const s of Object.values(versions.value?.systems || {})) for (const r of s.rows) out[r.status] = (out[r.status] || 0) + 1
  return out
})

async function checkNow() {
  await api.post('/api/versions/refresh')
  message.value = { kind: 'ok', text: 'Version check started; results appear here and on each host in a minute or two.' }
  setTimeout(load, 15000)
}

async function saveNpm() {
  busy.value = true
  message.value = null
  try {
    await api.put('/api/settings/npm', { url: form.url, email: form.email, password: form.password || null, system_id: form.system_id })
    form.password = ''
    const r = await api.post('/api/settings/npm/test')
    message.value = r.ok
      ? { kind: 'ok', text: `Connected: ${r.hosts} proxy hosts, ${Object.values(r.exposed).flat().length} containers marked internet-exposed.` }
      : { kind: 'error', text: `Saved, but NPM could not be read: ${r.error}` }
    await load()
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}

async function testNpm() {
  busy.value = true
  message.value = null
  try {
    const r = await api.post('/api/settings/npm/test')
    message.value = r.ok ? { kind: 'ok', text: `Connected: ${r.hosts} proxy hosts, ${(r.certificates || []).length} certificates in use.` }
      : { kind: 'error', text: `NPM could not be read: ${r.error}` }
    await load()
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}

const fritzText = (r) => `${r.forwards} port forwards, ${Object.values(r.exposed).flat().length} containers or hosts internet-exposed`

async function saveFritz() {
  busy.value = true
  message.value = null
  try {
    await api.put('/api/settings/fritzbox', { url: fform.url, user: fform.user, password: fform.password || null })
    fform.password = ''
    const r = await api.post('/api/settings/fritzbox/test')
    message.value = r.ok ? { kind: 'ok', text: `Connected: ${fritzText(r)}.` }
      : { kind: 'error', text: `Saved, but the FRITZ!Box could not be read: ${r.error}` }
    await load()
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}

async function testFritz() {
  busy.value = true
  message.value = null
  try {
    const r = await api.post('/api/settings/fritzbox/test')
    message.value = r.ok ? { kind: 'ok', text: `Connected: ${fritzText(r)}.` } : { kind: 'error', text: `FRITZ!Box could not be read: ${r.error}` }
    await load()
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}

async function removeFritz() {
  if (!confirm('Remove the FRITZ!Box connection? Containers marked by hand stay marked.')) return
  await api.del('/api/settings/fritzbox')
  Object.assign(fform, { url: '', user: '', password: '' })
  await load()
}

const exposedCount = computed(() => Object.values(npm.value?.state?.exposed || {}).flat().length)
const status = computed(() => {
  if (!versions.value?.at) return { tone: 'neutral', text: 'Not checked yet' }
  const t = totals.value
  return { tone: t.unknown ? 'danger' : t.outdated ? 'warning' : 'ok', text: `${t.outdated} outdated · ${t.unknown} not checkable` }
})

async function removeNpm() {
  if (!confirm('Remove the NPM connection? Containers marked by hand stay marked.')) return
  await api.del('/api/settings/npm')
  Object.assign(form, { url: '', email: '', password: '', system_id: null })
  await load()
}

const showAllCerts = ref(false)
const certTone = (d) => (d == null || d < 7 ? 'danger' : d < 20 ? 'warning' : 'ok')
const certText = (d) => (d == null ? 'unreadable' : d < 0 ? `expired ${Math.abs(Math.round(d))} d ago` : `${Math.round(d)} d`)
const sysName = (id) => systems.value.find((s) => s.id === Number(id))?.name || `#${id}`
onMounted(load)
useLive(['settings', 'findings'], load, 3000)
</script>

<template>
  <SettingsCard icon="package" title="Versions &amp; exposure" subtitle="Image updates and end of life (replaces image-check), internet exposure from Nginx Proxy Manager and the FRITZ!Box" :status="status">
    <SettingsSection title="Version check">
      <SettingsList>
        <SettingsEntry icon="refresh" title="Registry and end-of-life check" class="version-entry"
                       :meta="[versions?.at ? `Last pass ${timeAgo(new Date(versions.at * 1000).toISOString())} · every 6 hours` : 'Not run yet · every 6 hours',
                               versions?.at ? `${totals.current} current · ${totals.outdated} outdated · ${totals['newer-version']} newer version · ${totals.pending} queued (Docker Hub limit) · ${totals.local} built locally` : 'Registry digest per running image, newer versions, release lines from endoflife.date']">
          <template #actions>
            <button type="button" class="btn-sm" @click="checkNow"><Icon name="refresh" :size="14" />Check now</button>
          </template>
          <span class="subtext">Results become findings (filter <RouterLink :to="{ path: '/funde', query: { source: 'products' } }">Versions &amp; EOL</RouterLink>),
            the Versions column on the overview and the version per container in each host. “Check now” runs the pass immediately:
            NPM, every running image against its registry, release lines against endoflife.date.</span>
          <p v-if="versions?.eol_error" class="message error">{{ versions.eol_error }}</p>
        </SettingsEntry>
      </SettingsList>
    </SettingsSection>

    <SettingsSection title="Nginx Proxy Manager">
      <SettingsList :empty="!npm?.config" empty-text="Not connected. With a read-only NPM user vulnwatch learns which services are reachable from the internet and checks their TLS certificates.">
        <SettingsEntry v-if="npm?.config" icon="link" :title="npm.config.url" mono
                       :meta="[`User ${npm.config.email} · runs on ${npm.config.system_id ? sysName(npm.config.system_id) : 'no host chosen'}`,
                               npm.state?.configured ? (npm.state.ok ? `Last read ${timeAgo(new Date(npm.state.at * 1000).toISOString())}: ${npm.state.hosts} proxy hosts, ${exposedCount} containers internet-exposed` : `Last read failed: ${npm.state.error}`) : 'Not read yet']">
          <template #badge>
            <span v-if="npm.state?.configured" :class="['badge', npm.state.ok ? 'ok' : 'danger']">{{ npm.state.ok ? 'Connected' : 'Failing' }}</span>
          </template>
          <template #actions>
            <button type="button" class="btn-sm" :disabled="busy" @click="testNpm"><Icon name="refresh" :size="14" />Test</button>
            <button type="button" class="btn-sm btn-delete" :disabled="busy" @click="removeNpm"><Icon name="trash" :size="14" />Remove</button>
          </template>
          <p v-if="npm.state?.cert_note" class="message error">{{ npm.state.cert_note }}</p>
          <details v-if="npm.state?.unmatched?.length" class="more">
            <summary>{{ npm.state.unmatched.length }} proxy targets without a clear container – mark them on the host</summary>
            <span v-for="u in npm.state.unmatched" :key="u.target + u.domains[0]" class="more-line"><span class="mono">{{ u.domains.join(', ') }} → {{ u.target }}</span> · {{ u.reason }}</span>
          </details>
        </SettingsEntry>
      </SettingsList>

      <form class="settings-form" @submit.prevent="saveNpm">
        <div class="grid">
          <label><span class="field-label">Admin URL (port 81)</span><input v-model="form.url" name="npm_url" placeholder="http://npm.lan:81" autocomplete="off" required /></label>
          <label><span class="field-label">User e-mail</span><input v-model="form.email" name="npm_email" placeholder="vulnwatch@example.org" autocomplete="off" required /></label>
          <SecretField v-model="form.password" name="npm_password" label="Password" :set="!!npm?.password?.set" :updated-at="npm?.password?.updated_at" />
          <label>
            <span class="field-label">Host running NPM</span>
            <select v-model="form.system_id" name="npm_host">
              <option :value="null">Choose a host…</option>
              <option v-for="s in systems" :key="s.id" :value="s.id">{{ s.name }}</option>
            </select>
          </label>
        </div>
        <p class="subtext">A dedicated NPM user with item visibility “All items” and view-only rights is enough. vulnwatch reads proxy hosts and the expiry dates of their certificates, never private keys, access lists or DNS credentials.</p>
        <div class="actions">
          <button class="primary" :disabled="busy || !form.url || !form.email"><Icon name="check" :size="15" />{{ busy ? 'Saving & testing…' : 'Save and test' }}</button>
        </div>
      </form>
    </SettingsSection>

    <SettingsSection title="FRITZ!Box port forwards">
      <SettingsList :empty="!fritz?.config" empty-text="Not connected. With a FRITZ!Box user vulnwatch reads the IPv4 port forwards and marks the containers and hosts behind them as internet-exposed, including services that bypass NPM.">
        <SettingsEntry v-if="fritz?.config" icon="link" :title="fritz.config.url" mono
                       :meta="[`User ${fritz.config.user}`,
                               fritz.state?.configured ? (fritz.state.ok ? `Last read ${timeAgo(new Date(fritz.state.at * 1000).toISOString())}: ${fritzText(fritz.state)}` : `Last read failed: ${fritz.state.error}`) : 'Not read yet']">
          <template #badge>
            <span v-if="fritz.state?.configured" :class="['badge', fritz.state.ok ? 'ok' : 'danger']">{{ fritz.state.ok ? 'Connected' : 'Failing' }}</span>
          </template>
          <template #actions>
            <button type="button" class="btn-sm" :disabled="busy" @click="testFritz"><Icon name="refresh" :size="14" />Test</button>
            <button type="button" class="btn-sm btn-delete" :disabled="busy" @click="removeFritz"><Icon name="trash" :size="14" />Remove</button>
          </template>
          <details v-if="fritz.state?.unmatched?.length" class="more">
            <summary>{{ fritz.state.unmatched.length }} port forwards without a clear container – mark them on the host</summary>
            <span v-for="u in fritz.state.unmatched" :key="u.forward" class="more-line"><span class="mono">{{ u.forward }}</span>{{ u.description ? ` (${u.description})` : '' }} · {{ u.reason }}</span>
          </details>
        </SettingsEntry>
      </SettingsList>

      <form class="settings-form" @submit.prevent="saveFritz">
        <div class="grid">
          <label><span class="field-label">TR-064 URL</span><input v-model="fform.url" name="fritz_url" placeholder="http://192.168.178.1:49000" autocomplete="off" required /></label>
          <label><span class="field-label">User</span><input v-model="fform.user" name="fritz_user" placeholder="vulnwatch" autocomplete="off" required /></label>
          <SecretField v-model="fform.password" name="fritz_password" label="Password" :set="!!fritz?.password?.set" :updated-at="fritz?.password?.updated_at" />
        </div>
        <p class="subtext">Create a FRITZ!Box user with the right “FRITZ!Box settings” and enable “Allow access for applications” (Home network › Network › Network settings). vulnwatch only reads the port forward list and never changes it. IPv6 releases are not visible over TR-064; mark those by hand.</p>
        <div class="actions">
          <button class="primary" :disabled="busy || !fform.url || !fform.user"><Icon name="check" :size="15" />{{ busy ? 'Saving & testing…' : 'Save and test' }}</button>
        </div>
      </form>
    </SettingsSection>

    <SettingsSection v-if="npm?.state?.certificates?.length" title="TLS certificates in use" :count="npm.state.certificates.length"
                     hint="NPM renews 30 days ahead · under 20 days medium · under 7 days or expired high">
      <SettingsList>
        <SettingsEntry v-for="c in npm.state.certificates.slice(0, showAllCerts ? undefined : 5)" :key="c.name" dense mono
                       :title="c.domains.join(', ') || c.name">
          <template #actions><span :class="['days', certTone(c.days_left)]" :title="c.expires_on ? `expires ${fmtDateTime(c.expires_on)}` : ''">{{ certText(c.days_left) }}</span></template>
        </SettingsEntry>
      </SettingsList>
      <button v-if="npm.state.certificates.length > 5" type="button" class="link more-toggle" @click="showAllCerts = !showAllCerts">
        {{ showAllCerts ? 'Show fewer' : `Show all ${npm.state.certificates.length}` }}
      </button>
    </SettingsSection>

    <p v-if="message" class="message" :class="message.kind" role="status">{{ message.text }}</p>
  </SettingsCard>
</template>

<style scoped>
.more summary { cursor: pointer; font-size: 0.8rem; color: var(--text-2); width: fit-content; }
.more[open] summary { margin-bottom: 0.4rem; }
.more-line { display: block; font-size: 0.78rem; color: var(--muted); padding: 0.15rem 0; overflow-wrap: anywhere; }
.more-line .mono { color: var(--text-2); }
.more-toggle { align-self: flex-start; }
/* Restlaufzeit: Zahl in der Ampelfarbe statt einer Pille je Zeile */
.days { font: 0.78rem var(--mono); font-variant-numeric: tabular-nums; white-space: nowrap; }
.days.ok { color: var(--ok); }
.days.warning { color: var(--med); }
.days.danger { color: var(--crit); font-weight: 600; }
.version-entry .subtext a { color: var(--text-2); }
</style>
