<script setup>
import { onMounted, reactive, ref } from 'vue'
import { api } from '../api.js'
import { timeAgo } from '../time.js'
import Icon from './Icon.vue'
import SecretField from './SecretField.vue'
import SettingsEntry from './SettingsEntry.vue'
import SettingsFold from './SettingsFold.vue'

// Portfreigaben aus OPNsense und UniFi (PLAN-extensions D2), Gegenstück zum FRITZ!Box-Abschnitt
const emit = defineEmits(['changed'])
const ROUTERS = {
  opnsense: {
    label: 'OPNsense', url: 'https://opnsense.lan', secret: 'API secret',
    empty: 'Not connected. With an API key LabLantern reads the port forwards (Destination NAT) and marks the containers and hosts behind them as internet-exposed. Needs OPNsense 26.1 or newer.',
    help: 'System › Access › Users: a user <code>lablantern</code> with only the privilege for Firewall: NAT: Destination NAT, then create an API key for it. OPNsense has no read-only variant of that privilege; LabLantern only sends GET requests and never changes a rule. HTTPS only, the certificate is pinned when you save.',
  },
  unifi: {
    label: 'UniFi', url: 'https://unifi.lan', secret: 'API key',
    empty: 'Not connected. With an API key LabLantern reads the port forwards of your UniFi console and marks the containers and hosts behind them as internet-exposed.',
    help: 'On a UniFi OS console with Network 9 or newer: add an admin with the role <strong>View Only</strong>, sign in as that admin and create an API key under Settings › Control Plane › Integrations. LabLantern reads the port forward list of the site and never changes it. HTTPS only, the certificate is pinned when you save.',
  },
}
const data = reactive({ opnsense: null, unifi: null })
const forms = reactive({ opnsense: { url: '', key: '', secret: '' }, unifi: { url: '', site: 'default', secret: '' } })
const busy = ref(false)
const message = reactive({ opnsense: null, unifi: null })

const summary = (st) => `${st.forwards} port forwards, ${Object.values(st.exposed || {}).flat().length} containers or hosts internet-exposed`
const badge = (cfg, st) => (!cfg ? { tone: 'neutral', text: 'Not connected' } : !st?.configured ? { tone: 'neutral', text: 'Not read yet' }
  : st.ok ? { tone: 'ok', text: 'Connected' } : { tone: 'danger', text: 'Failing' })
const stateLine = (st) => !st?.configured ? 'Not read yet'
  : st.ok ? `Last read ${timeAgo(new Date(st.at * 1000).toISOString())}: ${summary(st)}` : `Last read failed: ${st.error}`

async function load(kind) {
  const r = await api.get(`/api/settings/router/${kind}`)
  data[kind] = r
  if (r.config) Object.assign(forms[kind], { url: r.config.url, key: r.config.key || '', site: r.config.site || 'default', secret: '' })
}

async function act(kind, fn) {
  busy.value = true
  message[kind] = null
  try {
    await fn()
    await load(kind)
    emit('changed')
  } catch (e) {
    message[kind] = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}

const test = async (kind) => {
  const r = await api.post(`/api/settings/router/${kind}/test`)
  message[kind] = r.ok ? { kind: 'ok', text: `Connected: ${summary(r)}.` }
    : { kind: 'error', text: `${ROUTERS[kind].label} could not be read: ${r.error}` }
}
const save = (kind) => act(kind, async () => {
  const f = forms[kind]
  await api.put(`/api/settings/router/${kind}`, { url: f.url, key: f.key, site: f.site, secret: f.secret || null })
  await test(kind)
})
const trust = (kind) => {
  if (!confirm(`Trust the new certificate of ${ROUTERS[kind].label}? Compare its fingerprint on the device first if you did not change it yourself.`)) return
  act(kind, async () => {
    const f = forms[kind]
    await api.put(`/api/settings/router/${kind}`, { url: f.url, key: f.key, site: f.site, secret: null, trust_certificate: true })
    await test(kind)
  })
}
const remove = (kind) => {
  if (!confirm(`Remove the ${ROUTERS[kind].label} connection? Containers marked by hand stay marked.`)) return
  act(kind, () => api.del(`/api/settings/router/${kind}`))
}

onMounted(() => Promise.all(Object.keys(ROUTERS).map((k) => load(k).catch(() => {}))))
</script>

<template>
  <SettingsEntry v-for="(r, kind) in ROUTERS" :id="`set-${kind}`" :key="kind" icon="link" :title="`${r.label} port forwards`" :data-test="`router-${kind}`"
                 :meta="data[kind]?.config ? [`${data[kind].config.url} · ${kind === 'opnsense' ? `API key ${data[kind].config.key}` : `site ${data[kind].config.site}`}`, stateLine(data[kind].state)] : r.empty">
    <template #badge><span :class="['badge', badge(data[kind]?.config, data[kind]?.state).tone]">{{ badge(data[kind]?.config, data[kind]?.state).text }}</span></template>
    <template v-if="data[kind]?.config" #actions>
      <button type="button" class="btn-sm" :disabled="busy" @click="act(kind, () => test(kind))"><Icon name="refresh" :size="14" />Test</button>
      <button v-if="data[kind].state?.error?.includes('certificate changed')" type="button" class="btn-sm" :disabled="busy" @click="trust(kind)">Trust new certificate</button>
      <button type="button" class="btn-sm btn-delete" :disabled="busy" @click="remove(kind)"><Icon name="trash" :size="14" />Remove</button>
    </template>
    <SettingsFold v-if="data[kind]?.state?.unmatched?.length" class="more" :data-test="`router-${kind}-unmatched`"
                  :title="`${data[kind].state.unmatched.length} port forwards without a clear container – mark them on the host`">
      <div>
        <span v-for="u in data[kind].state.unmatched" :key="u.forward" class="more-line"><span class="mono">{{ u.forward }}</span>{{ u.description ? ` (${u.description})` : '' }} · {{ u.reason }}</span>
      </div>
    </SettingsFold>
    <SettingsFold :id="`set-${kind}-form`" :title="data[kind]?.config ? 'Edit connection' : `Connect ${r.label}`" :open="!!message[kind]">
      <form class="settings-form" @submit.prevent="save(kind)">
        <div class="grid">
          <label><span class="field-label">URL</span><input v-model="forms[kind].url" :name="`${kind}_url`" :placeholder="r.url" autocomplete="off" required /></label>
          <label v-if="kind === 'opnsense'"><span class="field-label">API key</span><input v-model="forms[kind].key" name="opnsense_key" autocomplete="off" required /></label>
          <label v-else><span class="field-label">Site</span><input v-model="forms[kind].site" name="unifi_site" autocomplete="off" required /></label>
          <SecretField v-model="forms[kind].secret" :name="`${kind}_secret`" :label="r.secret" :set="!!data[kind]?.secret?.set" :updated-at="data[kind]?.secret?.updated_at" />
        </div>
        <!-- eslint-disable-next-line vue/no-v-html -- feste Texte aus dieser Datei -->
        <p class="subtext" v-html="r.help" />
        <p v-if="message[kind]" :class="['message', message[kind].kind]">{{ message[kind].text }}</p>
        <div class="actions">
          <button class="primary" :disabled="busy || !forms[kind].url"><Icon name="check" :size="15" />{{ busy ? 'Saving & testing…' : 'Save and test' }}</button>
        </div>
      </form>
    </SettingsFold>
  </SettingsEntry>
</template>

<style scoped>
.more summary { cursor: pointer; font-size: 0.8125rem; color: var(--text-2); width: fit-content; }
.more[open] summary { margin-bottom: 0.5rem; }
.more-line { display: block; font-size: 0.75rem; color: var(--muted); padding: 0.125rem 0; overflow-wrap: anywhere; }
.more-line .mono { color: var(--text-2); }
</style>
