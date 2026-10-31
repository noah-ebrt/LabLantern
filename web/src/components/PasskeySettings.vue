<script setup>
import { computed, onMounted, ref } from 'vue'
import { api } from '../api.js'
import { fmtStamp, fmtDayOnly } from '../time.js'
import { useLive } from '../live.js'
import { createPasskey, passkeysSupported, usePasskey } from '../webauthn.js'
import Icon from './Icon.vue'
import SettingsCard from './SettingsCard.vue'
import SettingsEntry from './SettingsEntry.vue'
import SettingsList from './SettingsList.vue'
import SettingsSection from './SettingsSection.vue'

const info = ref(null)
const name = ref('')
const busy = ref(false)
const message = ref(null)
const supported = passkeysSupported()
const here = window.location
const wrongHost = computed(() => info.value?.rp_id && here.hostname !== info.value.rp_id)
const rpUrl = computed(() => `https://${info.value?.rp_id}${here.port ? ':' + here.port : ''}${here.pathname}`)

async function load() {
  info.value = await api.get('/api/passkeys')
}

async function run(fn, ok) {
  busy.value = true
  message.value = null
  try {
    await fn()
    await load()
    message.value = { kind: 'ok', text: ok }
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}

const add = () => run(async () => {
  const options = await api.post('/api/passkeys/register/options')
  const credential = await createPasskey(options)
  await api.post('/api/passkeys/register', { name: name.value.trim() || 'Passkey', credential })
  name.value = ''
}, 'Passkey added.')

const remove = (k) => {
  if (!confirm(`Remove passkey “${k.name}”? Agents keep trusting it until you sign the new key list.`)) return
  run(() => api.del(`/api/passkeys/${k.id}`), 'Passkey removed.')
}

const signTrust = () => run(async () => {
  const { options } = await api.post('/api/passkeys/trust/options')
  const credential = await usePasskey(options)
  await api.post('/api/passkeys/trust', { credential })
}, 'Key list signed. Agents pick it up within a minute.')

onMounted(load)
useLive(['settings'], load)
const status = computed(() => (!info.value ? null : info.value.trust.outdated ? { tone: 'warning', text: 'Key list to sign', target: 'set-trust' }
  : info.value.keys.length ? { tone: 'ok', text: `${info.value.keys.length} registered` } : { tone: 'warning', text: 'None yet', target: 'set-passkey-add' }))
</script>

<template>
  <SettingsCard icon="key" title="Passkeys" subtitle="Sign in, and confirm reboots and agent updates with a touch" :status="status">
    <template v-if="info">
      <p v-if="!info.rp_id" class="message error">
        Passkeys need a hostname. Add one (e.g. <code>vulnwatch.lan</code>) to <code>VULNWATCH_HOSTNAMES</code>, point it to this host in your DNS, and open the UI under that name.
      </p>
      <p v-else-if="wrongHost" class="message">
        Open the UI as <a :href="rpUrl">{{ rpUrl }}</a> to use passkeys; browsers do not allow them on an IP address.
      </p>
      <p v-else-if="!supported" class="message">This browser context does not support passkeys (a trusted HTTPS certificate is required).</p>

      <SettingsSection title="Registered" :count="info.keys.length"
                       :hint="info.trust.rev ? `Agents trust key list v${info.trust.rev}${info.trust.signed ? ', signed with a passkey' : ' (the first list, not yet signed)'}` : ''">
        <SettingsList :empty="!info.keys.length" empty-text="No passkey yet. The first one you add becomes the key list your agents trust.">
          <SettingsEntry v-for="k in info.keys" :key="k.id" icon="key" :title="k.name"
                         :meta="`added ${fmtDayOnly(k.created_at)} · ${k.last_used ? `last used ${fmtStamp(k.last_used)}` : 'never used'}`">
            <template #actions>
              <button class="btn-sm btn-delete" :disabled="busy" @click="remove(k)"><Icon name="trash" :size="14" />Remove</button>
            </template>
          </SettingsEntry>
        </SettingsList>
      </SettingsSection>

      <div v-if="info.trust.outdated" id="set-trust" class="notice">
        <span>Your agents still trust the previous key list (revision {{ info.trust.rev }}). Confirm the change with a passkey they already trust.</span>
        <button class="btn-sm primary" :disabled="busy || wrongHost" @click="signTrust">Sign key list</button>
      </div>

      <form id="set-passkey-add" class="settings-form add" @submit.prevent="add">
        <label class="add-name">
          <span class="field-label">Add a passkey</span>
          <input v-model="name" maxlength="60" placeholder="Name, e.g. YubiKey or iPhone" aria-label="Passkey name" />
        </label>
        <button type="submit" class="primary" :disabled="busy || !info.rp_id || wrongHost || !supported">
          <Icon name="plus" :size="15" />Add passkey
        </button>
      </form>
      <p v-if="message" class="message" :class="message.kind" role="status">{{ message.text }}</p>
    </template>
  </SettingsCard>
</template>

<style scoped>
.add { flex-direction: row; align-items: flex-end; gap: 0.6rem; flex-wrap: wrap; }
.add-name { flex: 1; min-width: 220px; }
.notice { justify-content: space-between; margin: 0; }
</style>
