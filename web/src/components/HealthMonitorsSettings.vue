<script setup>
import { computed, ref } from 'vue'
import { api } from '../api.js'
import { KINDS } from '../health.js'
import HealthMonitorForm from './HealthMonitorForm.vue'
import Icon from './Icon.vue'
import Modal from './Modal.vue'
import SettingsCard from './SettingsCard.vue'
import SettingsEntry from './SettingsEntry.vue'
import SettingsList from './SettingsList.vue'
import SettingsSection from './SettingsSection.vue'
import StateBadge from './StateBadge.vue'

// Reiter „Settings“: überwachte Hosts verwalten. Agenten-Hosts kommen von selbst, eigene Hosts per Generator.
const props = defineProps({ monitors: { type: Array, required: true }, options: { type: Object, required: true } })
const emit = defineEmits(['changed'])
const editing = ref(undefined)   // undefined = zu, null = neu, Objekt = bearbeiten
const message = ref(null)
const beat = ref(null)

const agents = computed(() => props.monitors.filter((m) => m.auto))
const manual = computed(() => props.monitors.filter((m) => !m.auto))
const meta = (m) => [`${m.host || 'no host'} · API key ${m.slug}`, m.checks.map((c) => c.label).join(' · ') || 'no checks']

function saved() {
  editing.value = undefined
  emit('changed')
}
async function pause(m) {
  await api.post(`/api/health/monitors/${m.id}/pause`, { paused: !m.paused })
  emit('changed')
}
async function remove(m) {
  if (!confirm(`Stop monitoring ${m.name}? Its history is deleted too.`)) return
  try {
    await api.del(`/api/health/monitors/${m.id}`)
    emit('changed')
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  }
}
async function newBeat(m) {
  const c = m.checks.find((x) => x.kind === 'heartbeat')
  if (!confirm('Create a new heartbeat address? The old one stops working.')) return
  const r = await api.post(`/api/health/checks/${c.id}/heartbeat-token`)
  beat.value = `${window.location.origin}/api/health/beat/${r.token}`
}
const fritzStatus = computed(() => (props.options.fritz ? { tone: 'ok', text: 'Connected' } : { tone: 'neutral', text: 'Optional · not set up' }))
</script>

<template>
  <SettingsCard icon="systems" title="Monitored hosts" subtitle="What vulnwatch checks, how often, and when a host counts as down"
                :status="{ tone: 'neutral', text: `${monitors.length} hosts` }">
    <template #actions>
      <button type="button" class="btn-sm" @click="editing = null"><Icon name="plus" :size="14" />Add host</button>
    </template>
    <template #intro>
      Everything under Systems is watched automatically. Agents: their live connection plus a ping. Devices without an agent
      (TrueNAS, Home Assistant and other connectors): a ping plus the address vulnwatch reads them from. If an agent goes silent
      while the ping still answers, the host stays up with a warning. Add other devices (router, printers, phones) with their own checks.
    </template>

    <SettingsSection title="From Systems" :count="agents.length" hint="added and removed with the agent or connector">
      <SettingsList :empty="!agents.length" empty-text="Nothing under Systems yet. Approved agents and connected devices (TrueNAS, Home Assistant) appear here on their own.">
        <SettingsEntry v-for="m in agents" :key="m.id" :icon="m.source === 'connector' ? 'package' : 'shield'" :title="m.name" :meta="meta(m)">
          <template #badge><StateBadge :state="m.state" /><span class="badge neutral">{{ m.source === 'connector' ? 'Connector' : 'Agent' }}</span><span v-if="m.critical" class="badge warning">Critical</span></template>
          <template #actions>
            <button type="button" class="btn-sm" @click="editing = m"><Icon name="settings" :size="14" />Checks</button>
            <button type="button" class="btn-sm" @click="pause(m)">{{ m.paused ? 'Resume' : 'Pause' }}</button>
          </template>
        </SettingsEntry>
      </SettingsList>
    </SettingsSection>

    <SettingsSection title="Other hosts and services" :count="manual.length">
      <SettingsList :empty="!manual.length" empty-text="Nothing added yet – e.g. a NAS, the router, a DNS server or a phone.">
        <SettingsEntry v-for="m in manual" :key="m.id" icon="activity" :title="m.name" :meta="meta(m)">
          <template #badge><StateBadge :state="m.state" /><span v-if="m.critical" class="badge warning">Critical</span></template>
          <template #actions>
            <button type="button" class="btn-sm" @click="editing = m"><Icon name="settings" :size="14" />Edit</button>
            <button v-if="m.checks.some((c) => c.kind === 'heartbeat')" type="button" class="btn-sm" @click="newBeat(m)"><Icon name="key" :size="14" />Heartbeat URL</button>
            <button type="button" class="btn-sm" @click="pause(m)">{{ m.paused ? 'Resume' : 'Pause' }}</button>
            <button type="button" class="btn-sm btn-delete" @click="remove(m)"><Icon name="trash" :size="14" />Remove</button>
          </template>
        </SettingsEntry>
        <template #empty>
          <button type="button" class="btn-sm" @click="editing = null"><Icon name="plus" :size="14" />Add host</button>
        </template>
      </SettingsList>
    </SettingsSection>
    <div v-if="beat" class="cmd-block">
      <div class="cmd-bar-top"><span>New heartbeat address · shown only now</span><button type="button" class="btn-sm" @click="beat = null"><Icon name="x" :size="14" /></button></div>
      <pre class="cmd-text">curl -fsS {{ beat }}</pre>
    </div>
    <p v-if="message" class="message" :class="message.kind" role="status">{{ message.text }}</p>
  </SettingsCard>

  <SettingsCard icon="link" title="Router checks" subtitle="FRITZ!Box: device presence and internet status" :status="fritzStatus">
    <p class="text">
      With the FRITZ!Box connector, two more checks are offered: <b>{{ KINDS.fritz_host.label }}</b> asks the router whether it
      currently sees a device (by MAC or IP), which also catches phones and laptops that ignore ping in Wi-Fi power save, and
      <b>{{ KINDS.fritz_wan.label }}</b> reports whether the internet connection is actually up. If the FRITZ!Box itself
      cannot be reached, these checks show “unknown” instead of “down”.
    </p>
    <p class="text">
      <RouterLink to="/einstellungen?tab=exposure#set-fritz">{{ options.fritz ? 'Change the connector' : 'Set up the connector' }} under Settings → Exposure</RouterLink>.
      Use a separate FRITZ!Box user with the right “FRITZ!Box settings”; vulnwatch only reads.
    </p>
  </SettingsCard>

  <Modal v-if="editing !== undefined" :label="editing ? `Edit ${editing.name}` : 'Add a host'" size="lg" :footer="false" @close="editing = undefined">
    <HealthMonitorForm :monitor="editing" :options="options" @saved="saved" @cancel="editing = undefined" />
  </Modal>
</template>

<style scoped>
.text { margin: 0; max-width: 78ch; font-size: 0.875rem; line-height: 1.55; color: var(--muted); }
.text b { color: var(--text-2); font-weight: 500; }
.cmd-block { border: 1px solid var(--line-strong); border-radius: var(--radius-sm); background: var(--ground); overflow: hidden; }
.cmd-bar-top { display: flex; justify-content: space-between; align-items: center; padding: 0.25rem 0.5rem 0.25rem 0.75rem; border-bottom: 1px solid var(--line); color: var(--muted); font-size: 0.75rem; }
.cmd-text { margin: 0; padding: 0.75rem; overflow: auto; font: 0.75rem/1.55 var(--mono); color: var(--text-2); white-space: pre; }
</style>
