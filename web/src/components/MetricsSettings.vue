<script setup>
import { computed, onMounted, ref } from 'vue'
import { api } from '../api.js'
import { fmtStamp } from '../time.js'
import Icon from './Icon.vue'
import SettingsCard from './SettingsCard.vue'
import SettingsEntry from './SettingsEntry.vue'
import SettingsList from './SettingsList.vue'

// /metrics für Prometheus (optional). Das Token gibt es genau einmal zu sehen; danach liegt nur sein Hash vor.
const state = ref(null)
const token = ref('')
const copied = ref(false)
const busy = ref(false)
const message = ref(null)
const endpoint = `${window.location.origin}/metrics`

async function load() {
  state.value = await api.get('/api/settings/metrics')
}

async function create() {
  if (state.value?.enabled && !confirm('Create a new token? Prometheus keeps failing until you put the new one into its config.')) return
  busy.value = true
  message.value = null
  try {
    token.value = (await api.post('/api/settings/metrics/token')).token
    await load()
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}

async function disable() {
  if (!confirm('Turn the metrics endpoint off? Prometheus scrapes then get 404.')) return
  await api.del('/api/settings/metrics')
  token.value = ''
  await load()
}

const scrape = computed(() => `- job_name: vulnwatch
  scheme: https
  metrics_path: /metrics
  authorization:
    credentials: ${token.value || '<token>'}
  tls_config:
    ca_file: /etc/prometheus/vulnwatch-ca.crt   # ${window.location.origin}/ca.crt
  static_configs:
    - targets: ['${window.location.host}']`)

async function copy() {
  try {
    await navigator.clipboard.writeText(scrape.value)
    copied.value = true
    setTimeout(() => (copied.value = false), 2500)
  } catch {
    message.value = { kind: 'error', text: 'Copying needs a secure context – select the text and copy it by hand.' }
  }
}

const status = computed(() => (!state.value ? null : state.value.enabled ? { tone: 'ok', text: 'Enabled' } : { tone: 'neutral', text: 'Off' }))
onMounted(load)
</script>

<template>
  <SettingsCard icon="activity" title="Prometheus metrics" subtitle="Findings, coverage, agents, runs and certificates as a /metrics endpoint for Prometheus and Grafana" :status="status">
    <template v-if="state">
      <SettingsList :empty="!state.enabled" empty-text="Off. Creating a token turns /metrics on; Prometheus scrapes it with that token.">
        <SettingsEntry icon="link" :title="endpoint" mono :meta="`Bearer token created ${fmtStamp(state.created_at)} · only its hash is stored`">
          <template #actions>
            <button type="button" class="btn-sm" :disabled="busy" @click="create"><Icon name="refresh" :size="14" />New token</button>
            <button type="button" class="btn-sm btn-delete" :disabled="busy" @click="disable"><Icon name="trash" :size="14" />Turn off</button>
          </template>
        </SettingsEntry>
        <template #empty>
          <button type="button" class="btn-sm" :disabled="busy" @click="create"><Icon name="plus" :size="14" />Create token</button>
        </template>
      </SettingsList>

      <div v-if="token" class="cmd-block">
        <div class="cmd-bar-top">
          <span class="mono">prometheus.yml · the token is shown only now</span>
          <button class="btn-sm" @click="copy"><Icon :name="copied ? 'check' : 'copy'" :size="14" />{{ copied ? 'Copied' : 'Copy' }}</button>
        </div>
        <pre class="cmd-text">{{ scrape }}</pre>
      </div>
      <p v-if="message" class="message" :class="message.kind" role="status">{{ message.text }}</p>
    </template>
  </SettingsCard>
</template>

<style scoped>
.cmd-block { border: 1px solid var(--line-strong); border-radius: var(--radius-sm); background: var(--ground); overflow: hidden; }
.cmd-bar-top { display: flex; justify-content: space-between; align-items: center; padding: 0.35rem 0.5rem 0.35rem 0.8rem; border-bottom: 1px solid var(--line); color: var(--muted); font-size: 0.75rem; }
.cmd-text { margin: 0; padding: 0.75rem 0.85rem; overflow: auto; font: 0.76rem/1.55 var(--mono); color: var(--text-2); white-space: pre; }
</style>
