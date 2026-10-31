<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api.js'
import { checkClass, label } from '../labels.js'
import Modal from './Modal.vue'

// Was hinter einer Zeile "Exposure source" steht: erreichbare Stellen mit Begründung und was nicht zuzuordnen war
const props = defineProps({ source: { type: Object, required: true } })
const emit = defineEmits(['close'])

const ANCHORS = { npm: 'set-npm', fritzbox: 'set-fritz', cftunnel: 'set-cf', traefik: 'set-traefik' }
const detail = ref(null)
const address = (url) => url.replace(/^https?:\/\//, '').replace(/\/$/, '')
const error = ref('')
onMounted(async () => {
  try {
    detail.value = await api.get(`/api/overview/exposure/${props.source.key}`)
  } catch (e) {
    error.value = e.message
  }
})
</script>

<template>
  <Modal size="lg" :label="`Exposure source ${source.label}`" @close="emit('close')">
    <h2>{{ source.label }}</h2>
    <p class="subtitle">
      <span :class="checkClass(source.status)">{{ label(source.status) }}</span> {{ source.detail }}
    </p>
    <p v-if="error" class="message error" role="alert">{{ error }}</p>
    <div v-else-if="!detail" class="empty">Loading…</div>
    <template v-else>
      <p v-if="detail.host" class="host" data-test="exposure-host">
        Runs on
        <RouterLink v-if="detail.host.system_id" class="strong" :to="{ path: '/systeme', query: { open: String(detail.host.system_id) } }" @click="emit('close')">{{ detail.host.system_name }}</RouterLink>
        <span v-if="detail.host.ip" class="mono">{{ detail.host.ip }}</span>
        · management
        <a class="mono" :href="detail.host.url" target="_blank" rel="noopener noreferrer">{{ address(detail.host.url) }} ↗</a>
      </p>
      <h3>Internet-exposed ({{ detail.items.length }})</h3>
      <table v-if="detail.items.length" class="data-table" data-test="exposure-items">
        <thead><tr><th>System</th><th>Container</th><th>Via</th></tr></thead>
        <tbody>
          <tr v-for="i in detail.items" :key="`${i.system_id}/${i.name}`">
            <td class="strong">{{ i.system_name }}</td>
            <td class="mono">{{ i.name === '(host)' ? 'host itself' : i.name }}</td>
            <td><span v-for="v in i.via" :key="v" class="mono via">{{ v }}</span></td>
          </tr>
        </tbody>
      </table>
      <p v-else class="empty">Nothing from this source is reachable from the internet.</p>

      <h3>Not matched ({{ detail.unmatched_items.length }})</h3>
      <template v-if="detail.unmatched_items.length">
        <p class="subtext">These could not be tied to a container; mark them on the host if they belong to one.</p>
        <table class="data-table" data-test="exposure-unmatched">
          <thead><tr><th>Entry</th><th>Why</th></tr></thead>
          <tbody>
            <tr v-for="u in detail.unmatched_items" :key="u.what">
              <td class="mono">{{ u.what }}</td>
              <td>{{ u.why }}</td>
            </tr>
          </tbody>
        </table>
      </template>
      <p v-else class="empty">Everything was matched.</p>
    </template>
    <template #actions>
      <RouterLink class="btn-link" :to="`/einstellungen?tab=exposure#${ANCHORS[source.key] || ''}`" @click="emit('close')">Settings</RouterLink>
    </template>
  </Modal>
</template>

<style scoped>
.via { display: block; overflow-wrap: anywhere; }
.host { display: flex; flex-wrap: wrap; gap: 0 .5em; align-items: baseline; }
</style>
