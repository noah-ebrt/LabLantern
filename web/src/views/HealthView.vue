<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../api.js'
import { useLive } from '../live.js'
import HealthApiSettings from '../components/HealthApiSettings.vue'
import HealthMonitorsSettings from '../components/HealthMonitorsSettings.vue'
import HealthStatus from '../components/HealthStatus.vue'
import PageHeader from '../components/PageHeader.vue'
import PageTabs from '../components/PageTabs.vue'

// Gesundheit: Erreichbarkeit aller Hosts (Agenten automatisch, weitere von Hand) mit Verlauf, Einstellungen und API
const router = useRouter()
const data = ref(null)
const options = ref(null)
const error = ref('')
const refresh = ref(0)

async function load() {
  try {
    const [d, o] = await Promise.all([api.get('/api/health/overview'), api.get('/api/health/options')])
    data.value = d
    options.value = o
    refresh.value++
    error.value = ''
  } catch (e) {
    error.value = e.message
  }
}

useLive(['health', 'systems', 'settings'], load)
// Messwerte (Latenz, Alter) ändern sich ohne Zustandswechsel: solange die Seite sichtbar ist, alle 20 s nachladen
let timer = null
onMounted(() => {
  load()
  timer = setInterval(() => { if (document.visibilityState === 'visible') load() }, 20000)
})
onBeforeUnmount(() => clearInterval(timer))

const problems = computed(() => (data.value ? data.value.summary.down + data.value.summary.degraded : null))
const tabs = computed(() => [
  { key: 'status', label: 'Status', icon: 'activity', count: problems.value || null, tone: data.value?.summary.down ? 'danger' : 'warning' },
  { key: 'settings', label: 'Settings', icon: 'settings' },
])
</script>

<template>
  <div class="health-page">
    <PageHeader title="Health" subtitle="Uptime and response times of your hosts and services – agent hosts are watched automatically" />
    <p v-if="error" class="message error">{{ error }}</p>
    <PageTabs v-if="data" :tabs="tabs" label="Health sections">
      <template #status>
        <HealthStatus :data="data" :refresh="refresh" @configure="router.replace({ query: { tab: 'settings' } })" />
      </template>
      <template #settings>
        <HealthMonitorsSettings :monitors="data.monitors" :options="options" @changed="load" />
        <HealthApiSettings :monitors="data.monitors" />
      </template>
    </PageTabs>
  </div>
</template>

<style scoped>
.health-page { display: flex; flex-direction: column; gap: 1.25rem; }
</style>
