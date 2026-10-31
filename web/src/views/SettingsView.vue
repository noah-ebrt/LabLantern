<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useLive } from '../live.js'
import { reveal } from '../reveal.js'
import { OLD_TABS, SETTINGS_TABS } from '../settingsIndex.js'
import { loadSettingsSummary } from '../settingsSummary.js'
import ScheduleSettings from '../components/ScheduleSettings.vue'
import VersionCheckSettings from '../components/VersionCheckSettings.vue'
import NotificationSettings from '../components/NotificationSettings.vue'
import ReportSettings from '../components/ReportSettings.vue'
import WatchdogSettings from '../components/WatchdogSettings.vue'
import DropAlarmSettings from '../components/DropAlarmSettings.vue'
import ExposureSettings from '../components/ExposureSettings.vue'
import AiSettings from '../components/AiSettings.vue'
import AiLevelSettings from '../components/AiLevelSettings.vue'
import PasskeySettings from '../components/PasskeySettings.vue'
import ReleaseSettings from '../components/ReleaseSettings.vue'
import MetricsSettings from '../components/MetricsSettings.vue'
import ConfigJsonSettings from '../components/ConfigJsonSettings.vue'
import PageHeader from '../components/PageHeader.vue'
import PageTabs from '../components/PageTabs.vue'
import SettingsFinder from '../components/SettingsFinder.vue'

// Reiter nach dem, was man erledigen will; ?tab= und #ziel in der Adresse, damit Verweise direkt an die Stelle führen
const route = useRoute()
const router = useRouter()
const summary = ref(null)

async function load() {
  summary.value = await loadSettingsSummary()
}
onMounted(load)
useLive(['settings'], load, 3000)

// Probleme je Reiter als Zähler am Reiter, wie auf der Health-Seite
const tabs = computed(() => SETTINGS_TABS.map((t) => {
  const p = summary.value?.problems[t.key] || []
  return { ...t, count: p.length || null, tone: p.some((x) => x.tone === 'danger') ? 'danger' : 'warning' }
}))

watch(() => route.query.tab, (tab) => {
  if (OLD_TABS[tab]) router.replace({ query: { ...route.query, tab: OLD_TABS[tab] }, hash: route.hash })
}, { immediate: true })
watch(() => route.hash, (hash) => { if (hash) reveal(decodeURIComponent(hash.slice(1))) }, { immediate: true })

const linkTo = (it) => ({ query: { ...route.query, tab: it.tab === SETTINGS_TABS[0].key ? undefined : it.tab }, hash: `#${it.target}` })

// Gleiches Ziel zweimal: die Adresse ändert sich nicht, also direkt springen
function go(it) {
  if (route.hash === `#${it.target}` && (route.query.tab || SETTINGS_TABS[0].key) === it.tab) reveal(it.target)
  else router.replace(linkTo(it))
}
</script>

<template>
  <div class="settings-page">
    <PageHeader title="Settings">
      <template #actions><SettingsFinder @go="go" /></template>
    </PageHeader>

    <nav v-if="summary?.items.length" class="card summary" aria-label="Settings at a glance">
      <template v-for="(it, i) in summary.items" :key="it.label">
        <span v-if="i" class="sep" aria-hidden="true" />
        <a :href="router.resolve(linkTo(it)).href" class="sum-item" @click.prevent="go(it)">
          {{ it.label }} <strong :class="{ 'text-danger': it.tone === 'danger', 'text-warn': it.tone === 'warning' }">{{ it.value }}</strong>
        </a>
      </template>
    </nav>

    <PageTabs :tabs="tabs" label="Settings sections">
      <template #scanning>
        <ScheduleSettings id="set-schedule" />
        <VersionCheckSettings id="set-versions" />
      </template>
      <template #alerts>
        <!-- Wer was wann erfährt: Kanäle, Bericht, Wächter von außen, zusätzliche Alarmregeln -->
        <NotificationSettings id="set-channels" />
        <ReportSettings id="set-report-card" />
        <WatchdogSettings id="set-watchdog" />
        <DropAlarmSettings id="set-alert-rules" />
      </template>
      <template #exposure>
        <ExposureSettings id="set-exposure" />
      </template>
      <template #ai>
        <AiSettings id="set-ai-provider" />
        <AiLevelSettings id="set-ai" />
      </template>
      <template #system>
        <PasskeySettings id="set-passkeys" />
        <ReleaseSettings id="set-release" />
        <MetricsSettings id="set-metrics" />
        <ConfigJsonSettings id="set-config-card" />
      </template>
    </PageTabs>
  </div>
</template>

<style scoped>
.settings-page { display: flex; flex-direction: column; gap: 1rem; }
.settings-page :deep(.page-header) { align-items: center; }
/* Abstände wie auf der Übersicht */
.settings-page :deep(.tabpanel) { gap: 1rem; }
.summary { display: flex; align-items: center; flex-wrap: wrap; gap: 0.4rem 0.5rem; padding: 0.7rem 1.1rem; margin: 0; font-size: 0.85rem; }
.sum-item { color: var(--muted); text-decoration: none; border-radius: 6px; padding: 0.1rem 0.15rem; }
.sum-item strong { color: var(--text); font-weight: 500; }
.sum-item strong.text-warn { color: var(--warn); }
.sum-item strong.text-danger { color: var(--crit); }
.sum-item:hover strong { text-decoration: underline; text-underline-offset: 3px; text-decoration-color: var(--line-strong); }
.sum-item:focus-visible { outline: 2px solid var(--text-2); outline-offset: 2px; }
.sep { width: 1px; height: 14px; background: var(--line-strong); margin: 0 0.3rem; }
@media (max-width: 640px) {
  .sep { display: none; }
  .summary { gap: 0.35rem 1rem; }
}
</style>
