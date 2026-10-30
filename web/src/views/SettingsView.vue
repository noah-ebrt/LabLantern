<script setup>
import ScheduleSettings from '../components/ScheduleSettings.vue'
import NotificationSettings from '../components/NotificationSettings.vue'
import AiSettings from '../components/AiSettings.vue'
import ReleaseSettings from '../components/ReleaseSettings.vue'
import WatchdogSettings from '../components/WatchdogSettings.vue'
import PasskeySettings from '../components/PasskeySettings.vue'
import ConfigJsonSettings from '../components/ConfigJsonSettings.vue'
import DropAlarmSettings from '../components/DropAlarmSettings.vue'
import ProductsSettings from '../components/ProductsSettings.vue'
import MetricsSettings from '../components/MetricsSettings.vue'
import PageHeader from '../components/PageHeader.vue'
import PageTabs from '../components/PageTabs.vue'

// Reiter statt einer langen Seite; ?tab= in der Adresse, damit Verweise (z. B. aus „Health“) direkt hinführen
const TABS = [
  { key: 'general', label: 'Scans & alerts', icon: 'clock' },
  { key: 'notifications', label: 'Notifications', icon: 'bell' },
  { key: 'integrations', label: 'Integrations', icon: 'link' },
  { key: 'access', label: 'Access & agents', icon: 'lock' },
  { key: 'advanced', label: 'Advanced', icon: 'settings' },
]
</script>

<template>
  <div class="settings-page">
    <PageHeader title="Settings" subtitle="Scan schedule, alert notifications, integrations, passkeys and agent releases" />

    <PageTabs :tabs="TABS" label="Settings sections">
      <template #general>
        <!-- Täglicher Lauf, Offsite-Wächter, Sofort-Alarm bei starkem Rückgang der Funde -->
        <ScheduleSettings />
        <WatchdogSettings />
        <DropAlarmSettings />
      </template>
      <template #notifications>
        <NotificationSettings />
      </template>
      <template #integrations>
        <!-- Produktstände, Internet-Erreichbarkeit (NPM, FRITZ!Box, Cloudflare, Traefik) und KI -->
        <ProductsSettings />
        <AiSettings />
      </template>
      <template #access>
        <PasskeySettings />
        <ReleaseSettings />
        <MetricsSettings />
      </template>
      <template #advanced>
        <!-- Alles in einem Dokument: für Fortgeschrittene -->
        <ConfigJsonSettings />
      </template>
    </PageTabs>
  </div>
</template>

<style scoped>
.settings-page { display: flex; flex-direction: column; gap: 1.25rem; }
</style>
