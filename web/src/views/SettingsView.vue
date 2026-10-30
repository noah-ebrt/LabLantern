<script setup>
import ScheduleSettings from '../components/ScheduleSettings.vue'
import NotificationSettings from '../components/NotificationSettings.vue'
import AiSettings from '../components/AiSettings.vue'
import AiLevelSettings from '../components/AiLevelSettings.vue'
import ReleaseSettings from '../components/ReleaseSettings.vue'
import WatchdogSettings from '../components/WatchdogSettings.vue'
import PasskeySettings from '../components/PasskeySettings.vue'
import ConfigJsonSettings from '../components/ConfigJsonSettings.vue'
import DropAlarmSettings from '../components/DropAlarmSettings.vue'
import ProductsSettings from '../components/ProductsSettings.vue'
import MetricsSettings from '../components/MetricsSettings.vue'
</script>

<template>
  <div class="settings-page">
    <div class="header-row">
      <div>
        <h1>Settings</h1>
        <p class="subtitle">Scan schedule, alert notifications, passkeys, AI integration, and agent releases</p>
      </div>
    </div>

    <div class="settings-stack">
      <!-- 1. Daily automated scan with dominant toggle switch -->
      <ScheduleSettings />

      <!-- 2. Notification channels list with collapsible add channel form -->
      <NotificationSettings />

      <!-- Offsite-Wächter: Healthchecks außer Haus alarmiert, wenn vulnwatch verstummt -->
      <WatchdogSettings />

      <!-- Produktstände und Internet-Erreichbarkeit (NPM) -->
      <ProductsSettings />

      <!-- Sofort-Alarm bei starkem Rückgang der Funde -->
      <DropAlarmSettings />

      <!-- 3. AI Early Warning Integration -->
      <AiSettings />
      <AiLevelSettings />

      <!-- Passkeys: Login und Bestätigung gefährlicher Befehle -->
      <PasskeySettings />

      <!-- 4. Fleet Agent Distribution -->
      <ReleaseSettings />

      <!-- Prometheus (optional) -->
      <MetricsSettings />

      <!-- Alles in einem Dokument, zuletzt: für Fortgeschrittene -->
      <ConfigJsonSettings />
    </div>
  </div>
</template>

<style scoped>
.settings-page {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

.settings-stack {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}
</style>
