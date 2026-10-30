<script setup>
// Kopf einer Seite: Titel, Untertitel, Aktionen rechts (z. B. „Add host“)
defineProps({
  title: { type: String, required: true },
  subtitle: { type: String, default: '' },
})
</script>

<template>
  <div class="header-row page-header">
    <div>
      <h1>{{ title }}</h1>
      <p v-if="subtitle || $slots.subtitle" class="subtitle"><slot name="subtitle">{{ subtitle }}</slot></p>
    </div>
    <div v-if="$slots.actions"><slot name="actions" /></div>
  </div>
</template>

<style scoped>
.page-header { margin-bottom: 0; }
</style>
