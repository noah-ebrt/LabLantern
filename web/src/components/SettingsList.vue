<script setup>
// Eingelassene Liste konfigurierter Einträge (SettingsEntry). Ohne Einträge: gestrichelter Leerzustand.
defineProps({
  empty: { type: Boolean, default: false },
  emptyText: { type: String, default: 'Nothing configured yet.' },
  label: { type: String, default: '' },
})
</script>

<template>
  <div v-if="empty" class="settings-empty">
    <p>{{ emptyText }}</p>
    <slot name="empty" />
  </div>
  <ul v-else class="settings-list" :aria-label="label || undefined"><slot /></ul>
</template>

<style scoped>
.settings-list { list-style: none; margin: 0; padding: 0; border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--ground); }
.settings-empty {
  display: flex; flex-direction: column; align-items: flex-start; gap: 0.75rem; padding: 1rem;
  border: 1px dashed var(--line-strong); border-radius: var(--radius-sm); color: var(--muted); font-size: 0.875rem;
}
.settings-empty p { margin: 0; }
</style>
