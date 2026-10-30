<script setup>
import Icon from './Icon.vue'

// Rahmen aller Karten in den Einstellungen: Symbol, Titel mit Status, Untertitel, Aktionen rechts
defineProps({
  icon: { type: String, required: true },
  title: { type: String, required: true },
  subtitle: { type: String, default: '' },
  status: { type: Object, default: null },   // { tone: ok|warning|danger|neutral, text } – Zustand der ganzen Karte
})
</script>

<template>
  <section class="card settings-card">
    <header class="head">
      <span class="icon-bubble"><Icon :name="icon" :size="20" /></span>
      <div class="head-text">
        <div class="title-row">
          <h2>{{ title }}</h2>
          <span v-if="status" :class="['badge', status.tone]">{{ status.text }}</span>
          <slot name="badge" />
        </div>
        <p v-if="subtitle" class="subtitle">{{ subtitle }}</p>
      </div>
      <div v-if="$slots.actions" class="head-actions"><slot name="actions" /></div>
    </header>
    <p v-if="$slots.intro" class="intro"><slot name="intro" /></p>
    <slot />
  </section>
</template>

<style scoped>
.settings-card { display: flex; flex-direction: column; gap: 1.25rem; }
.head { display: flex; align-items: center; gap: 0.9rem; flex-wrap: wrap; }
.head-text { flex: 1; min-width: 220px; }
.title-row { display: flex; align-items: center; gap: 0.65rem; flex-wrap: wrap; }
.title-row h2 { margin: 0; font-size: 1.1rem; }
.subtitle { margin: 0.2rem 0 0; }
/* Erklärung zur Karte: schlichter Text unter dem Kopf, nie ein eigener Kasten */
.intro { margin: -0.4rem 0 0; max-width: 78ch; font-size: 0.86rem; line-height: 1.55; color: var(--muted); }
.intro :deep(code) { font-size: 0.8rem; color: var(--text-2); }
.icon-bubble {
  display: flex; align-items: center; justify-content: center; flex-shrink: 0;
  width: 40px; height: 40px; border-radius: var(--radius-sm);
  background: var(--surface-2); border: 1px solid var(--line-strong); color: var(--text);
}
.head-actions { display: flex; gap: 0.6rem; align-items: center; flex-wrap: wrap; }
</style>
