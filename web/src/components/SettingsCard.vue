<script setup>
import { reveal } from '../reveal.js'
import Icon from './Icon.vue'

// Rahmen aller Karten in den Einstellungen: Titel mit Symbol und Status, eine Zeile Zweck, Aktionen rechts.
// Leicht wie die Panels der Übersicht: kein Symbol-Kasten, kleine Abstände.
defineProps({
  icon: { type: String, default: '' },
  title: { type: String, required: true },
  subtitle: { type: String, default: '' },
  status: { type: Object, default: null },   // { tone: ok|warning|danger|neutral, text, target? } – Zustand der ganzen Karte
})
</script>

<template>
  <section class="card settings-card">
    <header class="head">
      <div class="head-text">
        <div class="title-row">
          <Icon v-if="icon" :name="icon" :size="16" class="title-icon" />
          <h2>{{ title }}</h2>
          <!-- Badge mit target: Klick öffnet das Element mit dieser id (auch ein <details>) und scrollt dorthin -->
          <a v-if="status?.target" :href="`#${status.target}`" :class="['badge', 'badge-link', status.tone]" title="Show details"
             @click.prevent="reveal(status.target)">{{ status.text }}</a>
          <span v-else-if="status" :class="['badge', status.tone]">{{ status.text }}</span>
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
.settings-card { display: flex; flex-direction: column; gap: 1rem; margin-bottom: 0; scroll-margin-top: 5rem; }
.head { display: flex; align-items: flex-start; justify-content: space-between; gap: 0.6rem 1rem; flex-wrap: wrap; }
.head-text { flex: 1; min-width: min(100%, 240px); }
.title-row { display: flex; align-items: center; gap: 0.55rem; flex-wrap: wrap; }
.title-icon { color: var(--muted); flex: none; }
.title-row h2 { margin: 0; font-size: 1rem; }
.subtitle { margin: 0.2rem 0 0; font-size: 0.84rem; max-width: 75ch; }
.badge-link { text-decoration: none; }
.badge-link:hover { text-decoration: underline; text-underline-offset: 2px; }
/* Erklärung zur Karte: schlichter Text unter dem Kopf, nie ein eigener Kasten */
.intro { margin: -0.4rem 0 0; max-width: 75ch; font-size: 0.82rem; line-height: 1.55; color: var(--muted); }
.intro :deep(code) { font-size: 0.78rem; color: var(--text-2); }
.settings-card :deep(.subtext) { max-width: 75ch; }
.head-actions { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
</style>
