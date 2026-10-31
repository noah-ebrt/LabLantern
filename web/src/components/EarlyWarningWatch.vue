<script setup>
import { computed, onMounted, ref } from 'vue'
import { api } from '../api.js'

// Was ein System zur Frühwarnung beiträgt: die Stichwörter, die neue Meldungen erwähnen müssen
const props = defineProps({ systemId: { type: Number, required: true } })

const watched = ref(null)
const error = ref('')
onMounted(async () => {
  try {
    watched.value = await api.get(`/api/early-warnings/watched/${props.systemId}`)
  } catch (e) {
    error.value = e.message
  }
})

const groups = computed(() => {
  const out = {}
  for (const i of watched.value?.items || []) (out[i.group] ||= []).push(i)
  return Object.entries(out)
})
const hint = (i) => [i.product, i.version, i.title_only ? 'matched in advisory titles only' : 'matched in title and text']
  .filter(Boolean).join(' · ')
</script>

<template>
  <section>
    <h3>Watched by the early warning ({{ watched?.items?.length ?? '…' }})</h3>
    <p v-if="error" class="text-danger">{{ error }}</p>
    <template v-else-if="watched?.items">
      <p class="subtext">New advisories from {{ watched.feeds }} feeds are checked for these keywords; only a match goes to the AI.
        <template v-if="!watched.ai_configured"> No AI provider is set, so nothing is checked yet.</template></p>
      <p v-if="!watched.items.length" class="subtext">Nothing from this system yet.</p>
      <div v-for="[name, items] in groups" :key="name" class="group">
        <span class="label">{{ name }} ({{ items.length }})</span>
        <p class="chips">
          <span v-for="i in items" :key="`${i.keyword}|${i.product}`" class="chip mono" :title="hint(i)">
            {{ i.keyword }}<span v-if="i.version" class="ver">{{ i.version }}</span></span>
        </p>
      </div>
    </template>
  </section>
</template>

<style scoped>
h3 { margin-top: 1.25rem; }
.group { margin: 0.5rem 0; }
.label { font-size: 0.8125rem; color: var(--muted); }
.chips { display: flex; flex-wrap: wrap; gap: 0.25rem; margin: 0.25rem 0 0; }
.chip { font-size: 0.75rem; padding: 0.125rem 0.5rem; border: 1px solid var(--line); border-radius: var(--radius-pill); color: var(--text-2); }
.ver { margin-left: 0.5rem; color: var(--muted); }
</style>
