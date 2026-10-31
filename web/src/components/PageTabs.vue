<script setup>
import { computed, nextTick, onMounted, ref, useId, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import Icon from './Icon.vue'

// Reiter einer Seite. Der Inhalt je Reiter kommt in den gleichnamigen Slot (<template #status>…).
// Mit `query` merkt sich die Adresse den Reiter (?tab=settings): Neu laden und Verweise landen am selben Ort.
const props = defineProps({
  tabs: { type: Array, required: true },        // [{ key, label, icon?, count?, tone? }]
  label: { type: String, default: 'Sections' },
  query: { type: String, default: 'tab' },      // '' = nicht in der Adresse
  modelValue: { type: String, default: '' },
})
const emit = defineEmits(['update:modelValue'])
const route = useRoute()
const router = useRouter()
const uid = useId()

const keys = computed(() => props.tabs.map((t) => t.key))
// Schmale Bildschirme: die Reiterleiste scrollt; ein Verlauf am Rand zeigt, dass rechts noch Reiter kommen
const list = ref(null)
const more = ref(false)
function measure() {
  const el = list.value
  if (el) more.value = el.scrollLeft + el.clientWidth < el.scrollWidth - 4
}
const active = computed(() => {
  const wanted = (props.query && route.query[props.query]) || props.modelValue
  return keys.value.includes(wanted) ? wanted : keys.value[0]
})

function select(key) {
  emit('update:modelValue', key)
  if (props.query) {
    const query = { ...route.query, [props.query]: key === keys.value[0] ? undefined : key }
    router.replace({ query })
  }
}

// Aktiver Reiter immer sichtbar, auch wenn er über einen Verweis gewählt wurde
watch(active, async (key) => {
  await nextTick()
  document.getElementById(`${uid}-tab-${key}`)?.scrollIntoView?.({ block: 'nearest', inline: 'nearest' })
  measure()
})
onMounted(measure)

// Pfeiltasten wie bei nativen Reitern: Fokus und Auswahl wandern gemeinsam
function onKey(e) {
  const i = keys.value.indexOf(active.value)
  const next = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: keys.value.length - 1 }[e.key]
  if (next === undefined) return
  e.preventDefault()
  const key = keys.value[(next + keys.value.length) % keys.value.length]
  select(key)
  document.getElementById(`${uid}-tab-${key}`)?.focus()
}
</script>

<template>
  <div class="page-tabs">
    <div ref="list" :class="['tablist', { more }]" role="tablist" :aria-label="label" @keydown="onKey" @scroll.passive="measure">
      <button v-for="t in tabs" :id="`${uid}-tab-${t.key}`" :key="t.key" type="button" role="tab"
              :class="['tab', { active: t.key === active }]" :aria-selected="t.key === active"
              :aria-controls="`${uid}-panel`" :tabindex="t.key === active ? 0 : -1" @click="select(t.key)">
        <Icon v-if="t.icon" :name="t.icon" :size="15" />
        {{ t.label }}
        <span v-if="t.count != null" :class="['count', t.tone]">{{ t.count }}</span>
      </button>
    </div>
    <div :id="`${uid}-panel`" class="tabpanel" role="tabpanel" :aria-labelledby="`${uid}-tab-${active}`">
      <slot :name="active" />
    </div>
  </div>
</template>

<style scoped>
.page-tabs { display: flex; flex-direction: column; gap: 1.25rem; }
.tablist {
  display: flex; gap: 0.25rem; border-bottom: 1px solid var(--line); overflow-x: auto; scrollbar-width: none;
}
.tablist.more { mask-image: linear-gradient(90deg, #000 calc(100% - 3rem), transparent); }
.tab {
  min-height: 40px; padding: 0.5rem 0.75rem; margin-bottom: -1px; border: 0; border-bottom: 2px solid transparent;
  border-radius: 0; background: transparent; color: var(--muted); white-space: nowrap; transition: color 0.15s, border-color 0.15s;
}
.tab:hover:not(:disabled) { background: transparent; border-color: transparent; border-bottom-color: var(--line-strong); color: var(--text-2); }
.tab.active, .tab.active:hover:not(:disabled) { color: var(--text); border-bottom-color: var(--text); }
.tab:active:not(:disabled) { transform: none; }
.tab:focus-visible { outline: 2px solid var(--text-2); outline-offset: -2px; border-radius: 6px 6px 0 0; }
.count { font: 0.6875rem var(--mono); color: var(--muted); padding: 0 0.5rem; border-radius: var(--radius-pill); background: var(--surface-2); }
.count.danger { color: var(--danger); background: color-mix(in srgb, var(--danger) 14%, transparent); }
.count.warning { color: var(--warn); background: color-mix(in srgb, var(--warn) 14%, transparent); }
.tabpanel { display: flex; flex-direction: column; gap: 1.5rem; min-width: 0; }
.tabpanel:focus-visible { outline: none; }
</style>
