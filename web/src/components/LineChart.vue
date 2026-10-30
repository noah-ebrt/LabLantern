<script setup>
import { computed, ref } from 'vue'

// Linienverlauf (SVG) für die Verlaufsseite.
// points: [{ label, title, extra }] je x-Wert; series: [{ key, label, color, values: [Zahl|null] }]
// Fehlende Werte (null) bleiben Lücken; einzelne Messpunkte erscheinen als Punkt.
const props = defineProps({
  points: { type: Array, required: true },
  series: { type: Array, required: true },
  unit: { type: String, default: '' },
  max: { type: Number, default: null },     // feste Obergrenze (z. B. 100 für Prozent)
  legend: { type: Boolean, default: false },
  digits: { type: Number, default: 0 },
})
const W = 1000
const H = 300
const hover = ref(null)

const top = computed(() => {
  if (props.max) return props.max
  const m = Math.max(...props.series.flatMap((s) => s.values.filter((v) => v != null)), 0)
  if (m <= 0) return 1
  const step = Math.pow(10, Math.floor(Math.log10(m)))
  // feine Stufen, damit die Achse knapp über dem Maximum endet (582 -> 600, nicht 1 000)
  return [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10].map((f) => f * step).find((v) => v >= m)
})
const x = (i) => (props.points.length < 2 ? W / 2 : (i / (props.points.length - 1)) * W)
const y = (v) => H - (v / top.value) * H
// Zusammenhängende Abschnitte ohne Lücke, je Reihe
const paths = computed(() => props.series.map((s) => {
  const runs = []
  let cur = []
  s.values.forEach((v, i) => {
    if (v == null) {
      if (cur.length) runs.push(cur)
      cur = []
    } else cur.push([x(i), y(v)])
  })
  if (cur.length) runs.push(cur)
  return {
    ...s,
    lines: runs.filter((r) => r.length > 1).map((r) => r.map(([a, b]) => `${a.toFixed(1)},${b.toFixed(1)}`).join(' ')),
    dots: runs.filter((r) => r.length === 1).map((r) => r[0]),   // allein stehende Werte
  }
}))
const fmt = (v) => (v == null ? '–' : `${Number(v).toLocaleString('en-GB', { maximumFractionDigits: props.digits })}${props.unit}`)
const ticks = computed(() => [top.value, top.value / 2, 0])
const xTicks = computed(() => {
  const n = props.points.length
  if (!n) return []
  const idx = n < 3 ? [...Array(n).keys()] : [0, Math.floor((n - 1) / 2), n - 1]
  return idx.map((i) => ({ i, left: `${(x(i) / W) * 100}%`, text: props.points[i].label }))
})
// Tooltip neben dem Punkt, an den Rändern nach innen geklappt
const tipStyle = computed(() => {
  if (hover.value == null) return {}
  const pct = (x(hover.value) / W) * 100
  if (pct > 65) return { left: `${pct}%`, transform: 'translateX(calc(-100% - 10px))' }
  return { left: `${pct}%`, transform: 'translateX(10px)' }
})
</script>

<template>
  <div class="line-chart">
    <p v-if="legend" class="legend">
      <span v-for="s in series" :key="s.key"><i :style="{ background: s.color }" />{{ s.label }}</span>
    </p>
    <div class="frame">
      <div class="y-axis" aria-hidden="true"><span v-for="t in ticks" :key="t">{{ fmt(t) }}</span></div>
      <div class="plot" @mouseleave="hover = null">
        <svg :viewBox="`0 0 ${W} ${H}`" preserveAspectRatio="none" role="img"
             :aria-label="series.map((s) => `${s.label}: ${s.values.filter((v) => v != null).map(fmt).join(', ')}`).join('; ')">
          <line v-for="t in ticks" :key="t" x1="0" :x2="W" :y1="y(t)" :y2="y(t)" class="grid" />
          <line v-if="hover != null" :x1="x(hover)" :x2="x(hover)" y1="0" :y2="H" class="guide" />
          <template v-for="s in paths" :key="s.key">
            <polyline v-for="(l, k) in s.lines" :key="k" :points="l" :style="{ stroke: s.color }" />
          </template>
        </svg>
        <!-- Punkte als HTML: bleiben rund, obwohl die Fläche gestreckt wird -->
        <template v-for="s in paths" :key="`d-${s.key}`">
          <i v-for="([px, py], k) in s.dots" :key="k" class="pt" :style="{ left: `${(px / W) * 100}%`, top: `${(py / H) * 100}%`, background: s.color }" />
        </template>
        <template v-if="hover != null">
          <i v-for="s in series" v-show="s.values[hover] != null" :key="`h-${s.key}`" class="pt on"
             :style="{ left: `${(x(hover) / W) * 100}%`, top: `${(y(s.values[hover] ?? 0) / H) * 100}%`, background: s.color }" />
        </template>
        <div class="hits">
          <div v-for="(p, i) in points" :key="i" class="hit" tabindex="0" :aria-label="`${p.title}: ${series.map((s) => `${s.label} ${fmt(s.values[i])}`).join(', ')}`"
               @mouseenter="hover = i" @focus="hover = i" @blur="hover = null" />
        </div>
        <div v-if="hover != null" class="tip" role="tooltip" :style="tipStyle">
          <strong>{{ points[hover].title }}</strong>
          <span v-for="s in series" :key="s.key"><i :style="{ background: s.color }" />{{ s.label }} <b>{{ fmt(s.values[hover]) }}</b></span>
          <span v-if="points[hover].extra" class="extra">{{ points[hover].extra }}</span>
        </div>
      </div>
      <div class="x-axis" aria-hidden="true">
        <span v-for="t in xTicks" :key="t.i" :style="{ left: t.left }" :class="{ first: t.i === 0, last: t.i === points.length - 1 && t.i !== 0 }">{{ t.text }}</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.line-chart { display: flex; flex-direction: column; gap: 0.6rem; }
.legend { display: flex; gap: 1rem; margin: 0; font-size: 0.78rem; color: var(--muted); }
.legend i, .tip i { display: inline-block; width: 8px; height: 8px; border-radius: 2px; margin-right: 0.4rem; }
.frame { display: grid; grid-template-columns: auto minmax(0, 1fr); grid-template-rows: 190px 20px; column-gap: 0.75rem; }
.y-axis { display: flex; flex-direction: column; justify-content: space-between; font: 0.7rem var(--mono); color: var(--muted); text-align: right; margin: -0.45em 0; }
.plot { position: relative; }
svg { position: absolute; inset: 0; width: 100%; height: 100%; overflow: visible; }
.grid { stroke: var(--line); stroke-dasharray: 4 4; vector-effect: non-scaling-stroke; }
.guide { stroke: var(--line-strong); vector-effect: non-scaling-stroke; }
polyline { fill: none; stroke-width: 2; vector-effect: non-scaling-stroke; stroke-linejoin: round; stroke-linecap: round; }
.pt { position: absolute; width: 7px; height: 7px; margin: -3.5px 0 0 -3.5px; border-radius: 50%; pointer-events: none; }
.pt.on { width: 9px; height: 9px; margin: -4.5px 0 0 -4.5px; box-shadow: 0 0 0 2px var(--surface); }
.hits { position: absolute; inset: 0; display: flex; }
.hit { flex: 1; outline: none; }
.hit:focus-visible { background: color-mix(in srgb, var(--text) 5%, transparent); }
.x-axis { grid-column: 2; position: relative; font: 0.68rem var(--mono); color: var(--muted); }
.x-axis span { position: absolute; top: 6px; transform: translateX(-50%); white-space: nowrap; }
.x-axis span.first { transform: none; }
.x-axis span.last { transform: translateX(-100%); }
.tip {
  position: absolute; top: 8px; z-index: 5; pointer-events: none;
  display: flex; flex-direction: column; gap: 0.2rem; white-space: nowrap; font-size: 0.78rem; color: var(--text-2);
  background: var(--surface-2); border: 1px solid var(--line-strong); border-radius: 8px; padding: 0.5rem 0.65rem;
  box-shadow: 0 12px 28px -8px rgb(0 0 0 / 0.6);
}
.tip strong { color: var(--text); font-weight: 500; }
.tip b { color: var(--text); font-weight: 500; font-variant-numeric: tabular-nums; }
.tip .extra { color: var(--muted); }
</style>
