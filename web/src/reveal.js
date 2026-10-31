// Springt zu einem Element (Karte, Eintrag, eingeklapptes Formular): öffnet alle umgebenden <details>, scrollt hin
// und hebt es kurz hervor. Karten laden ihre Daten erst nach einem Tab-Wechsel, darum wird kurz auf das Ziel gewartet.
export function reveal(id, tries = 20) {
  const el = id && document.getElementById(id)
  if (!el) {
    if (id && tries > 0) setTimeout(() => reveal(id, tries - 1), 100)
    return
  }
  if (el.tagName === 'DETAILS') el.open = true
  for (let d = el.parentElement?.closest('details'); d; d = d.parentElement?.closest('details')) d.open = true
  const still = window.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches
  el.scrollIntoView({ behavior: still ? 'auto' : 'smooth', block: 'center' })
  el.classList.remove('found')
  void el.offsetWidth   // Animation neu starten, wenn dasselbe Ziel zweimal gewählt wird
  el.classList.add('found')
  setTimeout(() => el.classList.remove('found'), 1800)
}
