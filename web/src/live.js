// Live-Updates vom Server (Server-Sent Events, GET /api/events).
// Der Strom meldet nur, *was* sich geändert hat ("systems", "runs" …); die Daten kommen weiter über die
// normale, angemeldete API. Eine Verbindung für die ganze App; Ansichten melden sich per useLive() an.
import { onBeforeUnmount, reactive } from 'vue'

export const live = reactive({ connected: false })

const handlers = new Set()
let source = null
let wantOpen = false
let everConnected = false

function dispatch(topics) {
  const all = topics.includes('*')
  for (const h of handlers) {
    if (all || h.topics.some((t) => topics.includes(t))) h.schedule()
  }
}

function open() {
  if (source || typeof EventSource === 'undefined') return
  source = new EventSource('/api/events', { withCredentials: true })
  source.addEventListener('hello', () => {
    // Nach einem Verbindungsabbruch kann etwas verpasst worden sein: einmal alles nachladen
    live.connected = true
    if (everConnected) dispatch(['*'])
    everConnected = true
  })
  source.addEventListener('change', (e) => {
    try {
      dispatch(JSON.parse(e.data).topics || [])
    } catch {
      /* kaputte Nachricht ignorieren */
    }
  })
  source.addEventListener('logout', () => {
    close()
    window.location.assign('/login')
  })
  source.onerror = () => {
    live.connected = false
    // EventSource verbindet sich selbst neu (retry); bei 401 bleibt sie geschlossen
    if (source?.readyState === EventSource.CLOSED) {
      source = null
      if (wantOpen) setTimeout(() => wantOpen && open(), 5000)
    }
  }
}

function close() {
  wantOpen = false
  everConnected = false
  source?.close()
  source = null
  live.connected = false
}

export function startLive() {
  wantOpen = true
  open()
}

export function stopLive() {
  close()
}

// Ruft `reload` auf, wenn sich eines der Themen ändert. Mehrere Meldungen kurz hintereinander
// werden zusammengefasst, damit z. B. ein Scan mit vielen Commits nicht jede Ansicht dutzendfach lädt.
export function onLive(topics, reload, delay = 300) {
  let timer = null
  const h = {
    topics,
    schedule() {
      clearTimeout(timer)
      timer = setTimeout(reload, delay)
    },
  }
  handlers.add(h)
  return () => {
    clearTimeout(timer)
    handlers.delete(h)
  }
}

// Für Komponenten: meldet sich beim Unmount automatisch ab
export function useLive(topics, reload, delay) {
  const off = onLive(topics, reload, delay)
  onBeforeUnmount(off)
  return off
}
