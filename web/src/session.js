import { reactive } from 'vue'
import { api, setCsrf } from './api.js'
import { loadTimeZone } from './time.js'

export const session = reactive({
  loaded: false,
  setup_complete: false,
  authenticated: false,
  username: '',
  role: '',
})

export function applyState(s) {
  session.setup_complete = s.setup_complete
  session.authenticated = !!s.authenticated
  session.username = s.username || ''
  session.role = s.role || ''
  setCsrf(s.csrf_token || null)
  if (session.authenticated) loadTimeZone()
  session.loaded = true
}

export async function refreshSession() {
  applyState(await api.get('/api/state'))
}

export async function logout() {
  await api.post('/api/logout')
  await refreshSession()
}
