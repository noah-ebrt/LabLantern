/** Wohin muss umgeleitet werden? `null` = Seite darf angezeigt werden. */
export function routeFor(state, path) {
  if (!state.setup_complete) return path === '/einrichtung' ? null : '/einrichtung'
  if (path === '/einrichtung') return state.authenticated ? '/' : '/login'
  if (!state.authenticated) return path === '/login' ? null : '/login'
  if (path === '/login') return '/'
  return null
}
