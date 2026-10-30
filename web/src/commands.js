import { api } from './api.js'
import { usePasskey } from './webauthn.js'

// Gefährliche Befehle (Neustart, Update, Entfernen): der Server bereitet vor, der Passkey signiert genau diesen
export async function signedCommand(systemId, type) {
  const { options } = await api.post(`/api/systems/${systemId}/commands/prepare`, { type })
  const credential = await usePasskey(options)
  return api.post(`/api/systems/${systemId}/commands/confirm`, { credential })
}
