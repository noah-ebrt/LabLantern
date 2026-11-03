// Passkeys im Browser: Optionen vom Server (base64url-JSON) in WebAuthn-Aufrufe übersetzen und die Antwort
// wieder als JSON zurückgeben, so wie py_webauthn sie prüft.

const toBytes = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4)), (c) => c.charCodeAt(0))
const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

export const passkeysSupported = () => typeof window !== 'undefined' && !!window.PublicKeyCredential && window.isSecureContext

function explain(e) {
  if (e?.name === 'NotAllowedError') return new Error('Passkey request was cancelled or timed out.')
  if (e?.name === 'SecurityError') return new Error('Passkeys only work when the UI is opened under its hostname with a trusted certificate (e.g. https://lablantern.lan:8443).')
  if (e?.name === 'InvalidStateError') return new Error('This passkey is already registered.')
  return e
}

export async function createPasskey(options) {
  const publicKey = {
    ...options,
    challenge: toBytes(options.challenge),
    user: { ...options.user, id: toBytes(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((c) => ({ ...c, id: toBytes(c.id) })),
  }
  let cred
  try {
    cred = await navigator.credentials.create({ publicKey })
  } catch (e) {
    throw explain(e)
  }
  return {
    id: cred.id, rawId: toB64(cred.rawId), type: cred.type, clientExtensionResults: cred.getClientExtensionResults(),
    response: { clientDataJSON: toB64(cred.response.clientDataJSON), attestationObject: toB64(cred.response.attestationObject),
      transports: cred.response.getTransports?.() || [] },
  }
}

export async function usePasskey(options) {
  const publicKey = {
    ...options,
    challenge: toBytes(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((c) => ({ ...c, id: toBytes(c.id) })),
  }
  let cred
  try {
    cred = await navigator.credentials.get({ publicKey })
  } catch (e) {
    throw explain(e)
  }
  return {
    id: cred.id, rawId: toB64(cred.rawId), type: cred.type, clientExtensionResults: cred.getClientExtensionResults(),
    response: { clientDataJSON: toB64(cred.response.clientDataJSON), authenticatorData: toB64(cred.response.authenticatorData),
      signature: toB64(cred.response.signature), userHandle: cred.response.userHandle ? toB64(cred.response.userHandle) : null },
  }
}
