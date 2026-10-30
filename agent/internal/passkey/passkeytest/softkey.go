// Package passkeytest erzeugt echte ES256-Assertions für Tests (wie ein Hardware-Authenticator).
package passkeytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"vulnwatch/agent/internal/passkey"
)

var enc = base64.RawURLEncoding

// SoftKey erzeugt echte ES256-Assertions wie ein Authenticator.
type SoftKey struct {
	priv *ecdsa.PrivateKey
	ID   string
}

func NewSoftKey(t *testing.T) *SoftKey {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &SoftKey{priv: priv, ID: enc.EncodeToString([]byte(t.Name()))}
}

func (k *SoftKey) Key() passkey.Key {
	b, _ := k.priv.PublicKey.Bytes()
	return passkey.Key{ID: k.ID, X: enc.EncodeToString(b[1:33]), Y: enc.EncodeToString(b[33:65])}
}

func (k *SoftKey) Sign(envelope, rpID, origin string, flags byte) *passkey.Assertion {
	sum := sha256.Sum256([]byte(envelope))
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": enc.EncodeToString(sum[:]), "origin": origin})
	rp := sha256.Sum256([]byte(rpID))
	ad := append(rp[:], flags, 0, 0, 0, 1)
	cdHash := sha256.Sum256(cd)
	msg := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, _ := ecdsa.SignASN1(rand.Reader, k.priv, msg[:])
	return &passkey.Assertion{CredentialID: k.ID, AuthenticatorData: enc.EncodeToString(ad),
		ClientDataJSON: enc.EncodeToString(cd), Signature: enc.EncodeToString(sig)}
}
