// Package passkey prüft WebAuthn-Assertions (ES256) direkt im Agenten. Gefährliche Befehle führt der Agent
// nur aus, wenn ein Passkey aus seiner vertrauten Liste genau diesen Befehls-Umschlag mit Nutzerprüfung
// signiert hat. Der Master leitet die Signatur nur weiter und kann sie nicht fälschen.
package passkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

type Key struct {
	ID string `json:"id"`
	X  string `json:"x"`
	Y  string `json:"y"`
}

// TrustSet ist die Liste der Admin-Passkeys, der dieser Agent vertraut.
type TrustSet struct {
	Kind     string `json:"kind"`
	Rev      int    `json:"rev"`
	RPID     string `json:"rp_id"`
	Keys     []Key  `json:"keys"`
	IssuedAt int64  `json:"issued_at"`
}

type Assertion struct {
	CredentialID      string `json:"credential_id"`
	AuthenticatorData string `json:"authenticator_data"`
	ClientDataJSON    string `json:"client_data_json"`
	Signature         string `json:"signature"`
}

func b64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func ParseTrust(envelope string) (*TrustSet, error) {
	var t TrustSet
	if err := json.Unmarshal([]byte(envelope), &t); err != nil || t.Kind != "passkeys" || t.RPID == "" || len(t.Keys) == 0 {
		return nil, fmt.Errorf("passkey list invalid")
	}
	return &t, nil
}

func ParseAssertion(raw string) (*Assertion, error) {
	var a Assertion
	if err := json.Unmarshal([]byte(raw), &a); err != nil || a.CredentialID == "" || a.Signature == "" {
		return nil, fmt.Errorf("passkey signature missing or invalid")
	}
	return &a, nil
}

// Verify prüft, dass ein vertrauter Passkey genau diesen Umschlag mit Nutzerprüfung (Fingerabdruck/PIN) signiert hat.
func Verify(set *TrustSet, envelope string, a *Assertion) error {
	var key *Key
	for i := range set.Keys {
		if set.Keys[i].ID == a.CredentialID {
			key = &set.Keys[i]
		}
	}
	if key == nil {
		return fmt.Errorf("signed with a passkey this agent does not trust")
	}
	x, errX := b64(key.X)
	y, errY := b64(key.Y)
	if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
		return fmt.Errorf("trusted key is malformed")
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		return fmt.Errorf("trusted key is not a valid P-256 point")
	}

	cdRaw, err := b64(a.ClientDataJSON)
	if err != nil {
		return fmt.Errorf("client data unreadable")
	}
	var cd struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	if json.Unmarshal(cdRaw, &cd) != nil || cd.Type != "webauthn.get" {
		return fmt.Errorf("not a WebAuthn assertion")
	}
	sum := sha256.Sum256([]byte(envelope))
	if strings.TrimRight(cd.Challenge, "=") != base64.RawURLEncoding.EncodeToString(sum[:]) {
		return fmt.Errorf("signature belongs to a different command")
	}
	if u, err := url.Parse(cd.Origin); err != nil || u.Scheme != "https" || u.Hostname() != set.RPID {
		return fmt.Errorf("signed on an unexpected origin")
	}

	ad, err := b64(a.AuthenticatorData)
	if err != nil || len(ad) < 37 {
		return fmt.Errorf("authenticator data unreadable")
	}
	rpHash := sha256.Sum256([]byte(set.RPID))
	if !bytes.Equal(ad[:32], rpHash[:]) {
		return fmt.Errorf("signed for a different site")
	}
	if ad[32]&0x01 == 0 || ad[32]&0x04 == 0 {
		return fmt.Errorf("passkey was used without user verification")
	}
	sig, err := b64(a.Signature)
	if err != nil {
		return fmt.Errorf("signature unreadable")
	}
	cdHash := sha256.Sum256(cdRaw)
	msg := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	if !ecdsa.VerifyASN1(pub, msg[:], sig) {
		return fmt.Errorf("passkey signature invalid")
	}
	return nil
}
