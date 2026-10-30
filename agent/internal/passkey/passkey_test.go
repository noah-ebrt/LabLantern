package passkey_test

import (
	"testing"

	. "vulnwatch/agent/internal/passkey"
	"vulnwatch/agent/internal/passkey/passkeytest"
)

func TestVerifyAcceptsOnlyTheExactEnvelopeFromATrustedVerifiedKey(t *testing.T) {
	k := passkeytest.NewSoftKey(t)
	stranger := passkeytest.NewSoftKey(t)
	stranger.ID = "stranger"
	set := &TrustSet{Kind: "passkeys", Rev: 1, RPID: "vulnwatch.lan", Keys: []Key{k.Key()}}
	env := `{"kind":"command","type":"reboot"}`
	origin := "https://vulnwatch.lan:8443"

	if err := Verify(set, env, k.Sign(env, "vulnwatch.lan", origin, 0x05)); err != nil {
		t.Fatalf("valid assertion refused: %v", err)
	}
	cases := map[string]*Assertion{
		"other envelope": k.Sign(`{"kind":"command","type":"update_agent"}`, "vulnwatch.lan", origin, 0x05),
		"no user verify": k.Sign(env, "vulnwatch.lan", origin, 0x01),
		"other rp":       k.Sign(env, "evil.lan", "https://evil.lan", 0x05),
		"other origin":   k.Sign(env, "vulnwatch.lan", "https://evil.lan", 0x05),
		"untrusted key":  stranger.Sign(env, "vulnwatch.lan", origin, 0x05),
		"forged by key-id": func() *Assertion {
			a := stranger.Sign(env, "vulnwatch.lan", origin, 0x05)
			a.CredentialID = k.ID
			return a
		}(),
		"tampered auth data": func() *Assertion {
			a := k.Sign(env, "vulnwatch.lan", origin, 0x05)
			a.AuthenticatorData = a.AuthenticatorData[:len(a.AuthenticatorData)-2] + "AA"
			return a
		}(),
	}
	for name, a := range cases {
		if err := Verify(set, env, a); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
