package passkey_test

import (
	"testing"

	. "lablantern/agent/internal/passkey"
	"lablantern/agent/internal/passkey/passkeytest"
)

func TestVerifyAcceptsOnlyTheExactEnvelopeFromATrustedVerifiedKey(t *testing.T) {
	k := passkeytest.NewSoftKey(t)
	stranger := passkeytest.NewSoftKey(t)
	stranger.ID = "stranger"
	set := &TrustSet{Kind: "passkeys", Rev: 1, RPID: "lablantern.lan", Keys: []Key{k.Key()}}
	env := `{"kind":"command","type":"reboot"}`
	origin := "https://lablantern.lan:8443"

	if err := Verify(set, env, k.Sign(env, "lablantern.lan", origin, 0x05)); err != nil {
		t.Fatalf("valid assertion refused: %v", err)
	}
	cases := map[string]*Assertion{
		"other envelope": k.Sign(`{"kind":"command","type":"update_agent"}`, "lablantern.lan", origin, 0x05),
		"no user verify": k.Sign(env, "lablantern.lan", origin, 0x01),
		"other rp":       k.Sign(env, "evil.lan", "https://evil.lan", 0x05),
		"other origin":   k.Sign(env, "lablantern.lan", "https://evil.lan", 0x05),
		"untrusted key":  stranger.Sign(env, "lablantern.lan", origin, 0x05),
		"forged by key-id": func() *Assertion {
			a := stranger.Sign(env, "lablantern.lan", origin, 0x05)
			a.CredentialID = k.ID
			return a
		}(),
		"tampered auth data": func() *Assertion {
			a := k.Sign(env, "lablantern.lan", origin, 0x05)
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
