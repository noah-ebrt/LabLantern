package pairing

import (
	"strings"
	"testing"
)

// Gleiche Eingaben wie in server/tests/test_pairing.py.
func TestCodeMatchesTheMaster(t *testing.T) {
	secret, nonce := strings.Repeat("ab", 32), strings.Repeat("cd", 16)
	if Code("aa:bb", secret, nonce) != Code("AABB", secret, nonce) {
		t.Fatal("fingerprint format must not matter")
	}
	if got := Code("AABB", secret, nonce); got != "VQK-IC7" { // gleicher Wert im Python-Test
		t.Fatalf("code %q", got)
	}
	if Code("AABB", secret, strings.Repeat("ce", 16)) == Code("AABB", secret, nonce) {
		t.Fatal("the master's nonce must change the code")
	}
}

func TestCommitmentAndNonce(t *testing.T) {
	// SHA-256("abc"), wie auth.sha256_hex im Master
	if Commitment("abc") != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatal("commitment")
	}
	if !ValidNonce(strings.Repeat("0f", 16)) || ValidNonce("") || ValidNonce(strings.Repeat("0F", 16)) {
		t.Fatal("nonce check")
	}
}
