// Package pairing berechnet den Code, den Admin und Host beim Einrichten vergleichen.
//
// Der Agent legt sich zuerst mit Commitment(secret) fest, der Master antwortet mit einer frischen Zufallszahl, erst
// danach deckt der Agent das Geheimnis auf. Ein Mann in der Mitte muss sich beim Master auf ein Geheimnis festlegen,
// bevor er die Zufallszahl kennt; er kann deshalb kein Geheimnis mehr suchen, das zum Code dieses Hosts passt.
package pairing

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"regexp"

	"vulnwatch/agent/internal/config"
)

var nonceRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Code muss genau so im Master berechnet werden (app/pairing.py: pairing_code). Er hängt am Fingerabdruck des
// Zertifikats, das dieser Host gesehen hat: Ein Master dazwischen hat ein anderes und damit einen anderen Code.
func Code(caFingerprint, secret, nonce string) string {
	sum := sha256.Sum256([]byte(config.NormalizeFingerprint(caFingerprint) + ":" + secret + ":" + nonce))
	raw := base32.StdEncoding.EncodeToString(sum[:])[:6]
	return raw[:3] + "-" + raw[3:]
}

// Commitment ist SHA-256 des Geheimnisses (hex); nur das geht im ersten Schritt an den Master.
func Commitment(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// ValidNonce prüft die Zufallszahl des Masters (16 Byte hex).
func ValidNonce(n string) bool { return nonceRe.MatchString(n) }

func NewSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
