// Sample: TLS settings and randomness in Go. Never compiled or run.
package samples

import (
	crand "crypto/rand" // expect: CSPRNG
	"crypto/tls"
	"encoding/hex"
	"math/rand/v2"
)

var insecure = &tls.Config{
	InsecureSkipVerify: true,       // expect: TLS_NO_VERIFY
	MinVersion:         tls.VersionTLS10, // expect: TLS_OLD
	CipherSuites: []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,               // expect: RC4, RSA
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,     // expect: CBC
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, // expect: AES_GCM
	},
}

var modern = &tls.Config{
	MinVersion:       tls.VersionTLS13,                           // expect: TLS_MODERN
	CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}, // expect: MLKEM, X25519
}

func rollDice() int {
	return rand.IntN(6) + 1
}

func generateToken() string {
	return hex.EncodeToString([]byte{byte(rand.IntN(256))}) // expect: INSECURE_RANDOM
}

func sessionKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := crand.Read(key) // expect: CSPRNG
	return key, err
}
