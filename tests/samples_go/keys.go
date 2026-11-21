// Sample: public-key crypto in Go, classical and post-quantum. Never compiled or run.
package samples

import (
	"crypto/ecdh"     // expect: ECDH
	"crypto/ecdsa"    // expect: ECC
	"crypto/ed25519"  // expect: ED25519
	"crypto/elliptic" // expect: ECC
	"crypto/mlkem"    // expect: MLKEM
	"crypto/rand"     // expect: CSPRNG
	"crypto/rsa"      // expect: RSA
	"crypto/x509"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65" // expect: MLDSA
)

func weakRsa() (*rsa.PrivateKey, error) { // expect: RSA
	return rsa.GenerateKey(rand.Reader, 1024) // expect: RSA_WEAK, CSPRNG
}

func okRsa() (*rsa.PrivateKey, error) { // expect: RSA
	bits := 3072
	return rsa.GenerateKey(rand.Reader, bits) // expect: RSA, CSPRNG
}

func ecdsaKey() (*ecdsa.PrivateKey, error) { // expect: ECC
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // expect: ECC, CSPRNG
}

func hybridParts() (*ecdh.PrivateKey, *mlkem.DecapsulationKey768, error) { // expect: ECDH, MLKEM
	classical, err := ecdh.X25519().GenerateKey(rand.Reader) // expect: X25519, CSPRNG
	if err != nil {
		return nil, nil, err
	}
	postQuantum, err := mlkem.GenerateKey768() // expect: MLKEM
	return classical, postQuantum, err
}

func ecdhP256() (*ecdh.PrivateKey, error) { // expect: ECDH
	return ecdh.P256().GenerateKey(rand.Reader) // expect: ECDH, CSPRNG
}

func signing() (ed25519.PublicKey, ed25519.PrivateKey, error) { // expect: ED25519
	return ed25519.GenerateKey(rand.Reader) // expect: ED25519, CSPRNG
}

func postQuantumSigning() (*mldsa65.PublicKey, *mldsa65.PrivateKey, error) { // expect: MLDSA
	return mldsa65.GenerateKey(rand.Reader) // expect: MLDSA, CSPRNG
}

func legacyCertificate() x509.SignatureAlgorithm {
	return x509.SHA1WithRSA // expect: SHA1, RSA
}
