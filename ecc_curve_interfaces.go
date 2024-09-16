package ecc

import (
	"crypto/rand"
	"math/big"
)

// GenerateRandomBytes generates a random array of N bytes.
func GenerateRandomBytes(numBytes int) ([]byte, error) {
	var randomBytes = make([]byte, numBytes)
	_, err := rand.Read(randomBytes[:]) // Fill the byte array with random data
	if err != nil {
		return randomBytes, err
	}
	return randomBytes, nil
}

type ECPrivateKey struct {
	D         *big.Int
	curve     *ECParams
	PublicKey *Point
}

// GeneratePublicKey interface returns a point struct which is an X,Y coordinate
type GeneratePublicKey interface {
	GeneratePublicKey() *Point
}

// GeneratePrivateKey returns a private key struct
type GeneratePrivateKey interface {
	GeneratePrivateKey() (*ECPrivateKey, error)
}

type ECDH interface {
	ECDH(public *Point) *Point
}
