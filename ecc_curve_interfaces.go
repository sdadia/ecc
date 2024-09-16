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

type IsValidPrivateKey interface {
	IsValidPrivateKey(key *ECPrivateKey) bool
}

type ECDH interface {
	ECDH(public *Point) *Point
}

// GeneratePublicKey computes the public key from private key and returns the X, Y coordinates
func (key *ECPrivateKey) GeneratePublicKey() *Point {

	result := key.ECDH(key.curve.BasePoint)

	key.PublicKey.X = result.X
	key.PublicKey.Y = result.Y

	return key.PublicKey

}

// ECDH Runs the ECDH and returns the shared key X,Y coordinates
func (key *ECPrivateKey) ECDH(public *Point) *Point {
	result := ScalarMult(key.D, public, key.curve)
	return result
}
