package ecc

import (
	"crypto/rand"
	"math/big"
)

// X25519 Use this to create the code
func Curve25519() *ECParameters {

	p, _ := new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
	n, _ := new(big.Int).SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)

	b, _ := new(big.Int).SetString("1", 16)
	a, _ := new(big.Int).SetString("76d06", 16)
	gx, _ := new(big.Int).SetString("9", 16)
	gy, _ := new(big.Int).SetString("20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9", 16)

	return &ECParameters{
		P:  p,
		N:  n,
		A:  a,
		B:  b,
		Gx: gx,
		Gy: gy,
	}
}

func (E *ECParameters) GenPrivatePublicKey() *ECPrivateKey {

	// generate random 32 bytes
	randombytes := make([]byte, 32)
	rand.Read(randombytes)

	// Clamp the private key as per RFC 7748
	randombytes[0] &= 248
	randombytes[31] &= 127
	randombytes[31] |= 64

	// Initialize private key
	privateKey := ECPrivateKey{D: new(big.Int).SetBytes(randombytes)}
	// Generate public key
	privateKey.PublicKey.X, privateKey.PublicKey.Y = scalarMult(E.Gx, E.Gy, privateKey.D, E.P, E.A)

	return &privateKey
}
