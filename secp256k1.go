package ecc

import (
	"math/big"
)

type Secp256k1 struct {
	*ECParams
}

// GetSecp256k1Parametes returns the parameters for the SECP256K1 curve
func GetSecp256k1Parametes() *Secp256k1 {

	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	n, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	b, _ := new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)
	a, _ := new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000000", 16)
	gx, _ := new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	gy, _ := new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)

	var curveParams = Secp256k1{
		ECParams: &ECParams{P: p, N: n, A: a, B: b, BasePoint: &Point{X: gx, Y: gy}},
	}

	return &(curveParams)

}

// GeneratePrivateKey generates at new 32 byte key
func (E *Secp256k1) GeneratePrivateKey() (*ECPrivateKey, error) {

	// generate random 32 bytes
	randomBytes, err := GenerateRandomBytes(32)

	// Initialize private key
	privateKey := ECPrivateKey{D: new(big.Int).SetBytes(randomBytes), curve: E.ECParams, PublicKey: &Point{}}

	// Do scalar multiplication
	privateKey.GeneratePublicKey()

	return &privateKey, err
}

// GeneratePublicKey computes the public key from private key and returns the X, Y coordinates
func (key *ECPrivateKey) GeneratePublicKey() *Point {

	pt2 := ScalarMult(key.D, key.curve.BasePoint, key.curve)

	key.PublicKey.X = pt2.X
	key.PublicKey.Y = pt2.Y

	return key.PublicKey

}

// ECDH Runs the ECDH and returns the shared key X,Y coordinates
func (key *ECPrivateKey) ECDH(public *Point) *Point {
	result := ScalarMult(key.D, public, key.curve)

	return result
}
