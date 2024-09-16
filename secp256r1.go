package ecc

import (
	"errors"
	"math/big"
)

type Secp256r1 struct {
	*ECParams
}

func GetSecp256r1Parameters() *Secp256r1 {
	p, _ := new(big.Int).SetString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
	n, _ := new(big.Int).SetString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
	b, _ := new(big.Int).SetString("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
	a, _ := new(big.Int).SetString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16)
	gx, _ := new(big.Int).SetString("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16)
	gy, _ := new(big.Int).SetString("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)

	var curveParams = Secp256r1{
		ECParams: &ECParams{P: p, N: n, A: a, B: b, BasePoint: &Point{X: gx, Y: gy}},
	}

	return &curveParams
}

func (E *Secp256r1) IsValidPrivateKey(key *ECPrivateKey) bool {
	// If 1 < key < n then valid else invalid78919850240963748110675029416502060938178102871195239984330800772548425541415
	if (E.N.Cmp(key.D) == 1) && (key.D.Cmp(new(big.Int).SetInt64(0)) == 1) {
		return true
	}
	return false
}

// GeneratePrivateKey generates at new 32 byte key
func (E *Secp256r1) GeneratePrivateKey() (*ECPrivateKey, error) {

	// Iterate till you find a valid private key
	const MAX_ITER = 100
	iter := 0
	for {
		iter += 1

		// generate random 32 bytes
		randomBytes, err := GenerateRandomBytes(32)

		// Initialize private key
		privateKey := ECPrivateKey{D: new(big.Int).SetBytes(randomBytes), curve: E.ECParams, PublicKey: &Point{}}

		// Return if valid private key
		if E.IsValidPrivateKey(&privateKey) {
			return &privateKey, err
		}

		// Quit if you cannot generate valid private key after MAX_ITER
		if iter == MAX_ITER {
			return &ECPrivateKey{}, errors.New("MAX ITERATION REACHED. Cannot generate private key")
		}
	}
}
