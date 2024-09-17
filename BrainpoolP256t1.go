package ecc

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

type BrainpoolP256t1 struct {
	*ECParams
}

func GetBrainpoolP256t1Parameters() *BrainpoolP256t1 {
	// BrainpoolP256t1 parameters
	p := new(big.Int)
	p.SetString("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", 16) // Prime p

	a := new(big.Int)
	a.SetString("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5374", 16) // Weierstrass 'a' parameter

	b := new(big.Int)
	b.SetString("662C61C430D84EA4FE66A7733D0B76B7BF93EBC4AF2F49256AE58101FEE92B04", 16) // Weierstrass 'b' parameter

	n := new(big.Int)
	n.SetString("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 16) // Order n

	// Base point (Gx, Gy) on BrainpoolP256t1
	baseX := new(big.Int)
	baseX.SetString("A3E8EB3CC1CFE7B7732213B23A656149AFA142C47AAFBC2B79A191562E1305F4", 16) // X coordinate of the base point

	baseY := new(big.Int)
	baseY.SetString("2D996C823439C56D7F7B22E14644417E69BCB6DE39D027001DABE8F35B25C9BE", 16) // Y coordinate of the base point

	// Create the ECParams instance
	curveParams := BrainpoolP256t1{ECParams: &ECParams{
		P: p,
		A: a,
		B: b,
		N: n,
		BasePoint: &Point{
			X: baseX,
			Y: baseY,
		},
	}}

	return &curveParams
}

func (E *BrainpoolP256t1) IsValidPrivateKey(privateKey *ECPrivateKey) bool {
	key := privateKey.D.Bytes()

	// Check if the key is 32 bytes long
	if len(key) != 32 {
		fmt.Errorf("Key length must be 32 bytes. Given key length %d\n", len(key))
		return false
	}

	// Check if the key is all zeros (an edge case to avoid)
	isAllZero := true
	for _, b := range key {
		if b != 0 {
			isAllZero = false
			break
		}
	}
	if isAllZero {
		return false
	}

	return true
}

// GeneratePrivateKey generates at new 32 byte key
func (E *BrainpoolP256t1) GeneratePrivateKey() (*ECPrivateKey, error) {

	// Iterate till you find a valid private key
	const MAX_ITER = 100
	iter := 0
	for {
		iter += 1

		// generate random 32 bytes
		randomBytes, err := GenerateRandomBytes(32)

		// Initialize private key
		privateKey := ECPrivateKey{D: new(big.Int).SetBytes(randomBytes), curve: E.ECParams, PublicKey: &Point{}}

		// Return if valid private key, else generate another one
		if E.IsValidPrivateKey(&privateKey) {
			return &privateKey, err
		}

		// Quit if you cannot generate valid private key after MAX_ITER
		if iter == MAX_ITER {
			return &ECPrivateKey{}, errors.New("MAX ITERATION REACHED. Cannot generate private key")
		}
	}
}

func Messagehash256(message []byte) []byte {
	hasher := sha256.New()
	hasher.Write(message)
	hashValue := hasher.Sum(nil)
	return hashValue
}
