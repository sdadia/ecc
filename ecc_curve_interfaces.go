package ecc

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type ECPrivateKey struct {
	D         *big.Int
	curve     *ECParams
	PublicKey *Point
}

type ECSignature struct {
	r, s *big.Int
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

func CreatePrivateKeyFromScalar(E *ECParams, scalar *big.Int) *ECPrivateKey {
	privateKey := ECPrivateKey{D: scalar, curve: E, PublicKey: &Point{}}
	return &privateKey
}

type ECDH interface {
	ECDH(public *Point) *Point
}

type ECSign interface {
	Sign(message []byte) *ECSignature
}

type ECVerify interface {
	Verify(message []byte, signature *ECSignature, params *ECParams) bool
}

// GenerateRandomBytes generates a random array of N bytes.
func GenerateRandomBytes(numBytes int) ([]byte, error) {
	var randomBytes = make([]byte, numBytes)
	_, err := rand.Read(randomBytes[:]) // Fill the byte array with random data
	if err != nil {
		return randomBytes, err
	}
	return randomBytes, nil
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

func (key *ECPrivateKey) Sign(message []byte) *ECSignature {

	// Step 1 : Hash the message
	messageHash := new(big.Int)
	messageHash.SetBytes(Messagehash256(message))
	//messageHash.SetString("86032112319101611046176971828093669637772856272773459297323797145286374828050", 10)
	fmt.Printf("Hash of message : %x\n", messageHash)
	//fmt.Printf("length of Hash of message : %d\n", len(messageHash.Bytes()))

	// Step 2 : Select k such that 1 < k < n
	//kdata, _ := GenerateRandomBytes(32)
	k, _ := new(big.Int).SetString("28695618543805844332113829720373285210420739438570883203839696518176414791234", 10)

	// Step 3 : Find R = k * G
	R := ScalarMult(k, key.curve.BasePoint, key.curve)
	//fmt.Printf("R : %d\n", R)
	//fmt.Printf("Rx : %x\n", R.X)

	// Step 4 :Calculate r = x coordinate of R % n
	r := new(big.Int).Mod(R.X, key.curve.N)
	//fmt.Printf("r = Rx mod n : %d\n", r)

	// Step 5: Find inverse modulo of k
	k_inv := new(big.Int).ModInverse(k, key.curve.N)

	// Step 6 : (k^-1( hash + r*d ))(modN)
	s := new(big.Int).Mod(new(big.Int).Mul(k_inv, new(big.Int).Add(new(big.Int).Mul(r, key.D), messageHash)), key.curve.N)
	return &ECSignature{r: r, s: s}
}

func (publicKey *Point) Verify(message []byte, signature *ECSignature, params *ECParams) bool {

	// Step 1 : Hash the message
	messageHash := new(big.Int)
	messageHash.SetBytes(Messagehash256(message))
	//messageHash.SetString("86032112319101611046176971828093669637772856272773459297323797145286374828050", 10)
	fmt.Printf("Hash of message : %x\n", messageHash)
	//fmt.Printf("length of Hash of message : %d\n", len(messageHash.Bytes()))

	// Compute modulo inverse of s
	// s * x === 1 % N
	s_inv := new(big.Int).ModInverse(signature.s, params.N)
	//fmt.Printf("N : %d\n", params.N)
	//fmt.Printf("S inv : %d\n", s_inv)

	// Compute (hash* s^-1) %p
	u1 := new(big.Int).Mod(new(big.Int).Mul(messageHash, s_inv), params.N)
	//fmt.Printf("u1 =  (hash* s^-1) mod N : %d\n", u1)

	// Compute (Rx*s^1) % p
	u2 := new(big.Int).Mod(new(big.Int).Mul(signature.r, s_inv), params.N)
	//fmt.Printf("u2 =  (Rx* s^-1) mod p : %d\n", u2)

	// Add u1 *G
	u1_G := ScalarMult(u1, params.BasePoint, params)
	//fmt.Printf("u1* G : %d\n", u1_G)

	// u2 * P
	u2_G := ScalarMult(u2, publicKey, params)
	//fmt.Printf("u2* G : %d\n", u2_G)

	// Add u1*G + u2*G
	R_dash := addPoints(u1_G, u2_G, params)
	//fmt.Printf("R_dash = (s^-1 (hash*G + Rx*P)) mod P  : %d\n", R_dash)

	// Compare x cordinate of Rdash with Signature's r
	if R_dash.X.Cmp(signature.r) == 0 {
		return true
	}
	return false
}
