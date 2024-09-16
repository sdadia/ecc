package ecc

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

// ECParameters represents the domain parameters for ECDSA
// p -> Prime
// a, b -> y^2 =  x^3 + ax + b
// gx, gy -> (x, y) coordinates of base point
// n -> Order of BASE POINT
type ECParameters struct {
	P, N, A, B, Gx, Gy *big.Int
}

// ECPrivateKey represents an ECDSA private key
type ECPrivateKey struct {
	D         *big.Int
	PublicKey ECPublicKey
}

// ECPublicKey represents an ECDSA public key
type ECPublicKey struct {
	X, Y *big.Int
}

type SharedSecret struct {
	X, Y *big.Int
}

// ECDSASignature represents an ECDSA signature
type ECDSASignature struct {
	R, S *big.Int
}

// modInverse calculates the modular multiplicative inverse
func modInverse(a, m *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, m)
}

// scalarMult performs scalar multiplication on the curve
func scalarMult(x, y, k, p, a *big.Int) (*big.Int, *big.Int) {
	rx, ry := new(big.Int), new(big.Int)
	if k.Sign() == 0 || x.Sign() == 0 && y.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	for i := k.BitLen() - 1; i >= 0; i-- {
		rx, ry = pointDouble(rx, ry, p, a)
		if k.Bit(i) == 1 {
			rx, ry = pointAdd(rx, ry, x, y, p)
		}
	}

	return rx, ry
}

// pointDouble performs point doubling on the curve
func pointDouble(x, y, p, a *big.Int) (*big.Int, *big.Int) {
	if x.Sign() == 0 && y.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	m := new(big.Int).Mul(x, x)
	m.Mul(m, big.NewInt(3))
	m.Add(m, a)
	m.Mul(m, modInverse(new(big.Int).Mul(y, big.NewInt(2)), p))
	m.Mod(m, p)

	rx := new(big.Int).Mul(m, m)
	rx.Sub(rx, new(big.Int).Mul(x, big.NewInt(2)))
	rx.Mod(rx, p)

	ry := new(big.Int).Sub(x, rx)
	ry.Mul(ry, m)
	ry.Sub(ry, y)
	ry.Mod(ry, p)

	return rx, ry
}

// pointAdd performs point addition on the curve
func pointAdd(x1, y1, x2, y2, p *big.Int) (*big.Int, *big.Int) {
	if x1.Sign() == 0 && y1.Sign() == 0 {
		return new(big.Int).Set(x2), new(big.Int).Set(y2)
	}
	if x2.Sign() == 0 && y2.Sign() == 0 {
		return new(big.Int).Set(x1), new(big.Int).Set(y1)
	}

	if x1.Cmp(x2) == 0 {
		if y1.Cmp(y2) == 0 {
			return pointDouble(x1, y1, p, new(big.Int))
		}
		return new(big.Int), new(big.Int)
	}

	m := new(big.Int).Sub(y2, y1)
	m.Mul(m, modInverse(new(big.Int).Sub(x2, x1), p))
	m.Mod(m, p)

	rx := new(big.Int).Mul(m, m)
	rx.Sub(rx, x1)
	rx.Sub(rx, x2)
	rx.Mod(rx, p)

	ry := new(big.Int).Sub(x1, rx)
	ry.Mul(ry, m)
	ry.Sub(ry, y1)
	ry.Mod(ry, p)

	return rx, ry
}

// Hash the message using SHA-256
func hashMessage(message string) *big.Int {
	hash := sha256.New()
	hash.Write([]byte(message))
	hashBytes := hash.Sum(nil)
	return new(big.Int).SetBytes(hashBytes)
}

// Sign performs the ECDSA signing operation
func Sign(privateKey *ECPrivateKey, message []byte, params *ECParameters) (*ECDSASignature, error) {
	z := hashMessage(string(message))

	for {
		k, err := rand.Int(rand.Reader, new(big.Int).Sub(params.N, big.NewInt(1)))
		if err != nil {
			return nil, err
		}
		k.Add(k, big.NewInt(1))

		rx, _ := scalarMult(params.Gx, params.Gy, k, params.P, params.A)
		r := new(big.Int).Mod(rx, params.N)
		if r.Sign() == 0 {
			continue
		}

		s := new(big.Int).Mul(privateKey.D, r)
		s.Add(s, z)
		s.Mul(s, modInverse(k, params.N))
		s.Mod(s, params.N)
		if s.Sign() == 0 {
			continue
		}

		return &ECDSASignature{R: r, S: s}, nil
	}
}

// Verify performs the ECDSA signature verification
func Verify(publicKey *ECPublicKey, message []byte, signature *ECDSASignature, params *ECParameters) (bool, error) {
	if signature.R.Sign() <= 0 || signature.R.Cmp(params.N) >= 0 ||
		signature.S.Sign() <= 0 || signature.S.Cmp(params.N) >= 0 {
		return false, errors.New("invalid signature")
	}

	z := hashMessage(string(message))

	w := modInverse(signature.S, params.N)

	u1 := new(big.Int).Mul(z, w)
	u1.Mod(u1, params.N)

	u2 := new(big.Int).Mul(signature.R, w)
	u2.Mod(u2, params.N)

	x1, y1 := scalarMult(params.Gx, params.Gy, u1, params.P, params.A)
	x2, y2 := scalarMult(publicKey.X, publicKey.Y, u2, params.P, params.A)

	x, _ := pointAdd(x1, y1, x2, y2, params.P)

	v := new(big.Int).Mod(x, params.N)

	return v.Cmp(signature.R) == 0, nil
}

// ECDH performs diffie hellman key exchange to get the shared key
func ECDH(privateKey *ECPrivateKey, publicKey *ECPublicKey, params *ECParameters) *SharedSecret {
	// Public Key
	var sharedSecret SharedSecret
	sharedSecret.X, sharedSecret.Y = scalarMult(publicKey.X,
		publicKey.Y,
		privateKey.D,
		params.P,
		params.A)

	return &sharedSecret
}

// GenPrivateKey Create an interface to private key generation depends on the curve we use
type GenPrivatePublicKey interface {
	GenPrivatePublicKey() *ECPrivateKey // Public Key is set internally accssed via ECPrivateKey.PrivateKey
}

// GenerateRandomBytes Function returns an array with random bytes of a given size
func GenerateRandomBytes(numberbytes uint) []byte {
	randombytes := make([]byte, numberbytes)
	rand.Read(randombytes)
	return randombytes[:]
}
