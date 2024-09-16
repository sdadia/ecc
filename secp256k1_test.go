package ecc

import (
	"fmt"
	"math/big"
	"testing"
)

func Test2(t *testing.T) {

	//curve2 := ecdh.X25519()
	//privateKey, _ := curve2.GeneratePrivateKey(rand.Reader)
	//publickey := privateKey.PublicKey()
	//fmt.Printf("Private key value is %x\n", privateKey.Bytes())
	//fmt.Printf("public key value is  %x\n", publickey.Bytes())
	//fmt.Printf("Private key len %d\n", len(privateKey.Bytes()))
	//fmt.Printf("Public key len  %d\n", len(publickey.Bytes()))

	params := GetSecp256k1Parametes()
	priv, _ := params.GeneratePrivateKey()
	k, _ := new(big.Int).SetString("2d5a166ee81fff6c3bf30bf6a67f84cd8b56a2e7932f426d5976786d26373271", 16)
	priv.D.SetBytes(k.Bytes())
	publicKey := priv.GeneratePublicKey()

	fmt.Printf("Private key value is %x\n", priv.D.Bytes())
	fmt.Printf("Public key value is  %d\n", publicKey.X)
	fmt.Printf("Public key value is  %d\n", publicKey.Y)

	p1, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	a1, _ := new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000000", 16)
	b1, _ := new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)
	gx1, _ := new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	gy1, _ := new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)

	// Example usage
	ec := &ECParams{
		P: p1,
		A: a1,
		B: b1,
	}

	P := &Point{
		X: gx1,
		Y: gy1,
	}

	result := ScalarMult(k, P, ec)
	fmt.Printf("Resulting X: %d\n", result.X)
	fmt.Printf("Resulting Y: %d\n", result.Y)

}
