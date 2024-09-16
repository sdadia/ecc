# ECC

## Installation

```bash
go get -u github.com/sdadia/ecc
```

This code implements the basics of elliptical curve such as point addition, doubling, scalar multiplication etc

```
ecc_helpers.go         ---- contains functions to find mod inverse, scalar Mult, point doubling, point addition, hash message, signing and verification
```

```go
func main() {
	// NIST parameters
	// p -> Prime
	// a, b -> y^2 =  x^3 + ax + b
	// gx, gy -> (x, y) coordinates of base point
	// n -> Order of BASE POINT
	p, _ := new(big.Int).SetString("71", 10)
	n, _ := new(big.Int).SetString("71", 16)
	b, _ := new(big.Int).SetString("7", 10)
	a, _ := new(big.Int).SetString("0", 10)
	gx, _ := new(big.Int).SetString("6", 10)
	gy, _ := new(big.Int).SetString("9", 10)
	
	params := &ECParameters{
		P:  p,
		N:  n,
		A:  a,
		B:  b,
		Gx: gx,
		Gy: gy,
	}


	// Private key - any randon number
	d := new(big.Int).SetUint64(mr.Uint64N(30))
	privateKey := &ECPrivateKey{
		D: d,
	}
	fmt.Printf("Private Key (base10): %s\n", d.String())
	
	// Public Key
	privateKey.PublicKey.X, privateKey.PublicKey.Y = scalarMult(params.Gx, 
                                                                params.Gy, 
                                                                privateKey.D, 
                                                                params.P, 
                                                                params.A)
	fmt.Printf("Public Key x (base10) : %s\n", privateKey.PublicKey.X.String())
	fmt.Printf("Public Key y (base10) : %s\n", privateKey.PublicKey.Y.String())

	
	// Sign
	message := []byte("Hello, ECDSA!")
	signature, err := Sign(privateKey, message, params)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\n\nMessage: %s\n", message)
	fmt.Printf("Signature (r, s):\n r (base10) = %d\n s (base10) = %d\n", signature.R, signature.S)
	
	// validate signature
	is_valid, err := Verify(&privateKey.PublicKey, message, signature, params)
	if err != nil {
		panic(err)
	}
	
	if is_valid {
		fmt.Println("Signature is is_valid")
	} else {
		fmt.Println("Signature is inis_valid")
	}
}

```