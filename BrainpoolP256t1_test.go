package ecc

import (
	"fmt"
	"testing"
)

func TestBrainpoolP256t1_ECDH(t *testing.T) {

	// perform ECDH
	params := GetBrainpoolP256t1Parameters()

	priv1, _ := params.GeneratePrivateKey()
	publicKey1 := priv1.GeneratePublicKey()
	fmt.Printf("Private key 1 : %x\n", priv1.D.Bytes())

	priv2, _ := params.GeneratePrivateKey()
	publicKey2 := priv2.GeneratePublicKey()
	fmt.Printf("Private key 2 : %x\n", priv2.D.Bytes())

	sharedKey1 := priv1.ECDH(publicKey2)
	sharedKey2 := priv2.ECDH(publicKey1)

	fmt.Printf("Shared key1 %x\n", sharedKey1)
	fmt.Printf("Shared key2 %x\n", sharedKey2)

	if sharedKey1.X.Cmp(sharedKey2.X) != 0 {
		t.Fatalf("Expected Value of X of public key != observed value of public key. Expected (%x), Observed (%x)", sharedKey1.X, sharedKey2.X)

	}
	if sharedKey1.Y.Cmp(sharedKey2.Y) != 0 {
		t.Fatalf("Expected Value of Y of public key != observed value of public key. Expected (%x), Observed (%x)", sharedKey1.Y, sharedKey2.Y)
	}

}

func TestBrainpoolP256t1SignAndVerifyValid(t *testing.T) {

	// Generate random private key
	params := GetBrainpoolP256t1Parameters()
	privateKey, _ := params.GeneratePrivateKey()
	fmt.Printf("Private Key :%d\n", privateKey.D)
	publicKey := privateKey.GeneratePublicKey()
	fmt.Printf("Public Key :%d\n", publicKey)

	// Random message
	message := []byte("Hello 123")
	signature := privateKey.Sign(message)
	fmt.Printf("Signature (r,s) : (%d, %d)\n", signature.r, signature.s)

	// Check if the signature is valid using same public key
	isvalid := publicKey.Verify(message, signature, params.ECParams)
	fmt.Printf("Signature valid : %v\n", isvalid)

	expected := true
	if isvalid != expected {
		t.Fatalf("Sign and Verification function failed for BrainpoolP256t1. Expected %v. Got %v\n", expected, isvalid)
	}
}

func TestBrainpoolP256t1SignAndVerifyInValid(t *testing.T) {

	// Generate random private key
	params := GetBrainpoolP256t1Parameters()
	privateKey, _ := params.GeneratePrivateKey()
	fmt.Printf("Private Key :%d\n", privateKey.D)
	publicKey := privateKey.GeneratePublicKey()
	fmt.Printf("Public Key :%d\n", publicKey)

	// Random message
	message := []byte("Hello 123")
	signature := privateKey.Sign(message)
	fmt.Printf("Signature (r,s) : (%d, %d)\n", signature.r, signature.s)

	// Check if the signature is valid using same public key
	// Modify the public key cordinates
	publicKey.X.SetInt64(1)
	isvalid := publicKey.Verify(message, signature, params.ECParams)
	fmt.Printf("Signature valid : %v\n", isvalid)

	expected := false
	if isvalid != expected {
		t.Fatalf("Sign and Verification function giving invalid results for BrainpoolP256t1. Expected %v. Got %v\n", expected, isvalid)
	}

}
