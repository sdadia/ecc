package ecc

import (
	"fmt"
	"math/big"
	"testing"
)

func TestSecp256r1_GeneratePrivateKey(t *testing.T) {

	// scalar
	k, _ := new(big.Int).SetString("2d5a166ee81fff6c3bf30bf6a67f84cd8b56a2e7932f426d5976786d26373271", 16)

	// perform ECDH
	params := GetSecp256r1Parameters()
	priv, _ := params.GeneratePrivateKey()
	priv.D.SetBytes(k.Bytes()) // Set the bytes so we can get the expected output
	publicKey := priv.GeneratePublicKey()

	fmt.Printf("Private key value is %x\n", priv.D.Bytes())
	fmt.Printf("Public key value is  %x\n", publicKey)

	expectedX, _ := new(big.Int).SetString("394b6f45c05c8145db054a416bca29964f0cb10b715994702bdb028ea00904fd", 16)
	expectedY, _ := new(big.Int).SetString("83e1082781ee34326966880a59a9dad299ac55bd30d210fd0c9b1472dbade1be", 16)

	if publicKey.X.Cmp(expectedX) != 0 {
		t.Fatalf("Expected Value of X of public key != observed value of public key. Expected (%x), Observed (%x)", expectedX, publicKey.X)
	}
	if publicKey.Y.Cmp(expectedY) != 0 {
		t.Fatalf("Expected Value of Y of public key != observed value of public key. Expected (%x), Observed (%x)", expectedY, publicKey.Y)
	}

	// Another test case
	k.SetString("71f25609dcec384ebc6655ef856242cb36e2f80c1092ceb21d32e3caad9c9d16", 16)
	priv.D.SetBytes(k.Bytes()) // Set the bytes so we can get the expected output
	publicKey = priv.GeneratePublicKey()

	fmt.Printf("Private key value is %x\n", priv.D.Bytes())
	fmt.Printf("Public key value is  %x\n", publicKey)

	expectedX, _ = new(big.Int).SetString("559a30e8dde8eba0b5fd5b4c5b41d1724155b55d7c297d58f3c26048ff8a8b9c", 16)
	expectedY, _ = new(big.Int).SetString("a74db1fec807cded120132df178d0a130c5431ee3c1ad83f0aa84e45594b0ecf", 16)

	if publicKey.X.Cmp(expectedX) != 0 {
		t.Fatalf("Expected Value of X of public key != observed value of public key. Expected (%x), Observed (%x)", expectedX, publicKey.X)
	}
	if publicKey.Y.Cmp(expectedY) != 0 {
		t.Fatalf("Expected Value of Y of public key != observed value of public key. Expected (%x), Observed (%x)", expectedY, publicKey.Y)
	}

}

func TestSecp256r1_ECDH(t *testing.T) {

	// perform ECDH
	params := GetSecp256r1Parameters()
	priv1, _ := params.GeneratePrivateKey()
	publicKey1 := priv1.GeneratePublicKey()

	priv2, _ := params.GeneratePrivateKey()
	publicKey2 := priv2.GeneratePublicKey()

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

func Test_5(t *testing.T) {
	params := GetSecp256r1Parameters()
	private, _ := params.GeneratePrivateKey()
	k, _ := new(big.Int).SetString("68723157890145320692495568116166642669112879877694933024822127787343477052557", 10)
	private.D.SetBytes(k.Bytes())
	publicKey := private.GeneratePublicKey()

	fmt.Println(publicKey)
}
