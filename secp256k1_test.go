package ecc

import (
	"fmt"
	"math/big"
	"testing"
)

func TestSecp256k1_GeneratePrivateKey(t *testing.T) {

	// scalar
	k, _ := new(big.Int).SetString("2d5a166ee81fff6c3bf30bf6a67f84cd8b56a2e7932f426d5976786d26373271", 16)

	// perform ECDH
	params := GetSecp256k1Parametes()
	priv, _ := params.GeneratePrivateKey()
	priv.D.SetBytes(k.Bytes()) // Set the bytes so we can get the expected output
	publicKey := priv.GeneratePublicKey()

	fmt.Printf("Private key value is %x\n", priv.D.Bytes())
	fmt.Printf("Public key value is  %x\n", publicKey)

	expectedX, _ := new(big.Int).SetString("49710557499949598090243477674222998985011332556910391240891128185314495370967", 10)
	expectedY, _ := new(big.Int).SetString("64270035363186707307820636791061526699111452494847386479344763071737060553952", 10)

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

	expectedX, _ = new(big.Int).SetString("5187665601482291425231576101914814547982103870788361956174768343387030656825", 10)
	expectedY, _ = new(big.Int).SetString("26221619619158625369657172093296592364263402700363944929933165700836866068748", 10)

	if publicKey.X.Cmp(expectedX) != 0 {
		t.Fatalf("Expected Value of X of public key != observed value of public key. Expected (%x), Observed (%x)", expectedX, publicKey.X)
	}
	if publicKey.Y.Cmp(expectedY) != 0 {
		t.Fatalf("Expected Value of Y of public key != observed value of public key. Expected (%x), Observed (%x)", expectedY, publicKey.Y)
	}

}

func TestSecp256k1_ECDH(t *testing.T) {

	// perform ECDH
	params := GetSecp256k1Parametes()
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
