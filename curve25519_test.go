package ecc

import (
	"fmt"
	"testing"
)

func TestGetCurve25519Parametes(t *testing.T) {
	curv := GetCurve25519Parametes()
	priv, pubkey := curv.GenPrivatePublicKey()
	fmt.Printf("Private Key d : %v\n", priv.D)
	fmt.Printf("Private Public Key (x, y) : (%x, %x)\n", pubkey.X, pubkey.Y)
}
