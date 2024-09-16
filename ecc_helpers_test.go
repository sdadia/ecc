package ecc

import (
	"testing"
)

func TestGenerateRandomBytesArraySize(t *testing.T) {
	var expected_array_size = uint(16)

	array := GenerateRandomBytes(expected_array_size)
	var got_array_size = uint(len(array))

	if got_array_size != expected_array_size {
		t.Fatalf("The function GenerateRandomBytes generated invalid array size. Expected : %d. Got %d\n", expected_array_size, got_array_size)
	}
}
