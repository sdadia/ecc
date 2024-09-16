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

func TestGenerateRandomBytesArrayValuesLessThan255(t *testing.T) {
	var expected_array_size = uint(16)
	array := GenerateRandomBytes(expected_array_size)
	var got_array_size = len(array)
	for i := range got_array_size {
		if !((array[i] < 255) && (array[i] > 0)) {
			t.Fatalf("Array values should >= 0 and < 255. Got : %d at index %d\n", array[i], i)
		}
	}
}
