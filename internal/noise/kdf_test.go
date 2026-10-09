package noise

import (
	"encoding/hex"
	"testing"
)

func TestKDF2(t *testing.T) {
	key := make([]byte, 32) // 32 zero bytes
	input, err := hex.DecodeString("aabbccdd")
	if err != nil {
		t.Fatal(err)
	}

	out1, out2 := kdf2(key, input)

	want1 := "1b9e98735a76dd43c226a9de6ad882f4ef3ecc0a2224dc045c978b3f0cd2db34"
	want2 := "96b5b5c14ee953f41dd98266dfa3cee06bef6772336a24cb5cfc04a18d5b0af4"

	if got := hex.EncodeToString(out1[:]); got != want1 {
		t.Errorf("out1 = %s, want %s", got, want1)
	}
	if got := hex.EncodeToString(out2[:]); got != want2 {
		t.Errorf("out2 = %s, want %s", got, want2)
	}
}
