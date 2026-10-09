package noise

import (
	"crypto/hmac"
	"crypto/sha256"
)

// hmacSHA256 returns HMAC-SHA-256(key, msg).
func hmacSHA256(key, msg []byte) [32]byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg) // writing to a hash never returns an error
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// kdf2 derives two 32-byte keys from a key and an input.
func kdf2(key, input []byte) (out1, out2 [32]byte) {
	temp := hmacSHA256(key, input)
	out1 = hmacSHA256(temp[:], []byte{0x01})
	out2 = hmacSHA256(temp[:], append(out1[:], 0x02))
	return out1, out2
}
