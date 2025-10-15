package types

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/dominant-strategies/go-quai/common"
)

func compactToTarget(bits uint32) *big.Int {
	exponent := (bits >> 24) & 0xff
	mantissa := bits & 0x00ffffff

	target := new(big.Int).SetUint64(uint64(mantissa))
	shift := int(exponent) - 3
	if shift < 0 {
		target.Rsh(target, uint(-shift*8))
	} else {
		target.Lsh(target, uint(shift*8))
	}
	return target
}

func comparePoW(hash common.Hash, bits uint32) bool {
	hashNum := new(big.Int).SetBytes(hash.Bytes())
	target := compactToTarget(bits)
	return hashNum.Cmp(target) <= 0
}

func reverseBytesCopy(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

// reverseHexString reverses bytes of a hex string for merkle proof validation
func reverseHexString(s string) string {
	b, _ := hex.DecodeString(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return hex.EncodeToString(b)
}

func GetTargetFromBits(bits uint32) *big.Int {
	return compactToTarget(bits)
}

func GetTargetInHex(bits uint32) string {
	target := compactToTarget(bits)
	// Return as 64-character hex string (padded with leading zeros)
	return fmt.Sprintf("%064x", target)
}
