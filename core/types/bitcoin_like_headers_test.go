package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBitcoinLikeHeaderConstructorsPreserveTimestamp(t *testing.T) {
	const timestamp = uint32(1710000000)
	tests := []struct {
		name  string
		powID PowID
	}{
		{name: "bitcoin", powID: SHA_BTC},
		{name: "bitcoin cash", powID: SHA_BCH},
		{name: "litecoin", powID: Scrypt},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := NewBlockHeader(tt.powID, 1, [32]byte{}, [32]byte{}, timestamp, 0x1d00ffff, 0, 0)
			require.NotNil(t, header)
			require.Equal(t, timestamp, header.Timestamp())
		})
	}
}
