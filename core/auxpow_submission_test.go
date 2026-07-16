package core

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
)

func TestDecodeSHA256dSubmission(t *testing.T) {
	const (
		height = uint32(840000)
		nTime  = uint32(1710000000)
		bits   = uint32(0x1d00ffff)
	)
	sealHash := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	coinbaseOut := []byte{0x00, 0x00, 0x00, 0x00, 0x00}

	tests := []struct {
		name  string
		powID types.PowID
	}{
		{name: "bitcoin", powID: types.SHA_BTC},
		{name: "bitcoin cash", powID: types.SHA_BCH},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			coinbase := types.NewAuxPowCoinbaseTx(tt.powID, height, coinbaseOut, sealHash, nTime)
			merkleRoot := types.CalculateMerkleRoot(tt.powID, coinbase, nil)
			header := types.NewBlockHeader(tt.powID, 1, [32]byte{}, merkleRoot, nTime, bits, 7, height)
			raw := append(header.Bytes(), byte(1))
			raw = append(raw, coinbase...)

			decodedHeader, decodedCoinbase, decodedSealHash, decodedHeight, err := decodeSHA256dSubmission(raw, tt.powID)
			require.NoError(t, err)
			require.Equal(t, header.Bytes(), decodedHeader.Bytes())
			require.Equal(t, header.PowHash(), decodedHeader.PowHash())
			require.Equal(t, coinbase, decodedCoinbase)
			require.Equal(t, sealHash, decodedSealHash)
			require.Equal(t, height, decodedHeight)
		})
	}
}

func TestDecodeSHA256dSubmissionRejectsWrongPowID(t *testing.T) {
	_, _, _, _, err := decodeSHA256dSubmission(make([]byte, bitcoinHeaderSize), types.Kawpow)
	require.ErrorContains(t, err, "unsupported SHA256d pow id")
}
