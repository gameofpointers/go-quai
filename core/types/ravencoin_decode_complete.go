package types

import (
	"github.com/btcsuite/btcd/wire"
)

// DecodeRavencoinHeaderWithCoinbase decodes a Ravencoin header and populates
// KAWPOW-specific fields from the associated coinbase transaction
func DecodeRavencoinHeaderWithCoinbase(headerData []byte, coinbaseTx *wire.MsgTx) (*RavencoinBlockHeader, error) {
	// First decode the standard 80-byte header
	header, err := DecodeRavencoinHeader(headerData)
	if err != nil {
		return nil, err
	}

	// If we have a coinbase transaction, extract KAWPOW fields from it
	if coinbaseTx != nil && len(coinbaseTx.TxIn) > 0 {
		scriptSig := coinbaseTx.TxIn[0].SignatureScript
		height, _, extraNonce2, _ := ExtractNoncesFromCoinbase(scriptSig)

		// Populate KAWPOW-specific fields
		header.Height = height
		header.Nonce64 = extraNonce2
		// MixHash would be set during mining when a valid solution is found
	}

	return header, nil
}

// EncodeCompleteRavencoinHeader creates a complete header with KAWPOW data
// and returns both the 80-byte header and the coinbase transaction
func EncodeCompleteRavencoinHeader(header *RavencoinBlockHeader, extraData []byte, minerAddress []byte, blockReward int64) ([]byte, *wire.MsgTx) {
	// Create the standard 80-byte header
	headerBytes := header.EncodeBinaryRavencoinHeader()

	// Create coinbase with KAWPOW nonces
	coinbaseTx := CreateCoinbaseTxWithNonce(
		header.Height,
		0, // extraNonce1 (pool nonce)
		header.Nonce64, // extraNonce2 (miner nonce)
		extraData,
		minerAddress,
		blockReward,
	)

	return headerBytes, coinbaseTx
}