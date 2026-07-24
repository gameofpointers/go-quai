package core

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	bchdwire "github.com/gcash/bchd/wire"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
)

const bitcoinHeaderSize = 80

// decodeSHA256dSubmission decodes the common Bitcoin-style submission envelope
// while preserving the donor chain's concrete header type and PowID.
func decodeSHA256dSubmission(data []byte, powID types.PowID) (*types.AuxPowHeader, []byte, common.Hash, uint32, error) {
	if len(data) < bitcoinHeaderSize {
		return nil, nil, common.Hash{}, 0, fmt.Errorf("SHA256d block submission too short: %d bytes", len(data))
	}

	headerBytes := data[:bitcoinHeaderSize]
	var auxHeader *types.AuxPowHeader
	switch powID {
	case types.SHA_BTC:
		header := &wire.BlockHeader{}
		if err := header.Deserialize(bytes.NewReader(headerBytes)); err != nil {
			return nil, nil, common.Hash{}, 0, fmt.Errorf("decode Bitcoin header: %w", err)
		}
		auxHeader = types.NewAuxPowHeader(types.NewBitcoinHeaderWrapper(header))
	case types.SHA_BCH:
		header := &bchdwire.BlockHeader{}
		if err := header.Deserialize(bytes.NewReader(headerBytes)); err != nil {
			return nil, nil, common.Hash{}, 0, fmt.Errorf("decode Bitcoin Cash header: %w", err)
		}
		auxHeader = types.NewAuxPowHeader(types.NewBitcoinCashHeaderWrapper(header))
	default:
		return nil, nil, common.Hash{}, 0, fmt.Errorf("unsupported SHA256d pow id: %s", powID)
	}

	extra := data[bitcoinHeaderSize:]
	if len(extra) == 0 {
		return nil, nil, common.Hash{}, 0, errors.New("SHA256d block submission must include coinbase transaction after 80-byte header")
	}

	reader := bytes.NewReader(extra)
	txCount, err := wire.ReadVarInt(reader, 0)
	if err != nil {
		return nil, nil, common.Hash{}, 0, fmt.Errorf("read SHA256d transaction count: %w", err)
	}
	if txCount == 0 {
		return nil, nil, common.Hash{}, 0, errors.New("SHA256d block must have at least one transaction (coinbase)")
	}

	// reader now points immediately after the variable-length transaction count.
	coinbaseTx := extra[len(extra)-reader.Len():]
	scriptSig := types.ExtractScriptSigFromCoinbaseTx(coinbaseTx)
	if len(scriptSig) == 0 {
		return nil, nil, common.Hash{}, 0, errors.New("failed to extract scriptSig from SHA256d coinbase transaction")
	}

	sealHash, err := types.ExtractSealHashFromCoinbase(scriptSig)
	if err != nil {
		return nil, nil, common.Hash{}, 0, fmt.Errorf("extract seal hash from SHA256d block: %w", err)
	}
	height, err := types.ExtractHeightFromCoinbase(scriptSig)
	if err != nil {
		return nil, nil, common.Hash{}, 0, fmt.Errorf("extract height from SHA256d block: %w", err)
	}

	return auxHeader, coinbaseTx, sealHash, height, nil
}
