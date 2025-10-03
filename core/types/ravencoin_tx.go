package types

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/wire"
	"github.com/dominant-strategies/go-quai/common"
)

// DecodeRavencoinTransaction decodes a Ravencoin transaction using the
// canonical non-witness wire encoding. Ravencoin blocks in the provided
// snapshot do not carry segwit data, so we force the base (legacy) encoding
// path while reusing wire.MsgTx.
func DecodeRavencoinTransaction(r io.Reader) (*wire.MsgTx, error) {
	msg := wire.NewMsgTx(1)
	if err := msg.BtcDecode(r, wire.ProtocolVersion, wire.WitnessEncoding); err != nil {
		return nil, err
	}
	return msg, nil
}

// DecodeRavencoinTransactionBytes decodes a Ravencoin transaction from a byte
// slice using the non-witness encoding.
func DecodeRavencoinTransactionBytes(data []byte) (*wire.MsgTx, error) {
	return DecodeRavencoinTransaction(bytes.NewReader(data))
}

// DecodeRavencoinCoinbaseTransaction attempts to deserialize the coinbase payload
// used in Ravencoin blocks. The payload may include a compact-encoded transaction
// count prefix; if that decode fails we fall back to treating the payload as a raw
// serialized transaction.
func DecodeRavencoinCoinbaseTransaction(extra []byte) (*wire.MsgTx, error) {
	reader := bytes.NewReader(extra)
	txCount, err := readCompactUint64(reader)
	if err == nil {
		if txCount == 0 {
			fallback, fallbackErr := decodeCoinbaseWithoutPrefix(extra)
			if fallbackErr != nil {
				return nil, fmt.Errorf("submitBlock payload missing coinbase transaction; fallback decode failed: %w", fallbackErr)
			}
			return fallback, nil
		}

		coinbaseTx := new(wire.MsgTx)
		decodeErr := coinbaseTx.Deserialize(reader)
		if decodeErr == nil {
			return coinbaseTx, nil
		}

		primaryErr := fmt.Errorf("decode coinbase tx: %w", decodeErr)
		fallback, fallbackErr := decodeCoinbaseWithoutPrefix(extra)
		if fallbackErr != nil {
			return nil, fmt.Errorf("%v; fallback decode failed: %w", primaryErr, fallbackErr)
		}
		return fallback, nil
	}

	// Failed to read a transaction count, fall back to treating the payload as a raw coinbase.
	fallback, fallbackErr := decodeCoinbaseWithoutPrefix(extra)
	if fallbackErr != nil {
		return nil, fmt.Errorf("decode tx count: %w; fallback decode failed: %v", err, fallbackErr)
	}
	return fallback, nil
}

// ExtractSealHashFromCoinbase scans a Ravencoin coinbase scriptSig and returns the
// embedded seal hash, if present.
func ExtractSealHashFromCoinbase(scriptSig []byte) (common.Hash, error) {
	if len(scriptSig) == 0 {
		return common.Hash{}, errors.New("coinbase scriptSig empty")
	}

	cursor := 0

	// First push must be the encoded height (ignore the actual value).
	_, consumed, err := parseScriptPush(scriptSig[cursor:])
	if err != nil {
		return common.Hash{}, fmt.Errorf("decode coinbase height: %w", err)
	}
	cursor += consumed

	for cursor < len(scriptSig) {
		sealBytes, consumed, err := parseScriptPush(scriptSig[cursor:])
		if err != nil {
			return common.Hash{}, fmt.Errorf("decode coinbase push: %w", err)
		}
		cursor += consumed

		if len(sealBytes) == common.HashLength {
			return common.BytesToHash(sealBytes), nil
		}

		if nested := searchSealHash(sealBytes); len(nested) == common.HashLength {
			return common.BytesToHash(nested), nil
		}
	}

	return common.Hash{}, errors.New("seal hash not found in coinbase script")
}

func decodeCoinbaseWithoutPrefix(extra []byte) (*wire.MsgTx, error) {
	coinbaseTx := new(wire.MsgTx)
	if err := coinbaseTx.Deserialize(bytes.NewReader(extra)); err != nil {
		return nil, err
	}
	return coinbaseTx, nil
}

func readCompactUint64(r *bytes.Reader) (uint64, error) {
	prefix, err := r.ReadByte()
	if err != nil {
		return 0, err
	}

	switch prefix {
	case 0xff:
		var buf [8]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, err
		}
		return binary.LittleEndian.Uint64(buf[:]), nil
	case 0xfe:
		var buf [4]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, err
		}
		return uint64(binary.LittleEndian.Uint32(buf[:])), nil
	case 0xfd:
		var buf [2]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, err
		}
		return uint64(binary.LittleEndian.Uint16(buf[:])), nil
	default:
		return uint64(prefix), nil
	}
}

func searchSealHash(payload []byte) []byte {
	idx := 0
	for idx < len(payload) {
		data, consumed, err := parseScriptPush(payload[idx:])
		if err != nil {
			return nil
		}
		idx += consumed

		if len(data) == common.HashLength {
			return data
		}
	}
	return nil
}

func parseScriptPush(script []byte) ([]byte, int, error) {
	if len(script) == 0 {
		return nil, 0, errors.New("empty script segment")
	}

	opcode := script[0]
	read := 1
	var dataLen int

	switch {
	case opcode <= 75:
		dataLen = int(opcode)
	case opcode == 0x4c: // OP_PUSHDATA1
		if len(script) < 2 {
			return nil, 0, errors.New("short OP_PUSHDATA1")
		}
		dataLen = int(script[1])
		read++
	case opcode == 0x4d: // OP_PUSHDATA2
		if len(script) < 3 {
			return nil, 0, errors.New("short OP_PUSHDATA2")
		}
		dataLen = int(binary.LittleEndian.Uint16(script[1:3]))
		read += 2
	default:
		return nil, 0, fmt.Errorf("unsupported opcode 0x%x in coinbase script", opcode)
	}

	if len(script) < read+dataLen {
		return nil, 0, errors.New("coinbase push exceeds script bounds")
	}

	return script[read : read+dataLen], read + dataLen, nil
}
