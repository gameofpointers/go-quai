package types

import (
    "bytes"
    "io"

    "github.com/btcsuite/btcd/wire"
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
