package types

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// Helper function to serialize TxOut to wire format
func serializeRavencoinTxOut(value int64, pkScript []byte) []byte {
	return serializeTxOut(wire.NewTxOut(value, pkScript))
}

type ravencoinValidationTestCase struct {
	Name              string
	BlockHeight       uint32
	HeaderData        string
	CoinbaseData      string
	MerkleBranch      []string
	ExpectedMixHash   string
	ExpectedBlockHash string
}

var ravencoinValidationTests = []ravencoinValidationTestCase{
	{
		Name:        "KAWPOW Block 0 (Genesis-style)",
		BlockHeight: 0,
		HeaderData: "00000020" +
			"0000000000000000000000000000000000000000000000000000000000000000" +
			"3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a" +
			"29ab5f49" +
			"ffff001d" +
			"1dac2b7c",
		CoinbaseData: "01000000" +
			"01" +
			"0000000000000000000000000000000000000000000000000000000000000000" +
			"ffffffff" +
			"08" +
			"04ffff001d02fd04" +
			"ffffffff" +
			"01" +
			"00f2052a01000000" +
			"43" +
			"4104ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ac" +
			"00000000",
		MerkleBranch:      []string{},
		ExpectedMixHash:   "11f19805c58ab46610ff9c719dcf0a5f18fa2f1605798eef770c47219a39905b",
		ExpectedBlockHash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
	},
}

func TestRavencoinPowBlockHeader(t *testing.T) {
	const ravenActivationHeight = 1219736

	header := make([]byte, 120)
	header[3] = 0x20 // version 0x20000000
	header[68] = 0x20
	header[69] = 0xA7
	header[70] = 0xAC
	header[71] = 0x5E
	header[72] = 0xFF
	header[73] = 0xFF
	header[74] = 0x00
	header[75] = 0x1D
	header[76] = 0x98
	header[77] = 0x9C
	header[78] = 0x12
	header[79] = 0x00
	header[80] = 0x01
	header[81] = 0x02
	header[82] = 0x03
	header[83] = 0x04
	header[84] = 0x05
	header[85] = 0x06
	header[86] = 0x07
	header[87] = 0x08

	coinbase := wire.NewMsgTx(1)
	prevOut := wire.NewOutPoint(&chainhash.Hash{}, wire.MaxPrevOutIndex)
	scriptSig := BuildCoinbaseScriptSigWithNonce(
		ravenActivationHeight,
		0xDEADBEEF,
		0x1234567890ABCDEF,
		[]byte("Ravencoin Test"),
	)
	coinbase.AddTxIn(wire.NewTxIn(prevOut, scriptSig, nil))
	pkscript, _ := hex.DecodeString("76a914" + "89abcdefabbaabbaabbaabbaabbaabbaabbaabba" + "88ac")
	coinbase.AddTxOut(wire.NewTxOut(625000000, pkscript))

	auxPow := NewAuxPow(Kawpow, header, nil, nil, coinbase)
	require.NotNil(t, auxPow)
	require.Equal(t, Kawpow, auxPow.PowID())
	require.Len(t, auxPow.Header(), 120)
	require.NotNil(t, auxPow.Transaction())

	height, nonce1, nonce2, extra := ExtractNoncesFromCoinbase(scriptSig)
	require.Equal(t, uint32(ravenActivationHeight), height)
	require.Equal(t, uint32(0xDEADBEEF), nonce1)
	require.Equal(t, uint64(0x1234567890ABCDEF), nonce2)
	require.Equal(t, []byte("Ravencoin Test"), extra)
}

func TestRavencoinHeaderEncoding(t *testing.T) {
	header := NewRavencoinBlockHeader()
	header.Version = 0x20000000
	header.Height = 1219736
	header.Time = 1588788000
	header.Bits = 0x1d00ffff
	header.Nonce64 = 0x1234567890ABCDEF

	input := &RavencoinKAWPOWInput{
		Version:        header.Version,
		HashPrevBlock:  header.HashPrevBlock,
		HashMerkleRoot: header.HashMerkleRoot,
		Time:           header.Time,
		Bits:           header.Bits,
		Height:         header.Height,
	}

	encoded := input.EncodeBinaryRavencoinKAWPOW()
	require.GreaterOrEqual(t, len(encoded), 80)

	auxPow := NewAuxPow(Kawpow, encoded[:120], nil, nil, wire.NewMsgTx(1))
	require.NotNil(t, auxPow)
	require.Equal(t, Kawpow, auxPow.PowID())
}

func TestRavencoinCoinbaseFormat(t *testing.T) {
	tests := []struct {
		name        string
		height      uint32
		extraNonce1 uint32
		extraNonce2 uint64
		extraData   []byte
	}{
		{name: "Activation", height: 1219736, extraNonce1: 0xDEADBEEF, extraNonce2: 0x1234567890ABCDEF, extraData: []byte("Ravencoin Test")},
		{name: "Empty", height: 1500000, extraNonce1: 0x12345678, extraNonce2: 0xABCDEF0123456789, extraData: nil},
		{name: "Long", height: 1800000, extraNonce1: 0xCAFEBABE, extraNonce2: 0x1111111122222222, extraData: []byte("Long identifier for Ravencoin miner")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			coinbaseOut := serializeRavencoinTxOut(2500000000, []byte{0x76, 0xa9, 0x14})
			coinbase := CreateCoinbaseTxWithNonce(tc.height, tc.extraNonce1, tc.extraNonce2, tc.extraData, coinbaseOut)
			require.NotNil(t, coinbase)

			height, nonce1, nonce2, extra := ExtractNoncesFromCoinbase(coinbase.TxIn[0].SignatureScript)
			require.Equal(t, tc.height, height)
			require.Equal(t, tc.extraNonce1, nonce1)
			require.Equal(t, tc.extraNonce2, nonce2)
			require.Equal(t, tc.extraData, extra)
		})
	}
}

func TestRavencoinEngineSelection(t *testing.T) {
	workHeader := &WorkObjectHeader{}
	coinbaseOut := serializeRavencoinTxOut(2500000000, []byte{0x76, 0xa9, 0x14})
	coinbase := CreateCoinbaseTxWithNonce(1219736, 0x12345678, 0x123456789ABCDEF0, []byte("Ravencoin Engine"), coinbaseOut)
	auxPow := NewAuxPow(Kawpow, make([]byte, 80), nil, nil, coinbase)
	workHeader.auxPow = auxPow

	require.NotNil(t, workHeader.AuxPow())
	require.Equal(t, Kawpow, workHeader.AuxPow().PowID())

	scriptSig := auxPow.Transaction().TxIn[0].SignatureScript
	height, nonce1, nonce2, extra := ExtractNoncesFromCoinbase(scriptSig)
	require.Equal(t, uint32(1219736), height)
	require.Equal(t, uint32(0x12345678), nonce1)
	require.Equal(t, uint64(0x123456789ABCDEF0), nonce2)
	require.Equal(t, []byte("Ravencoin Engine"), extra)
}

func TestRavencoinProgpowDisambiguation(t *testing.T) {
	progpowAux := NewAuxPow(Progpow, make([]byte, 80), nil, nil, wire.NewMsgTx(1))
	ravencoinAux := NewAuxPow(Kawpow, make([]byte, 80), nil, nil, wire.NewMsgTx(1))

	require.Equal(t, Progpow, progpowAux.PowID())
	require.Equal(t, Kawpow, ravencoinAux.PowID())
	require.NotEqual(t, progpowAux.PowID(), ravencoinAux.PowID())
}

func TestRavencoinCoinbaseEncoding(t *testing.T) {
	coinbaseOut := serializeRavencoinTxOut(2500000000, []byte{0x76, 0xa9, 0x14, 0x89, 0xab, 0xcd, 0xef, 0x88, 0xac})
	coinbase := CreateCoinbaseTxWithNonce(1219736, 0x00000001, 0x0000000000000001, []byte("RVN"), coinbaseOut)
	height, nonce1, nonce2, extra := ExtractNoncesFromCoinbase(coinbase.TxIn[0].SignatureScript)
	require.Equal(t, uint32(1219736), height)
	require.Equal(t, uint32(0x00000001), nonce1)
	require.Equal(t, uint64(0x0000000000000001), nonce2)
	require.Equal(t, []byte("RVN"), extra)

	auxPow := NewAuxPow(Kawpow, make([]byte, 80), nil, nil, coinbase)
	require.NotNil(t, auxPow)
	require.Equal(t, Kawpow, auxPow.PowID())
}

func TestRavencoinMerkleIntegration(t *testing.T) {
	coinbaseOut := serializeRavencoinTxOut(2500000000, []byte{0x76, 0xa9, 0x14, 0x89, 0xab, 0xcd, 0xef, 0x88, 0xac})
	coinbase := CreateCoinbaseTxWithNonce(1219736, 0x11111111, 0x2222222233333333, []byte("Ravencoin Merkle"), coinbaseOut)
	tx2 := wire.NewMsgTx(2)
	tx2.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{}, Index: 0}, []byte{0x01, 0x02}, nil))
	tx2.AddTxOut(wire.NewTxOut(100000000, []byte{0x51}))

	transactions := []*wire.MsgTx{coinbase, tx2}
	merkleRoot := CalculateMerkleRootFromTxs(transactions)
	merkleTree := BuildMerkleTree(transactions)
	branch := ExtractMerkleBranch(merkleTree, len(transactions))
	coinbaseHash := coinbase.TxHash()
	require.True(t, VerifyMerkleProof(coinbaseHash, branch, merkleRoot))
}

func TestRavencoinBlockValidation(t *testing.T) {
	for _, test := range ravencoinValidationTests {
		t.Run(test.Name, func(t *testing.T) {
			headerBytes, err := hex.DecodeString(test.HeaderData)
			require.NoError(t, err)
			require.Equal(t, 80, len(headerBytes))

			coinbaseBytes, err := hex.DecodeString(test.CoinbaseData)
			require.NoError(t, err)

			var coinbaseTx wire.MsgTx
			require.NoError(t, coinbaseTx.Deserialize(bytes.NewReader(coinbaseBytes)))

			var branch [][]byte
			for _, hash := range test.MerkleBranch {
				b, err := hex.DecodeString(hash)
				require.NoError(t, err)
				branch = append(branch, b)
			}

			auxPow := NewAuxPow(Kawpow, headerBytes, nil, branch, &coinbaseTx)
			require.NotNil(t, auxPow)
			require.Equal(t, Kawpow, auxPow.PowID())
		})
	}
}

func TestRavencoinCoinbaseNonceExtraction(t *testing.T) {
	coinbaseOut := serializeRavencoinTxOut(2500000000, []byte{0x76, 0xa9, 0x14})
	coinbase := CreateCoinbaseTxWithNonce(1219736, 0xDEADBEEF, 0x1234567890ABCDEF, []byte("Ravencoin Test Block"), coinbaseOut)
	height, nonce1, nonce2, extra := ExtractNoncesFromCoinbase(coinbase.TxIn[0].SignatureScript)
	require.Equal(t, uint32(1219736), height)
	require.Equal(t, uint32(0xDEADBEEF), nonce1)
	require.Equal(t, uint64(0x1234567890ABCDEF), nonce2)
	require.Equal(t, []byte("Ravencoin Test Block"), extra)

	auxPow := NewAuxPow(Kawpow, make([]byte, 80), nil, nil, coinbase)
	require.NotNil(t, auxPow)
	require.Equal(t, Kawpow, auxPow.PowID())
}

func TestRavencoinMerkleRootCalculation(t *testing.T) {
	coinbaseOut := serializeRavencoinTxOut(2500000000, []byte{0x76, 0xa9, 0x14})
	coinbase := CreateCoinbaseTxWithHeight(1219736, []byte("Ravencoin Genesis"), coinbaseOut)
	tx2 := wire.NewMsgTx(2)
	tx2.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{}, Index: 0}, []byte{}, nil))
	tx2.AddTxOut(wire.NewTxOut(100000000, []byte{0x51}))

	transactions := []*wire.MsgTx{coinbase, tx2}
	merkleRoot := CalculateMerkleRootFromTxs(transactions)
	require.NotEqual(t, [32]byte{}, merkleRoot.Bytes())

	merkleTree := BuildMerkleTree(transactions)
	branch := ExtractMerkleBranch(merkleTree, len(transactions))
	coinbaseHash := coinbase.TxHash()
	require.True(t, VerifyMerkleProof(coinbaseHash, branch, merkleRoot))
}
