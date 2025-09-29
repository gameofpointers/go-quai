package types

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/stretchr/testify/require"
)

type bitcoinLikeFixtures struct {
	Bitcoin     []bitcoinLikeFixture `json:"bitcoin"`
	Litecoin    []bitcoinLikeFixture `json:"litecoin"`
	BitcoinCash []bitcoinLikeFixture `json:"bitcoin_cash"`
}

type bitcoinLikeFixture struct {
	Height         int    `json:"height"`
	Version        int32  `json:"version"`
	HashPrevBlock  string `json:"hash_prev_block"`
	HashMerkleRoot string `json:"hash_merkle_root"`
	Time           uint32 `json:"time"`
	Bits           uint32 `json:"bits"`
	Nonce          uint32 `json:"nonce"`
	Hash           string `json:"hash"`
}

func mustLoadBitcoinLikeFixtures(t *testing.T) bitcoinLikeFixtures {
	t.Helper()
	fixturePath := filepath.Join("bitcoin_like_headers_vectors.json")
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("unable to read fixtures: %v", err)
	}
	var fixtures bitcoinLikeFixtures
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatalf("unable to unmarshal fixtures: %v", err)
	}
	return fixtures
}

func hashFromHex(s string) common.Hash {
	normalized := strings.TrimPrefix(strings.ToLower(s), "0x")
	return common.HexToHash("0x" + normalized)
}

func buildBitcoinHeader(f bitcoinLikeFixture) *BitcoinBlockHeader {
	return &BitcoinBlockHeader{bitcoinLikeHeader{
		Version:        f.Version,
		HashPrevBlock:  hashFromHex(f.HashPrevBlock),
		HashMerkleRoot: hashFromHex(f.HashMerkleRoot),
		Time:           f.Time,
		Bits:           f.Bits,
		Nonce:          f.Nonce,
	}}
}

func buildLitecoinHeader(f bitcoinLikeFixture) *LitecoinBlockHeader {
	return &LitecoinBlockHeader{bitcoinLikeHeader{
		Version:        f.Version,
		HashPrevBlock:  hashFromHex(f.HashPrevBlock),
		HashMerkleRoot: hashFromHex(f.HashMerkleRoot),
		Time:           f.Time,
		Bits:           f.Bits,
		Nonce:          f.Nonce,
	}}
}

func buildBitcoinCashHeader(f bitcoinLikeFixture) *BitcoinCashBlockHeader {
	return &BitcoinCashBlockHeader{bitcoinLikeHeader{
		Version:        f.Version,
		HashPrevBlock:  hashFromHex(f.HashPrevBlock),
		HashMerkleRoot: hashFromHex(f.HashMerkleRoot),
		Time:           f.Time,
		Bits:           f.Bits,
		Nonce:          f.Nonce,
	}}
}

func TestBitcoinHeaderFixtures(t *testing.T) {
	fixtures := mustLoadBitcoinLikeFixtures(t)
	for _, fixture := range fixtures.Bitcoin {
		fixture := fixture
		t.Run(fmt.Sprintf("height_%d", fixture.Height), func(t *testing.T) {
			header := buildBitcoinHeader(fixture)
			expectedHash := hashFromHex(fixture.Hash)

			encoded := header.EncodeBinary()
			require.Len(t, encoded, 80)

			decoded, err := DecodeBitcoinHeader(encoded)
			require.NoError(t, err)
			require.Equal(t, header.Version, decoded.Version)
			require.Equal(t, header.HashPrevBlock, decoded.HashPrevBlock)
			require.Equal(t, header.HashMerkleRoot, decoded.HashMerkleRoot)
			require.Equal(t, header.Time, decoded.Time)
			require.Equal(t, header.Bits, decoded.Bits)
			require.Equal(t, header.Nonce, decoded.Nonce)

			blockHash := header.Hash()
			require.Equal(t, expectedHash, blockHash)

			powHash, valid := header.VerifyPow()
			require.True(t, valid)
			require.Equal(t, expectedHash, powHash)
		})
	}
}

func TestLitecoinHeaderFixtures(t *testing.T) {
	fixtures := mustLoadBitcoinLikeFixtures(t)
	for _, fixture := range fixtures.Litecoin {
		fixture := fixture
		t.Run(fmt.Sprintf("height_%d", fixture.Height), func(t *testing.T) {
			header := buildLitecoinHeader(fixture)
			expectedHash := hashFromHex(fixture.Hash)

			encoded := header.EncodeBinary()
			require.Len(t, encoded, 80)

			decoded, err := DecodeLitecoinHeader(encoded)
			require.NoError(t, err)
			require.Equal(t, header.Version, decoded.Version)
			require.Equal(t, header.HashPrevBlock, decoded.HashPrevBlock)
			require.Equal(t, header.HashMerkleRoot, decoded.HashMerkleRoot)
			require.Equal(t, header.Time, decoded.Time)
			require.Equal(t, header.Bits, decoded.Bits)
			require.Equal(t, header.Nonce, decoded.Nonce)

			blockHash := header.Hash()
			require.Equal(t, expectedHash, blockHash)

			powHash, valid := header.VerifyPow()
			require.True(t, valid)
			require.NotEqual(t, blockHash, powHash, "litecoin PoW uses scrypt, block hash uses SHA256d")
			require.True(t, comparePoW(powHash, header.Bits), "pow hash must satisfy target")
		})
	}
}

func TestBitcoinCashHeaderFixtures(t *testing.T) {
	fixtures := mustLoadBitcoinLikeFixtures(t)
	for _, fixture := range fixtures.BitcoinCash {
		fixture := fixture
		t.Run(fmt.Sprintf("height_%d", fixture.Height), func(t *testing.T) {
			header := buildBitcoinCashHeader(fixture)
			expectedHash := hashFromHex(fixture.Hash)

			encoded := header.EncodeBinary()
			require.Len(t, encoded, 80)

			decoded, err := DecodeBitcoinCashHeader(encoded)
			require.NoError(t, err)
			require.Equal(t, header.Version, decoded.Version)
			require.Equal(t, header.HashPrevBlock, decoded.HashPrevBlock)
			require.Equal(t, header.HashMerkleRoot, decoded.HashMerkleRoot)
			require.Equal(t, header.Time, decoded.Time)
			require.Equal(t, header.Bits, decoded.Bits)
			require.Equal(t, header.Nonce, decoded.Nonce)

			blockHash := header.Hash()
			require.Equal(t, expectedHash, blockHash)

			powHash, valid := header.VerifyPow()
			require.True(t, valid)
			require.Equal(t, expectedHash, powHash)
		})
	}
}
