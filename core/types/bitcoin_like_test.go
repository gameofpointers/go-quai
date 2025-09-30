package types

import (
	"encoding/hex"
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
	Dogecoin    []bitcoinLikeFixture `json:"dogecoin"`
}

type bitcoinLikeFixture struct {
	Height         int               `json:"height"`
	Version        int32             `json:"version"`
	HashPrevBlock  string            `json:"hash_prev_block"`
	HashMerkleRoot string            `json:"hash_merkle_root"`
	Time           uint32            `json:"time"`
	Bits           uint32            `json:"bits"`
	Nonce          uint32            `json:"nonce"`
	Hash           string            `json:"hash"`
	AuxPow         *ltcAuxPowFixture `json:"auxpow"`
}

// ltcAuxPowFixture models the AuxPoW JSON we added under the dogecoin set.
// Only the parentblock is required here for PoW validation (scrypt on parent).
type ltcAuxPowFixture struct {
	Tx struct {
		Txid string `json:"txid"`
		Hex  string `json:"hex"`
	} `json:"tx"`
	Index             int      `json:"index"`
	ChainIndex        int      `json:"chainindex"`
	MerkleBranch      []string `json:"merklebranch"`
	ChainMerkleBranch []string `json:"chainmerklebranch"`
	ParentBlock       string   `json:"parentblock"`
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

func buildDogecoinHeader(t *testing.T, f bitcoinLikeFixture) *DogecoinBlockHeader {
	t.Helper()
	hdr := &DogecoinBlockHeader{bitcoinLikeHeader: bitcoinLikeHeader{
		Version:        f.Version,
		HashPrevBlock:  hashFromHex(f.HashPrevBlock),
		HashMerkleRoot: hashFromHex(f.HashMerkleRoot),
		Time:           f.Time,
		Bits:           f.Bits,
		Nonce:          f.Nonce,
	}}
	if f.AuxPow != nil && f.AuxPow.ParentBlock != "" {
		// Decode hex parent block header (80 bytes) for legacy compatibility
		pb := common.FromHex(f.AuxPow.ParentBlock)

		// Build complete LitecoinAuxPoW structure for full validation
		hdr.LitecoinAuxPoW = &LitecoinAuxPoW{
			ParentHeader:      pb,
			CoinbaseTx:        common.FromHex(f.AuxPow.Tx.Hex),
			MerkleBranch:      f.AuxPow.MerkleBranch,
			ChainMerkleBranch: f.AuxPow.ChainMerkleBranch,
			ChainIndex:        f.AuxPow.ChainIndex,
		}
	}
	return hdr
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

func TestDogecoinHeaderFixtures(t *testing.T) {
	fixtures := mustLoadBitcoinLikeFixtures(t)
	for _, fixture := range fixtures.Dogecoin {
		fixture := fixture
		t.Run(fmt.Sprintf("height_%d", fixture.Height), func(t *testing.T) {
			header := buildDogecoinHeader(t, fixture)
			expectedHash := hashFromHex(fixture.Hash)

			encoded := header.EncodeBinary()
			require.Len(t, encoded, 80)

			decoded, err := DecodeDogecoinHeader(encoded)
			require.NoError(t, err)
			require.Equal(t, header.Version, decoded.Version)
			require.Equal(t, header.HashPrevBlock, decoded.HashPrevBlock)
			require.Equal(t, header.HashMerkleRoot, decoded.HashMerkleRoot)
			require.Equal(t, header.Time, decoded.Time)
			require.Equal(t, header.Bits, decoded.Bits)
			require.Equal(t, header.Nonce, decoded.Nonce)

			blockHash := header.Hash()
			require.Equal(t, expectedHash, blockHash)

			powHash, err := header.VerifyPow()
			require.NoError(t, err)
			// Dogecoin's PoW uses scrypt on the parent header, not SHA256d on the block header.
			require.NotEqual(t, blockHash, powHash)
			require.True(t, comparePoW(powHash, header.Bits))
		})
	}
}

// Negative tests: perturb AuxPoW inputs and expect validation to fail
func TestDogecoinHeaderFixtures_Negative(t *testing.T) {
	fixtures := mustLoadBitcoinLikeFixtures(t)
	for _, fixture := range fixtures.Dogecoin {
		fixture := fixture
		t.Run(fmt.Sprintf("neg_height_%d", fixture.Height), func(t *testing.T) {
			// Build a valid header first
			base := buildDogecoinHeader(t, fixture)
			require.NotNil(t, base.LitecoinAuxPoW)

			// 1) Corrupt parent header to break scrypt PoW
			t.Run("corrupt_parent_pow", func(t *testing.T) {
				h := *base // shallow copy struct
				aux := *base.LitecoinAuxPoW
				aux.ParentHeader = append([]byte(nil), aux.ParentHeader...)
				if len(aux.ParentHeader) >= 1 {
					aux.ParentHeader[0] ^= 0xFF
				}
				h.LitecoinAuxPoW = &aux
				_, err := h.VerifyPow()
				require.Error(t, err, "expected error when parent header PoW is invalid")
			})

			// 2) Corrupt coinbase tx to break merged-mining commitment parsing or value
			t.Run("corrupt_coinbase_tx", func(t *testing.T) {
				h := *base
				aux := *base.LitecoinAuxPoW
				aux.CoinbaseTx = append([]byte(nil), aux.CoinbaseTx...)
				if len(aux.CoinbaseTx) > 10 {
					aux.CoinbaseTx[10] ^= 0x01
				} else if len(aux.CoinbaseTx) > 0 {
					aux.CoinbaseTx[0] ^= 0x01
				}
				h.LitecoinAuxPoW = &aux
				_, err := h.VerifyPow()
				require.Error(t, err, "expected error when coinbase is corrupted")
			})

			// 3) Corrupt chain merkle branch to break chain commitment
			t.Run("corrupt_chain_merkle", func(t *testing.T) {
				h := *base
				aux := *base.LitecoinAuxPoW
				if len(aux.ChainMerkleBranch) > 0 && len(aux.ChainMerkleBranch[0]) > 0 {
					br := make([]string, len(aux.ChainMerkleBranch))
					copy(br, aux.ChainMerkleBranch)
					hb := common.FromHex(br[0])
					if len(hb) > 0 {
						hb[0] ^= 0x01
					}
					br[0] = hex.EncodeToString(hb)
					aux.ChainMerkleBranch = br
				}
				h.LitecoinAuxPoW = &aux
				_, err := h.VerifyPow()
				require.Error(t, err, "expected error when chain merkle branch is corrupted")
			})

			// 4) Corrupt parent merkle branch (coinbase to parent merkle root)
			t.Run("corrupt_parent_merkle", func(t *testing.T) {
				h := *base
				aux := *base.LitecoinAuxPoW
				if len(aux.MerkleBranch) > 0 && len(aux.MerkleBranch[0]) > 0 {
					mb := make([]string, len(aux.MerkleBranch))
					copy(mb, aux.MerkleBranch)
					hb := common.FromHex(mb[0])
					if len(hb) > 0 {
						hb[len(hb)-1] ^= 0x01
					}
					mb[0] = hex.EncodeToString(hb)
					aux.MerkleBranch = mb
				}
				h.LitecoinAuxPoW = &aux
				_, err := h.VerifyPow()
				require.Error(t, err, "expected error when parent merkle branch is corrupted")
			})
		})
	}
}
