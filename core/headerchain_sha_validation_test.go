package core

import (
	"math/big"
	"testing"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/stretchr/testify/require"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/rawdb"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/params"
)

func TestUncleWorkShareClassificationSha(t *testing.T) {
	hc := NewTestHeaderChain()

	for _, powID := range []types.PowID{types.SHA_BTC, types.SHA_BCH} {
		t.Run(powID.String(), func(t *testing.T) {
			newShare := func(difficulty *big.Int) *types.WorkObjectHeader {
				share := types.EmptyWorkObject(common.ZONE_CTX).WorkObjectHeader()
				share.SetPrimeTerminusNumber(new(big.Int).SetUint64(params.KawPowForkBlock + 1))
				share.SetAuxPow(createTestAuxPow(powID, 1))
				share.SetShaDiffAndCount(types.NewPowShareDiffAndCount(difficulty, common.Big0, common.Big0))
				return share
			}

			require.Equal(t, types.Valid, hc.UncleWorkShareClassification(newShare(big.NewInt(1))))
			require.Equal(t, types.Invalid, hc.UncleWorkShareClassification(newShare(common.Big0)))
			require.Equal(t, types.Invalid, hc.UncleWorkShareClassification(newShare(new(big.Int).Set(common.Big2e256))))

			missingDifficulty := newShare(big.NewInt(1))
			missingDifficulty.SetShaDiffAndCount(types.NewPowShareDiffAndCount(nil, common.Big0, common.Big0))
			require.Equal(t, types.Invalid, hc.UncleWorkShareClassification(missingDifficulty))
		})
	}
}

func TestCheckPowIDValidityForShaWorkshares(t *testing.T) {
	hc := NewTestHeaderChain()
	primeTerminus := new(big.Int).SetUint64(params.KawPowForkBlock + params.KawPowTransitionPeriod + 1)

	for _, powID := range []types.PowID{types.SHA_BTC, types.SHA_BCH} {
		t.Run(powID.String(), func(t *testing.T) {
			share := types.EmptyWorkObject(common.ZONE_CTX).WorkObjectHeader()
			share.SetPrimeTerminusNumber(new(big.Int).Set(primeTerminus))
			share.SetAuxPow(createTestAuxPow(powID, 1))
			require.NoError(t, hc.CheckPowIdValidityForWorkshare(share))
			require.Error(t, hc.CheckPowIdValidity(share), "SHA work must not be accepted as a full Quai block")
		})
	}
}

func TestCountWorkSharesByAlgoCombinesBitcoinAndBitcoinCash(t *testing.T) {
	hc := NewTestHeaderChain()
	block := types.EmptyWorkObject(common.ZONE_CTX)

	btc := conversionStabilityWorkShare(types.SHA_BTC, false)
	bchUncled := conversionStabilityWorkShare(types.SHA_BCH, true)
	scrypt := conversionStabilityWorkShare(types.Scrypt, false)
	progpow := types.EmptyWorkObject(common.ZONE_CTX).WorkObjectHeader()
	block.Body().SetUncles([]*types.WorkObjectHeader{btc, bchUncled, scrypt, progpow})

	kawpow, sha, uncledSha, scryptCount, uncledScrypt := hc.CountWorkSharesByAlgo(block)
	require.Equal(t, 1, kawpow)
	require.Equal(t, 2, sha)
	require.Equal(t, 1, uncledSha)
	require.Equal(t, 1, scryptCount)
	require.Zero(t, uncledScrypt)
}

func TestVerifyUnclesValidatesShaAuxPow(t *testing.T) {
	db := rawdb.NewMemoryDatabase(log.Global)
	chainConfig := &params.ChainConfig{Location: common.Location{0, 0}}
	hc := NewTestHeaderChain()
	hc.headerDb = db
	hc.config = chainConfig
	hc.bc = NewTestBodyDb(db)
	hc.bc.chainConfig = chainConfig
	hc.headerCache, _ = lru.New[common.Hash, types.WorkObject](headerCacheLimit)
	hc.numberCache, _ = lru.New[common.Hash, uint64](numberCacheLimit)

	primeTerminus := new(big.Int).SetUint64(params.ControllerKickInBlock + 1)
	parentHash := types.EmptyRootHash
	for number := int64(7); number <= 9; number++ {
		ancestor := types.EmptyWorkObject(common.ZONE_CTX)
		ancestor.WorkObjectHeader().SetNumber(big.NewInt(number))
		ancestor.WorkObjectHeader().SetParentHash(parentHash)
		ancestor.WorkObjectHeader().SetPrimeTerminusNumber(new(big.Int).Set(primeTerminus))
		ancestor.WorkObjectHeader().SetData([]byte{0})
		rawdb.WriteTermini(db, ancestor.Hash(), types.EmptyTermini())
		hc.bc.WriteBlock(ancestor, common.ZONE_CTX)
		parentHash = ancestor.Hash()
	}
	shareParentHash := parentHash

	for _, powID := range []types.PowID{types.SHA_BTC, types.SHA_BCH} {
		t.Run(powID.String(), func(t *testing.T) {
			newBlock := func(shaDifficulty *big.Int) *types.WorkObject {
				share := types.EmptyWorkObject(common.ZONE_CTX).WorkObjectHeader()
				share.SetNumber(big.NewInt(10))
				share.SetParentHash(shareParentHash)
				share.SetPrimeTerminusNumber(new(big.Int).Set(primeTerminus))
				share.SetData([]byte{0})
				share.SetPrimaryCoinbase(common.ZeroAddress(common.Location{0, 0}))
				share.SetTime(1)
				share.SetShaDiffAndCount(types.NewPowShareDiffAndCount(shaDifficulty, common.Big0, common.Big0))

				sealHash := share.SealHash()
				coinbaseOut := []byte{0, 0, 0, 0, 0}
				coinbase := types.NewAuxPowCoinbaseTx(powID, 100, coinbaseOut, sealHash, 1)
				merkleRoot := types.CalculateMerkleRoot(powID, coinbase, nil)
				header := types.NewBlockHeader(powID, 1, types.EmptyRootHash, merkleRoot, 1, 0x1d00ffff, 0, 100)
				share.SetAuxPow(types.NewAuxPow(powID, header, []byte{}, []byte{}, [][]byte{}, coinbase))

				block := types.EmptyWorkObject(common.ZONE_CTX)
				block.WorkObjectHeader().SetNumber(big.NewInt(11))
				block.WorkObjectHeader().SetParentHash(shareParentHash)
				block.WorkObjectHeader().SetPrimeTerminusNumber(new(big.Int).Set(primeTerminus))
				block.Body().SetUncles([]*types.WorkObjectHeader{share})
				return block
			}

			// A zero SHA difficulty is rejected by SHA classification before ancestry checks.
			err := hc.VerifyUncles(newBlock(common.Big0))
			require.ErrorContains(t, err, "invalid proof of work")

			// Difficulty one makes the SHA proof valid, so validation reaches signature verification.
			err = hc.VerifyUncles(newBlock(big.NewInt(1)))
			require.ErrorContains(t, err, "invalid auxpow signature")

			wrongSealBlock := newBlock(big.NewInt(1))
			wrongSealShare := wrongSealBlock.Uncles()[0]
			wrongCoinbase := types.NewAuxPowCoinbaseTx(powID, 100, []byte{0, 0, 0, 0, 0}, types.EmptyRootHash, 1)
			wrongRoot := types.CalculateMerkleRoot(powID, wrongCoinbase, nil)
			wrongHeader := types.NewBlockHeader(powID, 1, types.EmptyRootHash, wrongRoot, 1, 0x1d00ffff, 0, 100)
			wrongSealShare.SetAuxPow(types.NewAuxPow(powID, wrongHeader, []byte{}, []byte{}, [][]byte{}, wrongCoinbase))
			err = hc.VerifyUncles(wrongSealBlock)
			require.ErrorContains(t, err, "coinbase seal hash does not match uncle seal hash")

			badMerkleBlock := newBlock(big.NewInt(1))
			badMerkleAuxPow := badMerkleBlock.Uncles()[0].AuxPow()
			mutatedCoinbase := append([]byte{}, badMerkleAuxPow.Transaction()...)
			mutatedCoinbase[len(mutatedCoinbase)-1] ^= 1
			badMerkleAuxPow.SetTransaction(mutatedCoinbase)
			err = hc.VerifyUncles(badMerkleBlock)
			require.ErrorContains(t, err, "invalid merkle root in auxpow")

			oldHeaderTimeBlock := newBlock(big.NewInt(1))
			oldHeaderTimeAuxPow := oldHeaderTimeBlock.Uncles()[0].AuxPow()
			oldHeader := types.NewBlockHeader(powID, 1, types.EmptyRootHash, oldHeaderTimeAuxPow.Header().MerkleRoot(), 0, 0x1d00ffff, 0, 100)
			oldHeaderTimeAuxPow.SetHeader(oldHeader)
			err = hc.VerifyUncles(oldHeaderTimeBlock)
			require.ErrorContains(t, err, "invalid auxpow signature")
		})
	}
}
