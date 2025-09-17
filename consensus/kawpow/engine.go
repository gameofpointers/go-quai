package kawpow

import (
	"errors"
	"math/big"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/consensus"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/log"
)

var (
	errZeroBlockTime    = errors.New("timestamp equals parent's")
	errTooManyUncles    = errors.New("too many uncles")
	errDuplicateUncle   = errors.New("duplicate uncle")
	errUncleIsAncestor  = errors.New("uncle is ancestor")
	errDanglingUncle    = errors.New("uncle's parent is not ancestor")
	errInvalidMixDigest = errors.New("invalid mix digest")
	errInvalidPoW       = errors.New("invalid proof-of-work")
)


// CheckWorkThreshold checks if the work meets the difficulty requirement
func (kawpow *Kawpow) CheckWorkThreshold(workObjectHeader *types.WorkObjectHeader, workShareThreshold int) bool {
	if workObjectHeader == nil {
		return false
	}

	powHash, err := kawpow.ComputePowHash(workObjectHeader)
	if err != nil {
		return false
	}

	threshold := consensus.CalcWorkShareThreshold(workObjectHeader, workShareThreshold)
	if threshold == nil {
		return false
	}

	return new(big.Int).SetBytes(powHash.Bytes()).Cmp(threshold) <= 0
}