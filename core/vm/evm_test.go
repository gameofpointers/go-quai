package vm

import (
	"math/big"
	"testing"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/rawdb"
	"github.com/dominant-strategies/go-quai/core/state"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/ethdb"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/params"
	"github.com/stretchr/testify/require"
)

func TestDelegateCallWithOutOfScopeContract(t *testing.T) {

	statedb := state.NewDatabaseWithConfig(rawdb.NewMemoryDatabase(log.Global), nil)
	s, _ := state.New(types.EmptyRootHash, types.EmptyRootHash, big.NewInt(0), statedb, statedb, nil, common.Location{0, 0}, log.Global)

	chainConfig := params.TestChainConfig
	chainConfig.Location = common.Location{0, 0}

	evm := NewEVM(BlockContext{}, TxContext{}, s, chainConfig, Config{}, ethdb.HookedBatch{})
	// set the block number of the evm context
	evm.Context.BlockNumber = new(big.Int).SetInt64(1000000)

	newScopeContract := ScopeContext{}

	// send out of scope address
	addr := common.HexToAddress("0x01201De0D8854d63121c0cfF96Ae01cD3ef62414", common.Location{0, 0})

	_, _, err := evm.DelegateCall(newScopeContract.Contract, addr, []byte{}, 1000)
	if err != nil {
		require.Error(t, err)
	}
}

func TestDelegateCallAfterFork(t *testing.T) {

	statedb := state.NewDatabaseWithConfig(rawdb.NewMemoryDatabase(log.Global), nil)
	s, _ := state.New(types.EmptyRootHash, types.EmptyRootHash, big.NewInt(0), statedb, statedb, nil, common.Location{0, 0}, log.Global)

	chainConfig := params.TestChainConfig
	chainConfig.Location = common.Location{0, 0}

	code := []byte{10, 1, 2, 3, 4}

	addr := common.HexToAddress("0x00201De0D8854d63121c0cfF96Ae01cD3ef62414", common.Location{0, 0})
	addrInternal, err := addr.InternalAddress()
	require.NoError(t, err)

	evm := NewEVM(BlockContext{}, TxContext{}, s, chainConfig, Config{}, ethdb.HookedBatch{})
	// set the block number of the evm context
	evm.Context.BlockNumber = new(big.Int).SetInt64(1000000)
	evm.StateDB.SetCode(addrInternal, code)

	newScopeContract := ScopeContext{}
	newScopeContract.Contract = NewContract(AccountRef(addr), AccountRef(addr), common.Big10, 0)
	// add some code to the contract
	newScopeContract.Contract.Code = code

	_, _, err = evm.DelegateCall(newScopeContract.Contract, addr, []byte{}, 1000)
	require.Error(t, err)
}

func TestDelegateCallBeforeFork(t *testing.T) {

	statedb := state.NewDatabaseWithConfig(rawdb.NewMemoryDatabase(log.Global), nil)
	s, _ := state.New(types.EmptyRootHash, types.EmptyRootHash, big.NewInt(0), statedb, statedb, nil, common.Location{0, 0}, log.Global)

	chainConfig := params.TestChainConfig
	chainConfig.Location = common.Location{0, 0}

	code := []byte{10, 1, 2, 3, 4}

	addr := common.HexToAddress("0x00201De0D8854d63121c0cfF96Ae01cD3ef62414", common.Location{0, 0})
	addrInternal, err := addr.InternalAddress()
	require.NoError(t, err)

	evm := NewEVM(BlockContext{}, TxContext{}, s, chainConfig, Config{}, ethdb.HookedBatch{})
	// set the block number of the evm context
	evm.Context.BlockNumber = new(big.Int).SetInt64(100)
	evm.StateDB.SetCode(addrInternal, code)

	newScopeContract := ScopeContext{}
	newScopeContract.Contract = NewContract(AccountRef(addr), AccountRef(addr), common.Big10, 0)
	// add some code to the contract
	newScopeContract.Contract.Code = code

	// This should not bubble up the error as this is done before the fork
	_, _, err = evm.DelegateCall(newScopeContract.Contract, addr, []byte{}, 1000)
	require.NoError(t, err)
}
