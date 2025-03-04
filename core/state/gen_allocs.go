package state

import (
	"math/big"

	"github.com/dominant-strategies/go-quai/cmd/genallocs"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/params"
)

// Will go through the balance schedule and add each one to the account's balance in state.
func (state *StateDB) AddLockedBalances(blockNum *big.Int, genesisAccounts []genallocs.GenesisAccount, log *log.Logger) error {
	// just add balance to the k quai setting address for testing
	addr := common.HexToAddress("0x004D979168B78dD6FC3c3db944Ce7a94baC125ea", common.Location{0, 0})
	addrInternal, _ := addr.InternalAddress()
	state.AddBalance(addrInternal, new(big.Int).Mul(big.NewInt(1000000), big.NewInt(1000000000000000000)))

	uintBlockNum := blockNum.Uint64()
	// Check if this block is a monthly unlock.
	if uintBlockNum%params.BlocksPerMonth == 0 || uintBlockNum == 1 {
		if uintBlockNum == 1 {
			uintBlockNum = 0
		}
		// Rotate through the accounts and apply the unlocks valid for this month.
		accountsAdded := 0
		for _, account := range genesisAccounts {
			accountAddr, err := account.Address.InternalAddress()
			if err != nil {
				return err
			}
			if balance, ok := account.BalanceSchedule.Get(uintBlockNum); ok && balance != nil {
				state.AddBalance(accountAddr, balance)
				accountsAdded += 1
			}
		}
		log.WithField("accountsAdded", accountsAdded).Debug("Allocated genesis accounts")
	}
	return nil
}
