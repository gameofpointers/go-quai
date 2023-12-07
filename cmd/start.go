package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/dominant-strategies/go-quai/cmd/utils"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/consensus/quai"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/p2p/node"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "starts a go-quai p2p node",
	Long: `starts the go-quai daemon. The daemon will start a libp2p node and a http API.
By default the node will bootstrap to the public bootstrap nodes and port 4001. 
To bootstrap to a private node, use the --bootstrap flag.`,
	RunE:                       runStart,
	SilenceUsage:               true,
	SuggestionsMinimumDistance: 2,
	Example:                    `go-quai start -log-level=debug`,
	PreRunE:                    startCmdPreRun,
}

func init() {
	rootCmd.AddCommand(startCmd)

	// IP address for p2p networking
	startCmd.PersistentFlags().StringP(utils.IPAddrFlag.Name, utils.IPAddrFlag.Abbreviation, utils.IPAddrFlag.DefaultValue, utils.IPAddrFlag.Usage)
	viper.BindPFlag(utils.IPAddrFlag.Name, startCmd.PersistentFlags().Lookup(utils.IPAddrFlag.Name))

	// p2p port for networking
	startCmd.PersistentFlags().StringP(utils.P2PPortFlag.Name, utils.P2PPortFlag.Abbreviation, utils.P2PPortFlag.DefaultValue, utils.P2PPortFlag.Usage)
	viper.BindPFlag(utils.P2PPortFlag.Name, startCmd.PersistentFlags().Lookup(utils.P2PPortFlag.Name))

	// isBootNode when set to true starts p2p node as a DHT boostrap server (no static peers required).
	startCmd.PersistentFlags().BoolP(utils.BootNodeFlag.Name, utils.BootNodeFlag.Abbreviation, utils.BootNodeFlag.DefaultValue, utils.BootNodeFlag.Usage)
	viper.BindPFlag(utils.BootNodeFlag.Name, startCmd.PersistentFlags().Lookup(utils.BootNodeFlag.Name))

	// initial peers to connect to and use for bootstrapping purposes
	startCmd.PersistentFlags().StringSliceP(utils.BootPeersFlag.Name, utils.BootPeersFlag.Abbreviation, utils.BootPeersFlag.DefaultValue, utils.BootPeersFlag.Usage)
	viper.BindPFlag(utils.BootPeersFlag.Name, startCmd.PersistentFlags().Lookup(utils.BootPeersFlag.Name))

	// enableNATPortMap configures libp2p to attempt to open a port in network's firewall using UPnP.
	// See https://pkg.go.dev/github.com/libp2p/go-libp2p@v0.31.0#NATPortMap
	startCmd.PersistentFlags().Bool(utils.PortMapFlag.Name, utils.PortMapFlag.DefaultValue, utils.PortMapFlag.Usage)
	viper.BindPFlag(utils.PortMapFlag.Name, startCmd.PersistentFlags().Lookup(utils.PortMapFlag.Name))

	// path to file containing node private key
	startCmd.PersistentFlags().StringP(utils.KeyFileFlag.Name, utils.KeyFileFlag.Abbreviation, utils.KeyFileFlag.DefaultValue, utils.KeyFileFlag.Usage)
	viper.BindPFlag(utils.KeyFileFlag.Name, startCmd.PersistentFlags().Lookup(utils.KeyFileFlag.Name))

	// look for more peers until we have at least min-peers
	startCmd.PersistentFlags().StringP(utils.MinPeersFlag.Name, utils.MinPeersFlag.Abbreviation, utils.MinPeersFlag.DefaultValue, utils.MinPeersFlag.Usage)
	viper.BindPFlag(utils.MinPeersFlag.Name, startCmd.PersistentFlags().Lookup(utils.MinPeersFlag.Name))

	// stop looking for more peers once we've reached max-peers
	startCmd.PersistentFlags().StringP(utils.MaxPeersFlag.Name, utils.MaxPeersFlag.Abbreviation, utils.MaxPeersFlag.DefaultValue, utils.MaxPeersFlag.Usage)
	viper.BindPFlag(utils.MaxPeersFlag.Name, startCmd.PersistentFlags().Lookup(utils.MaxPeersFlag.Name))

	// location ID
	startCmd.PersistentFlags().StringP(utils.LocationFlag.Name, utils.LocationFlag.Abbreviation, utils.LocationFlag.DefaultValue, utils.LocationFlag.Usage)
	viper.BindPFlag(utils.LocationFlag.Name, startCmd.PersistentFlags().Lookup(utils.LocationFlag.Name))

	// DB Engine Flag
	startCmd.PersistentFlags().String(utils.DBEngineFlag.Name, utils.DBEngineFlag.DefaultValue, utils.DBEngineFlag.Usage)
	viper.BindPFlag(utils.DBEngineFlag.Name, startCmd.PersistentFlags().Lookup(utils.DBEngineFlag.Name))

	// Keystore Directory Flag
	startCmd.PersistentFlags().String(utils.KeystoreDirFlag.Name, utils.KeystoreDirFlag.DefaultValue, utils.KeystoreDirFlag.Usage)
	viper.BindPFlag(utils.KeystoreDirFlag.Name, startCmd.PersistentFlags().Lookup(utils.KeystoreDirFlag.Name))

	// No USB Flag
	startCmd.PersistentFlags().Bool(utils.NoUSBFlag.Name, utils.NoUSBFlag.DefaultValue, utils.NoUSBFlag.Usage)
	viper.BindPFlag(utils.NoUSBFlag.Name, startCmd.PersistentFlags().Lookup(utils.NoUSBFlag.Name))

	// USB Flag
	startCmd.PersistentFlags().Bool(utils.USBFlag.Name, utils.USBFlag.DefaultValue, utils.USBFlag.Usage)
	viper.BindPFlag(utils.USBFlag.Name, startCmd.PersistentFlags().Lookup(utils.USBFlag.Name))

	// Network ID Flag
	startCmd.PersistentFlags().Uint64(utils.NetworkIdFlag.Name, utils.NetworkIdFlag.DefaultValue, utils.NetworkIdFlag.Usage)
	viper.BindPFlag(utils.NetworkIdFlag.Name, startCmd.PersistentFlags().Lookup(utils.NetworkIdFlag.Name))

	// Slices Running Flag
	startCmd.PersistentFlags().String(utils.SlicesRunningFlag.Name, utils.SlicesRunningFlag.DefaultValue, utils.SlicesRunningFlag.Usage)
	viper.BindPFlag(utils.SlicesRunningFlag.Name, startCmd.PersistentFlags().Lookup(utils.SlicesRunningFlag.Name))

	// Colosseum Flag
	startCmd.PersistentFlags().Bool(utils.ColosseumFlag.Name, utils.ColosseumFlag.DefaultValue, utils.ColosseumFlag.Usage)
	viper.BindPFlag(utils.ColosseumFlag.Name, startCmd.PersistentFlags().Lookup(utils.ColosseumFlag.Name))

	// Garden Flag
	startCmd.PersistentFlags().Bool(utils.GardenFlag.Name, utils.GardenFlag.DefaultValue, utils.GardenFlag.Usage)
	viper.BindPFlag(utils.GardenFlag.Name, startCmd.PersistentFlags().Lookup(utils.GardenFlag.Name))

	// Orchard Flag
	startCmd.PersistentFlags().Bool(utils.OrchardFlag.Name, utils.OrchardFlag.DefaultValue, utils.OrchardFlag.Usage)
	viper.BindPFlag(utils.OrchardFlag.Name, startCmd.PersistentFlags().Lookup(utils.OrchardFlag.Name))

	// Lighthouse Flag
	startCmd.PersistentFlags().Bool(utils.LighthouseFlag.Name, utils.LighthouseFlag.DefaultValue, utils.LighthouseFlag.Usage)
	viper.BindPFlag(utils.LighthouseFlag.Name, startCmd.PersistentFlags().Lookup(utils.LighthouseFlag.Name))

	// Local Flag
	startCmd.PersistentFlags().Bool(utils.LocalFlag.Name, utils.LocalFlag.DefaultValue, utils.LocalFlag.Usage)
	viper.BindPFlag(utils.LocalFlag.Name, startCmd.PersistentFlags().Lookup(utils.LocalFlag.Name))

	// Genesis Nonce Flag
	startCmd.PersistentFlags().Uint64(utils.GenesisNonceFlag.Name, utils.GenesisNonceFlag.DefaultValue, utils.GenesisNonceFlag.Usage)
	viper.BindPFlag(utils.GenesisNonceFlag.Name, startCmd.PersistentFlags().Lookup(utils.GenesisNonceFlag.Name))

	// Developer Flag
	startCmd.PersistentFlags().Bool(utils.DeveloperFlag.Name, utils.DeveloperFlag.DefaultValue, utils.DeveloperFlag.Usage)
	viper.BindPFlag(utils.DeveloperFlag.Name, startCmd.PersistentFlags().Lookup(utils.DeveloperFlag.Name))

	// Dev Period Flag
	startCmd.PersistentFlags().Int(utils.DevPeriodFlag.Name, utils.DevPeriodFlag.DefaultValue, utils.DevPeriodFlag.Usage)
	viper.BindPFlag(utils.DevPeriodFlag.Name, startCmd.PersistentFlags().Lookup(utils.DevPeriodFlag.Name))

	// Identity Flag
	startCmd.PersistentFlags().String(utils.IdentityFlag.Name, utils.IdentityFlag.DefaultValue, utils.IdentityFlag.Usage)
	viper.BindPFlag(utils.IdentityFlag.Name, startCmd.PersistentFlags().Lookup(utils.IdentityFlag.Name))

	// Doc Root Flag
	startCmd.PersistentFlags().String(utils.DocRootFlag.Name, utils.DocRootFlag.DefaultValue, utils.DocRootFlag.Usage)
	viper.BindPFlag(utils.DocRootFlag.Name, startCmd.PersistentFlags().Lookup(utils.DocRootFlag.Name))

	// Exit When Synced Flag
	startCmd.PersistentFlags().Bool(utils.ExitWhenSyncedFlag.Name, utils.ExitWhenSyncedFlag.DefaultValue, utils.ExitWhenSyncedFlag.Usage)
	viper.BindPFlag(utils.ExitWhenSyncedFlag.Name, startCmd.PersistentFlags().Lookup(utils.ExitWhenSyncedFlag.Name))

	// Iterative Output Flag
	startCmd.PersistentFlags().Bool(utils.IterativeOutputFlag.Name, utils.IterativeOutputFlag.DefaultValue, utils.IterativeOutputFlag.Usage)
	viper.BindPFlag(utils.IterativeOutputFlag.Name, startCmd.PersistentFlags().Lookup(utils.IterativeOutputFlag.Name))

	// Exclude Storage Flag
	startCmd.PersistentFlags().Bool(utils.ExcludeStorageFlag.Name, utils.ExcludeStorageFlag.DefaultValue, utils.ExcludeStorageFlag.Usage)
	viper.BindPFlag(utils.ExcludeStorageFlag.Name, startCmd.PersistentFlags().Lookup(utils.ExcludeStorageFlag.Name))

	// Include Incompletes Flag
	startCmd.PersistentFlags().Bool(utils.IncludeIncompletesFlag.Name, utils.IncludeIncompletesFlag.DefaultValue, utils.IncludeIncompletesFlag.Usage)
	viper.BindPFlag(utils.IncludeIncompletesFlag.Name, startCmd.PersistentFlags().Lookup(utils.IncludeIncompletesFlag.Name))

	// Exclude Code Flag
	startCmd.PersistentFlags().Bool(utils.ExcludeCodeFlag.Name, utils.ExcludeCodeFlag.DefaultValue, utils.ExcludeCodeFlag.Usage)
	viper.BindPFlag(utils.ExcludeCodeFlag.Name, startCmd.PersistentFlags().Lookup(utils.ExcludeCodeFlag.Name))

	// Start Key Flag
	startCmd.PersistentFlags().String(utils.StartKeyFlag.Name, utils.StartKeyFlag.DefaultValue, utils.StartKeyFlag.Usage)
	viper.BindPFlag(utils.StartKeyFlag.Name, startCmd.PersistentFlags().Lookup(utils.StartKeyFlag.Name))

	// Dump Limit Flag
	startCmd.PersistentFlags().Uint64(utils.DumpLimitFlag.Name, utils.DumpLimitFlag.DefaultValue, utils.DumpLimitFlag.Usage)
	viper.BindPFlag(utils.DumpLimitFlag.Name, startCmd.PersistentFlags().Lookup(utils.DumpLimitFlag.Name))

	// Sync Mode Flag
	// Cannot bind without getting issue. Is this flag still neccessary? Don't want to spend too much time on
	// deprecated flag
	// startCmd.PersistentFlags().Var(utils.SyncModeFlag.DefaultValue, utils.SyncModeFlag.Name, utils.SyncModeFlag.Usage)
	// viper.BindPFlag(utils.SyncModeFlag.Name, startCmd.PersistentFlags().Lookup(utils.SyncModeFlag.Name))

	// GC Mode Flag
	startCmd.PersistentFlags().String(utils.GCModeFlag.Name, utils.GCModeFlag.DefaultValue, utils.GCModeFlag.Usage)
	viper.BindPFlag(utils.GCModeFlag.Name, startCmd.PersistentFlags().Lookup(utils.GCModeFlag.Name))

	// Snapshot Flag
	startCmd.PersistentFlags().Bool(utils.SnapshotFlag.Name, utils.SnapshotFlag.DefaultValue, utils.SnapshotFlag.Usage)
	viper.BindPFlag(utils.SnapshotFlag.Name, startCmd.PersistentFlags().Lookup(utils.SnapshotFlag.Name))

	// Tx Lookup Limit Flag
	startCmd.PersistentFlags().Uint64(utils.TxLookupLimitFlag.Name, utils.TxLookupLimitFlag.DefaultValue, utils.TxLookupLimitFlag.Usage)
	viper.BindPFlag(utils.TxLookupLimitFlag.Name, startCmd.PersistentFlags().Lookup(utils.TxLookupLimitFlag.Name))

	// Light KDF Flag
	startCmd.PersistentFlags().Bool(utils.LightKDFFlag.Name, utils.LightKDFFlag.DefaultValue, utils.LightKDFFlag.Usage)
	viper.BindPFlag(utils.LightKDFFlag.Name, startCmd.PersistentFlags().Lookup(utils.LightKDFFlag.Name))

	// Whitelist Flag
	startCmd.PersistentFlags().String(utils.WhitelistFlag.Name, utils.WhitelistFlag.DefaultValue, utils.WhitelistFlag.Usage)
	viper.BindPFlag(utils.WhitelistFlag.Name, startCmd.PersistentFlags().Lookup(utils.WhitelistFlag.Name))

	// Bloom Filter Size Flag
	startCmd.PersistentFlags().Uint64(utils.BloomFilterSizeFlag.Name, utils.BloomFilterSizeFlag.DefaultValue, utils.BloomFilterSizeFlag.Usage)
	viper.BindPFlag(utils.BloomFilterSizeFlag.Name, startCmd.PersistentFlags().Lookup(utils.BloomFilterSizeFlag.Name))

	// Transaction pool settings
	startCmd.PersistentFlags().String(utils.TxPoolLocalsFlag.Name, utils.TxPoolLocalsFlag.DefaultValue, utils.TxPoolLocalsFlag.Usage)
	viper.BindPFlag(utils.TxPoolLocalsFlag.Name, startCmd.PersistentFlags().Lookup(utils.TxPoolLocalsFlag.Name))

	startCmd.PersistentFlags().Bool(utils.TxPoolNoLocalsFlag.Name, utils.TxPoolNoLocalsFlag.DefaultValue, utils.TxPoolNoLocalsFlag.Usage)
	viper.BindPFlag(utils.TxPoolNoLocalsFlag.Name, startCmd.PersistentFlags().Lookup(utils.TxPoolNoLocalsFlag.Name))

	startCmd.PersistentFlags().String(utils.TxPoolJournalFlag.Name, utils.TxPoolJournalFlag.DefaultValue, utils.TxPoolJournalFlag.Usage)
	viper.BindPFlag(utils.TxPoolJournalFlag.Name, startCmd.PersistentFlags().Lookup(utils.TxPoolJournalFlag.Name))

	startCmd.PersistentFlags().Duration(utils.TxPoolRejournalFlag.Name, utils.TxPoolRejournalFlag.DefaultValue, utils.TxPoolRejournalFlag.Usage)
	viper.BindPFlag(utils.TxPoolRejournalFlag.Name, startCmd.PersistentFlags().Lookup(utils.TxPoolRejournalFlag.Name))

	startCmd.PersistentFlags().Uint64(utils.TxPoolPriceLimitFlag.Name, utils.TxPoolPriceLimitFlag.DefaultValue, utils.TxPoolPriceLimitFlag.Usage)
	viper.BindPFlag(utils.TxPoolPriceLimitFlag.Name, startCmd.PersistentFlags().Lookup(utils.TxPoolPriceLimitFlag.Name))

	startCmd.PersistentFlags().Uint64(utils.TxPoolPriceBumpFlag.Name, utils.TxPoolPriceBumpFlag.DefaultValue, utils.TxPoolPriceBumpFlag.Usage)
	viper.BindPFlag(utils.TxPoolPriceBumpFlag.Name, startCmd.PersistentFlags().Lookup(utils.TxPoolPriceBumpFlag.Name))

	startCmd.PersistentFlags().Uint64(utils.TxPoolAccountSlotsFlag.Name, utils.TxPoolAccountSlotsFlag.DefaultValue, utils.TxPoolAccountSlotsFlag.Usage)
	viper.BindPFlag(utils.TxPoolAccountSlotsFlag.Name, startCmd.PersistentFlags().Lookup(utils.TxPoolAccountSlotsFlag.Name))

	startCmd.PersistentFlags().Uint64(utils.TxPoolGlobalSlotsFlag.Name, utils.TxPoolGlobalSlotsFlag.DefaultValue, utils.TxPoolGlobalSlotsFlag.Usage)
	viper.BindPFlag(utils.TxPoolGlobalSlotsFlag.Name, startCmd.PersistentFlags().Lookup(utils.TxPoolGlobalSlotsFlag.Name))

	startCmd.PersistentFlags().Uint64(utils.TxPoolAccountQueueFlag.Name, utils.TxPoolAccountQueueFlag.DefaultValue, utils.TxPoolAccountQueueFlag.Usage)
	viper.BindPFlag(utils.TxPoolAccountQueueFlag.Name, startCmd.PersistentFlags().Lookup(utils.TxPoolAccountQueueFlag.Name))

	startCmd.PersistentFlags().Uint64(utils.TxPoolGlobalQueueFlag.Name, utils.TxPoolGlobalQueueFlag.DefaultValue, utils.TxPoolGlobalQueueFlag.Usage)
	viper.BindPFlag(utils.TxPoolGlobalQueueFlag.Name, startCmd.PersistentFlags().Lookup(utils.TxPoolGlobalQueueFlag.Name))

	startCmd.PersistentFlags().Duration(utils.TxPoolLifetimeFlag.Name, utils.TxPoolLifetimeFlag.DefaultValue, utils.TxPoolLifetimeFlag.Usage)
	viper.BindPFlag(utils.TxPoolLifetimeFlag.Name, startCmd.PersistentFlags().Lookup(utils.TxPoolLifetimeFlag.Name))

	// Cache settings
	startCmd.PersistentFlags().Int(utils.CacheFlag.Name, utils.CacheFlag.DefaultValue, utils.CacheFlag.Usage)
	viper.BindPFlag(utils.CacheFlag.Name, startCmd.PersistentFlags().Lookup(utils.CacheFlag.Name))

	startCmd.PersistentFlags().Int(utils.CacheDatabaseFlag.Name, utils.CacheDatabaseFlag.DefaultValue, utils.CacheDatabaseFlag.Usage)
	viper.BindPFlag(utils.CacheDatabaseFlag.Name, startCmd.PersistentFlags().Lookup(utils.CacheDatabaseFlag.Name))

	startCmd.PersistentFlags().Int(utils.CacheTrieFlag.Name, utils.CacheTrieFlag.DefaultValue, utils.CacheTrieFlag.Usage)
	viper.BindPFlag(utils.CacheTrieFlag.Name, startCmd.PersistentFlags().Lookup(utils.CacheTrieFlag.Name))

	startCmd.PersistentFlags().String(utils.CacheTrieJournalFlag.Name, utils.CacheTrieJournalFlag.DefaultValue, utils.CacheTrieJournalFlag.Usage)
	viper.BindPFlag(utils.CacheTrieJournalFlag.Name, startCmd.PersistentFlags().Lookup(utils.CacheTrieJournalFlag.Name))

	startCmd.PersistentFlags().Duration(utils.CacheTrieRejournalFlag.Name, utils.CacheTrieRejournalFlag.DefaultValue, utils.CacheTrieRejournalFlag.Usage)
	viper.BindPFlag(utils.CacheTrieRejournalFlag.Name, startCmd.PersistentFlags().Lookup(utils.CacheTrieRejournalFlag.Name))

	startCmd.PersistentFlags().Int(utils.CacheGCFlag.Name, utils.CacheGCFlag.DefaultValue, utils.CacheGCFlag.Usage)
	viper.BindPFlag(utils.CacheGCFlag.Name, startCmd.PersistentFlags().Lookup(utils.CacheGCFlag.Name))

	startCmd.PersistentFlags().Int(utils.CacheSnapshotFlag.Name, utils.CacheSnapshotFlag.DefaultValue, utils.CacheSnapshotFlag.Usage)
	viper.BindPFlag(utils.CacheSnapshotFlag.Name, startCmd.PersistentFlags().Lookup(utils.CacheSnapshotFlag.Name))

	startCmd.PersistentFlags().Bool(utils.CacheNoPrefetchFlag.Name, utils.CacheNoPrefetchFlag.DefaultValue, utils.CacheNoPrefetchFlag.Usage)
	viper.BindPFlag(utils.CacheNoPrefetchFlag.Name, startCmd.PersistentFlags().Lookup(utils.CacheNoPrefetchFlag.Name))

	startCmd.PersistentFlags().Bool(utils.CachePreimagesFlag.Name, utils.CachePreimagesFlag.DefaultValue, utils.CachePreimagesFlag.Usage)
	viper.BindPFlag(utils.CachePreimagesFlag.Name, startCmd.PersistentFlags().Lookup(utils.CachePreimagesFlag.Name))

	// Consensus settings
	startCmd.PersistentFlags().String(utils.ConsensusEngineFlag.Name, utils.ConsensusEngineFlag.DefaultValue, utils.ConsensusEngineFlag.Usage)
	viper.BindPFlag(utils.ConsensusEngineFlag.Name, startCmd.PersistentFlags().Lookup(utils.ConsensusEngineFlag.Name))

	// Miner settings
	startCmd.PersistentFlags().String(utils.MinerGasPriceFlag.Name, utils.MinerGasPriceFlag.DefaultValue.String(), utils.MinerGasPriceFlag.Usage)
	viper.BindPFlag(utils.MinerGasPriceFlag.Name, startCmd.PersistentFlags().Lookup(utils.MinerGasPriceFlag.Name))

	startCmd.PersistentFlags().String(utils.MinerEtherbaseFlag.Name, utils.MinerEtherbaseFlag.DefaultValue, utils.MinerEtherbaseFlag.Usage)
	viper.BindPFlag(utils.MinerEtherbaseFlag.Name, startCmd.PersistentFlags().Lookup(utils.MinerEtherbaseFlag.Name))

	// Account settings
	startCmd.PersistentFlags().String(utils.UnlockedAccountFlag.Name, utils.UnlockedAccountFlag.DefaultValue, utils.UnlockedAccountFlag.Usage)
	viper.BindPFlag(utils.UnlockedAccountFlag.Name, startCmd.PersistentFlags().Lookup(utils.UnlockedAccountFlag.Name))

	startCmd.PersistentFlags().String(utils.PasswordFileFlag.Name, utils.PasswordFileFlag.DefaultValue, utils.PasswordFileFlag.Usage)
	viper.BindPFlag(utils.PasswordFileFlag.Name, startCmd.PersistentFlags().Lookup(utils.PasswordFileFlag.Name))

	startCmd.PersistentFlags().String(utils.ExternalSignerFlag.Name, utils.ExternalSignerFlag.DefaultValue, utils.ExternalSignerFlag.Usage)
	viper.BindPFlag(utils.ExternalSignerFlag.Name, startCmd.PersistentFlags().Lookup(utils.ExternalSignerFlag.Name))

	// VM Debug settings
	startCmd.PersistentFlags().Bool(utils.VMEnableDebugFlag.Name, utils.VMEnableDebugFlag.DefaultValue, utils.VMEnableDebugFlag.Usage)
	viper.BindPFlag(utils.VMEnableDebugFlag.Name, startCmd.PersistentFlags().Lookup(utils.VMEnableDebugFlag.Name))

	startCmd.PersistentFlags().Bool(utils.InsecureUnlockAllowedFlag.Name, utils.InsecureUnlockAllowedFlag.DefaultValue, utils.InsecureUnlockAllowedFlag.Usage)
	viper.BindPFlag(utils.InsecureUnlockAllowedFlag.Name, startCmd.PersistentFlags().Lookup(utils.InsecureUnlockAllowedFlag.Name))

	// RPC settings
	startCmd.PersistentFlags().Uint64(utils.RPCGlobalGasCapFlag.Name, utils.RPCGlobalGasCapFlag.DefaultValue, utils.RPCGlobalGasCapFlag.Usage)
	viper.BindPFlag(utils.RPCGlobalGasCapFlag.Name, startCmd.PersistentFlags().Lookup(utils.RPCGlobalGasCapFlag.Name))

	startCmd.PersistentFlags().String(utils.QuaiStatsURLFlag.Name, utils.QuaiStatsURLFlag.DefaultValue, utils.QuaiStatsURLFlag.Usage)
	viper.BindPFlag(utils.QuaiStatsURLFlag.Name, startCmd.PersistentFlags().Lookup(utils.QuaiStatsURLFlag.Name))

	startCmd.PersistentFlags().Bool(utils.SendFullStatsFlag.Name, utils.SendFullStatsFlag.DefaultValue, utils.SendFullStatsFlag.Usage)
	viper.BindPFlag(utils.SendFullStatsFlag.Name, startCmd.PersistentFlags().Lookup(utils.SendFullStatsFlag.Name))

	startCmd.PersistentFlags().Bool(utils.FakePoWFlag.Name, utils.FakePoWFlag.DefaultValue, utils.FakePoWFlag.Usage)
	viper.BindPFlag(utils.FakePoWFlag.Name, startCmd.PersistentFlags().Lookup(utils.FakePoWFlag.Name))

	startCmd.PersistentFlags().Bool(utils.NoCompactionFlag.Name, utils.NoCompactionFlag.DefaultValue, utils.NoCompactionFlag.Usage)
	viper.BindPFlag(utils.NoCompactionFlag.Name, startCmd.PersistentFlags().Lookup(utils.NoCompactionFlag.Name))

	// HTTP RPC settings
	startCmd.PersistentFlags().Bool(utils.HTTPEnabledFlag.Name, utils.HTTPEnabledFlag.DefaultValue, utils.HTTPEnabledFlag.Usage)
	viper.BindPFlag(utils.HTTPEnabledFlag.Name, startCmd.PersistentFlags().Lookup(utils.HTTPEnabledFlag.Name))

	startCmd.PersistentFlags().String(utils.HTTPListenAddrFlag.Name, utils.HTTPListenAddrFlag.DefaultValue, utils.HTTPListenAddrFlag.Usage)
	viper.BindPFlag(utils.HTTPListenAddrFlag.Name, startCmd.PersistentFlags().Lookup(utils.HTTPListenAddrFlag.Name))

	startCmd.PersistentFlags().Int(utils.HTTPPortFlag.Name, utils.HTTPPortFlag.DefaultValue, utils.HTTPPortFlag.Usage)
	viper.BindPFlag(utils.HTTPPortFlag.Name, startCmd.PersistentFlags().Lookup(utils.HTTPPortFlag.Name))

	startCmd.PersistentFlags().String(utils.HTTPCORSDomainFlag.Name, utils.HTTPCORSDomainFlag.DefaultValue, utils.HTTPCORSDomainFlag.Usage)
	viper.BindPFlag(utils.HTTPCORSDomainFlag.Name, startCmd.PersistentFlags().Lookup(utils.HTTPCORSDomainFlag.Name))

	startCmd.PersistentFlags().String(utils.HTTPVirtualHostsFlag.Name, utils.HTTPVirtualHostsFlag.DefaultValue, utils.HTTPVirtualHostsFlag.Usage)
	viper.BindPFlag(utils.HTTPVirtualHostsFlag.Name, startCmd.PersistentFlags().Lookup(utils.HTTPVirtualHostsFlag.Name))

	startCmd.PersistentFlags().String(utils.HTTPApiFlag.Name, utils.HTTPApiFlag.DefaultValue, utils.HTTPApiFlag.Usage)
	viper.BindPFlag(utils.HTTPApiFlag.Name, startCmd.PersistentFlags().Lookup(utils.HTTPApiFlag.Name))

	startCmd.PersistentFlags().String(utils.HTTPPathPrefixFlag.Name, utils.HTTPPathPrefixFlag.DefaultValue, utils.HTTPPathPrefixFlag.Usage)
	viper.BindPFlag(utils.HTTPPathPrefixFlag.Name, startCmd.PersistentFlags().Lookup(utils.HTTPPathPrefixFlag.Name))

	startCmd.PersistentFlags().Bool(utils.WSEnabledFlag.Name, utils.WSEnabledFlag.DefaultValue, utils.WSEnabledFlag.Usage)
	viper.BindPFlag(utils.WSEnabledFlag.Name, startCmd.PersistentFlags().Lookup(utils.WSEnabledFlag.Name))

	startCmd.PersistentFlags().String(utils.WSListenAddrFlag.Name, utils.WSListenAddrFlag.DefaultValue, utils.WSListenAddrFlag.Usage)
	viper.BindPFlag(utils.WSListenAddrFlag.Name, startCmd.PersistentFlags().Lookup(utils.WSListenAddrFlag.Name))

	startCmd.PersistentFlags().Int(utils.WSPortFlag.Name, utils.WSPortFlag.DefaultValue, utils.WSPortFlag.Usage)
	viper.BindPFlag(utils.WSPortFlag.Name, startCmd.PersistentFlags().Lookup(utils.WSPortFlag.Name))

	startCmd.PersistentFlags().String(utils.WSApiFlag.Name, utils.WSApiFlag.DefaultValue, utils.WSApiFlag.Usage)
	viper.BindPFlag(utils.WSApiFlag.Name, startCmd.PersistentFlags().Lookup(utils.WSApiFlag.Name))

	startCmd.PersistentFlags().String(utils.WSAllowedOriginsFlag.Name, utils.WSAllowedOriginsFlag.DefaultValue, utils.WSAllowedOriginsFlag.Usage)
	viper.BindPFlag(utils.WSAllowedOriginsFlag.Name, startCmd.PersistentFlags().Lookup(utils.WSAllowedOriginsFlag.Name))

	startCmd.PersistentFlags().String(utils.WSPathPrefixFlag.Name, utils.WSPathPrefixFlag.DefaultValue, utils.WSPathPrefixFlag.Usage)
	viper.BindPFlag(utils.WSPathPrefixFlag.Name, startCmd.PersistentFlags().Lookup(utils.WSPathPrefixFlag.Name))

	startCmd.PersistentFlags().String(utils.ExecFlag.Name, utils.ExecFlag.DefaultValue, utils.ExecFlag.Usage)
	viper.BindPFlag(utils.ExecFlag.Name, startCmd.PersistentFlags().Lookup(utils.ExecFlag.Name))

	startCmd.PersistentFlags().String(utils.PreloadJSFlag.Name, utils.PreloadJSFlag.DefaultValue, utils.PreloadJSFlag.Usage)
	viper.BindPFlag(utils.PreloadJSFlag.Name, startCmd.PersistentFlags().Lookup(utils.PreloadJSFlag.Name))

	startCmd.PersistentFlags().Int(utils.MaxPendingPeersFlag.Name, utils.MaxPendingPeersFlag.DefaultValue, utils.MaxPendingPeersFlag.Usage)
	viper.BindPFlag(utils.MaxPendingPeersFlag.Name, startCmd.PersistentFlags().Lookup(utils.MaxPendingPeersFlag.Name))

	startCmd.PersistentFlags().String(utils.BootnodesFlag.Name, utils.BootnodesFlag.DefaultValue, utils.BootnodesFlag.Usage)
	viper.BindPFlag(utils.BootnodesFlag.Name, startCmd.PersistentFlags().Lookup(utils.BootnodesFlag.Name))

	startCmd.PersistentFlags().String(utils.NodeKeyFileFlag.Name, utils.NodeKeyFileFlag.DefaultValue, utils.NodeKeyFileFlag.Usage)
	viper.BindPFlag(utils.NodeKeyFileFlag.Name, startCmd.PersistentFlags().Lookup(utils.NodeKeyFileFlag.Name))

	startCmd.PersistentFlags().String(utils.NodeKeyHexFlag.Name, utils.NodeKeyHexFlag.DefaultValue, utils.NodeKeyHexFlag.Usage)
	viper.BindPFlag(utils.NodeKeyHexFlag.Name, startCmd.PersistentFlags().Lookup(utils.NodeKeyHexFlag.Name))

	startCmd.PersistentFlags().String(utils.NATFlag.Name, utils.NATFlag.DefaultValue, utils.NATFlag.Usage)
	viper.BindPFlag(utils.NATFlag.Name, startCmd.PersistentFlags().Lookup(utils.NATFlag.Name))

	startCmd.PersistentFlags().Bool(utils.NoDiscoverFlag.Name, utils.NoDiscoverFlag.DefaultValue, utils.NoDiscoverFlag.Usage)
	viper.BindPFlag(utils.NoDiscoverFlag.Name, startCmd.PersistentFlags().Lookup(utils.NoDiscoverFlag.Name))

	startCmd.PersistentFlags().Bool(utils.DiscoveryV5Flag.Name, utils.DiscoveryV5Flag.DefaultValue, utils.DiscoveryV5Flag.Usage)
	viper.BindPFlag(utils.DiscoveryV5Flag.Name, startCmd.PersistentFlags().Lookup(utils.DiscoveryV5Flag.Name))

	startCmd.PersistentFlags().String(utils.NetrestrictFlag.Name, utils.NetrestrictFlag.DefaultValue, utils.NetrestrictFlag.Usage)
	viper.BindPFlag(utils.NetrestrictFlag.Name, startCmd.PersistentFlags().Lookup(utils.NetrestrictFlag.Name))

	startCmd.PersistentFlags().String(utils.DNSDiscoveryFlag.Name, utils.DNSDiscoveryFlag.DefaultValue, utils.DNSDiscoveryFlag.Usage)
	viper.BindPFlag(utils.DNSDiscoveryFlag.Name, startCmd.PersistentFlags().Lookup(utils.DNSDiscoveryFlag.Name))

	startCmd.PersistentFlags().String(utils.JSpathFlag.Name, utils.JSpathFlag.DefaultValue, utils.JSpathFlag.Usage)
	viper.BindPFlag(utils.JSpathFlag.Name, startCmd.PersistentFlags().Lookup(utils.JSpathFlag.Name))

	startCmd.PersistentFlags().Int(utils.GpoBlocksFlag.Name, utils.GpoBlocksFlag.DefaultValue, utils.GpoBlocksFlag.Usage)
	viper.BindPFlag(utils.GpoBlocksFlag.Name, startCmd.PersistentFlags().Lookup(utils.GpoBlocksFlag.Name))

	startCmd.PersistentFlags().Int(utils.GpoPercentileFlag.Name, utils.GpoPercentileFlag.DefaultValue, utils.GpoPercentileFlag.Usage)
	viper.BindPFlag(utils.GpoPercentileFlag.Name, startCmd.PersistentFlags().Lookup(utils.GpoPercentileFlag.Name))

	startCmd.PersistentFlags().Int64(utils.GpoMaxGasPriceFlag.Name, utils.GpoMaxGasPriceFlag.DefaultValue, utils.GpoMaxGasPriceFlag.Usage)
	viper.BindPFlag(utils.GpoMaxGasPriceFlag.Name, startCmd.PersistentFlags().Lookup(utils.GpoMaxGasPriceFlag.Name))

	startCmd.PersistentFlags().Int64(utils.GpoIgnoreGasPriceFlag.Name, utils.GpoIgnoreGasPriceFlag.DefaultValue, utils.GpoIgnoreGasPriceFlag.Usage)
	viper.BindPFlag(utils.GpoIgnoreGasPriceFlag.Name, startCmd.PersistentFlags().Lookup(utils.GpoIgnoreGasPriceFlag.Name))

	startCmd.PersistentFlags().Bool(utils.MetricsEnabledFlag.Name, utils.MetricsEnabledFlag.DefaultValue, utils.MetricsEnabledFlag.Usage)
	viper.BindPFlag(utils.MetricsEnabledFlag.Name, startCmd.PersistentFlags().Lookup(utils.MetricsEnabledFlag.Name))

	startCmd.PersistentFlags().Bool(utils.MetricsEnabledExpensiveFlag.Name, utils.MetricsEnabledExpensiveFlag.DefaultValue, utils.MetricsEnabledExpensiveFlag.Usage)
	viper.BindPFlag(utils.MetricsEnabledExpensiveFlag.Name, startCmd.PersistentFlags().Lookup(utils.MetricsEnabledExpensiveFlag.Name))

	startCmd.PersistentFlags().String(utils.MetricsHTTPFlag.Name, utils.MetricsHTTPFlag.DefaultValue, utils.MetricsHTTPFlag.Usage)
	viper.BindPFlag(utils.MetricsHTTPFlag.Name, startCmd.PersistentFlags().Lookup(utils.MetricsHTTPFlag.Name))

	startCmd.PersistentFlags().Int(utils.MetricsPortFlag.Name, utils.MetricsPortFlag.DefaultValue, utils.MetricsPortFlag.Usage)
	viper.BindPFlag(utils.MetricsPortFlag.Name, startCmd.PersistentFlags().Lookup(utils.MetricsPortFlag.Name))

	startCmd.PersistentFlags().Bool(utils.MetricsEnableInfluxDBFlag.Name, utils.MetricsEnableInfluxDBFlag.DefaultValue, utils.MetricsEnableInfluxDBFlag.Usage)
	viper.BindPFlag(utils.MetricsEnableInfluxDBFlag.Name, startCmd.PersistentFlags().Lookup(utils.MetricsEnableInfluxDBFlag.Name))

	startCmd.PersistentFlags().String(utils.MetricsInfluxDBEndpointFlag.Name, utils.MetricsInfluxDBEndpointFlag.DefaultValue, utils.MetricsInfluxDBEndpointFlag.Usage)
	viper.BindPFlag(utils.MetricsInfluxDBEndpointFlag.Name, startCmd.PersistentFlags().Lookup(utils.MetricsInfluxDBEndpointFlag.Name))

	startCmd.PersistentFlags().String(utils.MetricsInfluxDBDatabaseFlag.Name, utils.MetricsInfluxDBDatabaseFlag.DefaultValue, utils.MetricsInfluxDBDatabaseFlag.Usage)
	viper.BindPFlag(utils.MetricsInfluxDBDatabaseFlag.Name, startCmd.PersistentFlags().Lookup(utils.MetricsInfluxDBDatabaseFlag.Name))

	startCmd.PersistentFlags().String(utils.MetricsInfluxDBUsernameFlag.Name, utils.MetricsInfluxDBUsernameFlag.DefaultValue, utils.MetricsInfluxDBUsernameFlag.Usage)
	viper.BindPFlag(utils.MetricsInfluxDBUsernameFlag.Name, startCmd.PersistentFlags().Lookup(utils.MetricsInfluxDBUsernameFlag.Name))

	startCmd.PersistentFlags().String(utils.MetricsInfluxDBPasswordFlag.Name, utils.MetricsInfluxDBPasswordFlag.DefaultValue, utils.MetricsInfluxDBPasswordFlag.Usage)
	viper.BindPFlag(utils.MetricsInfluxDBPasswordFlag.Name, startCmd.PersistentFlags().Lookup(utils.MetricsInfluxDBPasswordFlag.Name))

	startCmd.PersistentFlags().Bool(utils.ShowColorsFlag.Name, utils.ShowColorsFlag.DefaultValue, utils.ShowColorsFlag.Usage)
	viper.BindPFlag(utils.ShowColorsFlag.Name, startCmd.PersistentFlags().Lookup(utils.ShowColorsFlag.Name))

	startCmd.PersistentFlags().Bool(utils.LogToStdOutFlag.Name, utils.LogToStdOutFlag.DefaultValue, utils.LogToStdOutFlag.Usage)
	viper.BindPFlag(utils.LogToStdOutFlag.Name, startCmd.PersistentFlags().Lookup(utils.LogToStdOutFlag.Name))

	startCmd.PersistentFlags().String(utils.MetricsInfluxDBTagsFlag.Name, utils.MetricsInfluxDBTagsFlag.DefaultValue, utils.MetricsInfluxDBTagsFlag.Usage)
	viper.BindPFlag(utils.MetricsInfluxDBTagsFlag.Name, startCmd.PersistentFlags().Lookup(utils.MetricsInfluxDBTagsFlag.Name))

	startCmd.PersistentFlags().Int(utils.RegionFlag.Name, utils.RegionFlag.DefaultValue, utils.RegionFlag.Usage)
	viper.BindPFlag(utils.RegionFlag.Name, startCmd.PersistentFlags().Lookup(utils.RegionFlag.Name))

	startCmd.PersistentFlags().Int(utils.ZoneFlag.Name, utils.ZoneFlag.DefaultValue, utils.ZoneFlag.Usage)
	viper.BindPFlag(utils.ZoneFlag.Name, startCmd.PersistentFlags().Lookup(utils.ZoneFlag.Name))

	startCmd.PersistentFlags().String(utils.DomUrl.Name, utils.DomUrl.DefaultValue, utils.DomUrl.Usage)
	viper.BindPFlag(utils.DomUrl.Name, startCmd.PersistentFlags().Lookup(utils.DomUrl.Name))

	startCmd.PersistentFlags().String(utils.SubUrls.Name, utils.SubUrls.DefaultValue, utils.SubUrls.Usage)
	viper.BindPFlag(utils.SubUrls.Name, startCmd.PersistentFlags().Lookup(utils.SubUrls.Name))

}

func startCmdPreRun(cmd *cobra.Command, args []string) error {
	// set keyfile path
	if viper.GetString(utils.KeyFileFlag.Name) == "" {
		configDir := cmd.Flag(utils.ConfigDirFlag.Name).Value.String()
		viper.Set(utils.KeyFileFlag.Name, configDir+"private.key")
	}

	// if no bootstrap peers are provided, use the default ones defined in config/bootnodes.go
	if bootstrapPeers := viper.GetStringSlice(utils.BootPeersFlag.Name); len(bootstrapPeers) == 0 {
		log.Debugf("no bootstrap peers provided. Using default ones: %v", common.BootstrapPeers)
		viper.Set(utils.BootPeersFlag.Name, common.BootstrapPeers)
	}
	return nil
}

func runStart(cmd *cobra.Command, args []string) error {
	log.Infof("Starting go-quai")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// create a new p2p node
	node, err := node.NewNode(ctx)
	if err != nil {
		log.Fatalf("error creating node: %s", err)
	}

	// create instance of consensus backend
	consensus, err := quai.NewQuaiBackend()
	if err != nil {
		log.Fatalf("error creating consensus backend: %s", err)
	}

	// start the consensus backend
	consensus.SetP2PNode(node)
	if err := consensus.Start(); err != nil {
		log.Fatalf("error starting consensus backend: %s", err)
	}

	// start the p2p node
	node.SetConsensusBackend(consensus)
	if err := node.Start(); err != nil {
		log.Fatalf("error starting node: %s", err)
	}

	// wait for a SIGINT or SIGTERM signal
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	log.Warnf("Received 'stop' signal, shutting down gracefully...")
	cancel()
	if err := node.Stop(); err != nil {
		panic(err)
	}
	log.Warnf("Node is offline")
	return nil
}
