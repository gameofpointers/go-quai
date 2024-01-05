package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	godebug "runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/adrg/xdg"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/common/constants"
	"github.com/dominant-strategies/go-quai/common/fdlimit"
	"github.com/dominant-strategies/go-quai/core"
	"github.com/dominant-strategies/go-quai/core/rawdb"
	"github.com/dominant-strategies/go-quai/ethdb"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/node"
	"github.com/dominant-strategies/go-quai/params"
	"github.com/dominant-strategies/go-quai/quai/gasprice"
	"github.com/dominant-strategies/go-quai/quai/quaiconfig"
	gopsutil "github.com/shirou/gopsutil/mem"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var GlobalFlags = []Flag{ConfigDirFlag, DataDirFlag,
	AncientDirFlag,
	LogLevelFlag,
	SaveConfigFlag,
}

var NodeFlags = []Flag{
	IPAddrFlag,
	P2PPortFlag,
	BootNodeFlag,
	BootPeersFlag,
	PortMapFlag,
	KeyFileFlag,
	MinPeersFlag,
	MaxPeersFlag,
	LocationFlag,
	SoloFlag,
	CoinbaseAddressFlag,
	DBEngineFlag,
	KeystoreDirFlag,
	NoUSBFlag,
	USBFlag,
	NetworkIdFlag,
	SlicesRunningFlag,
	ColosseumFlag,
	GardenFlag,
	OrchardFlag,
	LighthouseFlag,
	LocalFlag,
	GenesisNonceFlag,
	DeveloperFlag,
	DevPeriodFlag,
	IdentityFlag,
	DocRootFlag,
	ExitWhenSyncedFlag,
	IterativeOutputFlag,
	ExcludeStorageFlag,
	IncludeIncompletesFlag,
	ExcludeCodeFlag,
	StartKeyFlag,
	DumpLimitFlag,
	GCModeFlag,
	SnapshotFlag,
	TxLookupLimitFlag,
	LightKDFFlag,
	WhitelistFlag,
	BloomFilterSizeFlag,
	TxPoolLocalsFlag,
	TxPoolNoLocalsFlag,
	TxPoolJournalFlag,
	TxPoolRejournalFlag,
	TxPoolPriceLimitFlag,
	TxPoolPriceBumpFlag,
	TxPoolAccountSlotsFlag,
	TxPoolGlobalSlotsFlag,
	TxPoolAccountQueueFlag,
	TxPoolGlobalQueueFlag,
	TxPoolLifetimeFlag,
	CacheFlag,
	CacheDatabaseFlag,
	CacheTrieFlag,
	CacheTrieJournalFlag,
	CacheTrieRejournalFlag,
	CacheGCFlag,
	CacheSnapshotFlag,
	CacheNoPrefetchFlag,
	CachePreimagesFlag,
	ConsensusEngineFlag,
	MinerGasPriceFlag,
	UnlockedAccountFlag,
	PasswordFileFlag,
	ExternalSignerFlag,
	VMEnableDebugFlag,
	InsecureUnlockAllowedFlag,
	ShowColorsFlag,
	LogToStdOutFlag,
	MaxPendingPeersFlag,
	BootnodesFlag,
	NodeKeyFileFlag,
	NodeKeyHexFlag,
	NATFlag,
	NoDiscoverFlag,
	DiscoveryV5Flag,
	NetrestrictFlag,
	DNSDiscoveryFlag,
	JSpathFlag,
	GpoBlocksFlag,
	GpoPercentileFlag,
	GpoMaxGasPriceFlag,
	GpoIgnoreGasPriceFlag,
	FakePoWFlag,
	NoCompactionFlag,
	DomUrl,
	SubUrls,
}

var RPCFlags = []Flag{
	HTTPEnabledFlag,
	HTTPListenAddrFlag,
	HTTPPortFlag,
	HTTPCORSDomainFlag,
	HTTPVirtualHostsFlag,
	HTTPApiFlag,
	HTTPPathPrefixFlag,
	WSEnabledFlag,
	WSListenAddrFlag,
	WSPortFlag,
	WSApiFlag,
	WSAllowedOriginsFlag,
	WSPathPrefixFlag,
	ExecFlag,
	PreloadJSFlag,
	RPCGlobalTxFeeCapFlag,
	RPCGlobalGasCapFlag,
	QuaiStatsURLFlag,
	SendFullStatsFlag,
}

var (
	// ****************************************
	// **                                    **
	// **         LOCAL FLAGS                **
	// **                                    **
	// ****************************************
	IPAddrFlag = Flag{
		Name:         "ipaddr",
		Abbreviation: "i",
		Value:        "0.0.0.0",
		Usage:        "ip address to listen on" + generateEnvDoc("ipaddr"),
	}

	P2PPortFlag = Flag{
		Name:         "port",
		Abbreviation: "p",
		Value:        "4001",
		Usage:        "p2p port to listen on" + generateEnvDoc("port"),
	}

	BootNodeFlag = Flag{
		Name:         "bootnode",
		Abbreviation: "b",
		Value:        false,
		Usage:        "start the node as a boot node (no static peers required)" + generateEnvDoc("bootnode"),
	}

	BootPeersFlag = Flag{
		Name:  "bootpeers",
		Value: []string{},
		Usage: "list of bootstrap peers. Syntax: <multiaddress1>,<multiaddress2>,..." + generateEnvDoc("bootpeers"),
	}

	PortMapFlag = Flag{
		Name:  "portmap",
		Value: true,
		Usage: "enable NAT portmap" + generateEnvDoc("portmap"),
	}

	KeyFileFlag = Flag{
		Name:         "private.key",
		Abbreviation: "k",
		Value:        "",
		Usage:        "file containing node private key" + generateEnvDoc("keyfile"),
	}

	MinPeersFlag = Flag{
		Name:  "min-peers",
		Value: "5",
		Usage: "minimum number of peers to maintain connectivity with" + generateEnvDoc("min-peers"),
	}

	MaxPeersFlag = Flag{
		Name:  "max-peers",
		Value: "50",
		Usage: "maximum number of peers to maintain connectivity with" + generateEnvDoc("max-peers"),
	}

	LocationFlag = Flag{
		Name:  "location",
		Value: "",
		Usage: "region and zone location" + generateEnvDoc("location"),
	}

	SoloFlag = Flag{
		Name:         "solo",
		Abbreviation: "s",
		Value:        false,
		Usage:        "start the node as a solo node (will not reach out to bootstrap peers)" + generateEnvDoc("solo"),
	}

	// ****************************************
	// **                                    **
	// **         GLOBAL FLAGS               **
	// **                                    **
	// ****************************************
	ConfigDirFlag = Flag{
		Name:         "config-dir",
		Abbreviation: "c",
		Value:        xdg.ConfigHome + "/" + constants.APP_NAME + "/",
		Usage:        "config directory" + generateEnvDoc("config-dir"),
	}

	DataDirFlag = Flag{
		Name:         "data-dir",
		Abbreviation: "d",
		Value:        xdg.DataHome + "/" + constants.APP_NAME + "/",
		Usage:        "data directory" + generateEnvDoc("data-dir"),
	}

	AncientDirFlag = Flag{
		Name:  "datadir.ancient",
		Value: "",
		Usage: "Data directory for ancient chain segments (default = inside chaindata)" + generateEnvDoc("datadir.ancient"),
	}

	LogLevelFlag = Flag{
		Name:         "log-level",
		Abbreviation: "l",
		Value:        "info",
		Usage:        "log level (trace, debug, info, warn, error, fatal, panic)" + generateEnvDoc("log-level"),
	}

	SaveConfigFlag = Flag{
		Name:         "save-config",
		Abbreviation: "S",
		Value:        false,
		Usage:        "save/update config file with current config parameters" + generateEnvDoc("save-config"),
	}
	// ****************************************
	// ** 								     **
	// ** 	      IMPORTED FLAGS    		 **
	// ** 								     **
	// ****************************************
	DBEngineFlag = Flag{
		Name:  "db.engine",
		Value: "leveldb",
		Usage: "Backing database implementation to use ('leveldb' or 'pebble')" + generateEnvDoc("db.engine"),
	}
	// Is this the same as keyfile?
	KeystoreDirFlag = Flag{
		Name:  "keystore",
		Value: xdg.DataHome + "/" + constants.APP_NAME + "/",
		Usage: "Directory containing the node's private keys" + generateEnvDoc("keystore"),
	}

	NoUSBFlag = Flag{
		Name:  "no-usb",
		Value: false,
		Usage: "Disable USB hardware wallet support" + generateEnvDoc("no-usb"),
	}

	USBFlag = Flag{
		Name:  "usb",
		Value: false,
		Usage: "Enable monitoring and management of USB hardware wallets" + generateEnvDoc("usb"),
	}

	NetworkIdFlag = Flag{
		Name:  "networkid",
		Value: 1,
		Usage: "Explicitly set network id (integer)(For testnets: use --garden)" + generateEnvDoc("networkid"),
	}

	SlicesRunningFlag = Flag{
		Name:  "slices",
		Value: "",
		Usage: "All the slices that are running on this node" + generateEnvDoc("slices"),
	}

	ColosseumFlag = Flag{
		Name:  "colosseum",
		Value: false,
		Usage: "Quai Colosseum testnet" + generateEnvDoc("colosseum"),
	}

	GardenFlag = Flag{
		Name:  "garden",
		Value: false,
		Usage: "Garden network: pre-configured proof-of-work test network" + generateEnvDoc("garden"),
	}
	OrchardFlag = Flag{
		Name:  "orchard",
		Value: false,
		Usage: "Orchard network: pre-configured proof-of-work test network" + generateEnvDoc("orchard"),
	}
	LighthouseFlag = Flag{
		Name:  "lighthouse",
		Value: false,
		Usage: "Lighthouse network: pre-configured proof-of-work test network" + generateEnvDoc("lighthouse"),
	}
	LocalFlag = Flag{
		Name:  "local",
		Value: false,
		Usage: "Local network: localhost proof-of-work node, will not attempt to connect to bootnode or any public network" + generateEnvDoc("local"),
	}
	GenesisNonceFlag = Flag{
		Name:  "nonce",
		Value: 0,
		Usage: "Nonce to use for the genesis block (integer)" + generateEnvDoc("nonce"),
	}
	DeveloperFlag = Flag{
		Name:  "dev",
		Value: false,
		Usage: "Ephemeral proof-of-authority network with a pre-funded developer account, mining enabled" + generateEnvDoc("dev"),
	}
	DevPeriodFlag = Flag{
		Name:  "dev.period",
		Value: 0,
		Usage: "Block period to use for the dev network (integer) (0 = mine only if transaction pending)" + generateEnvDoc("dev.period"),
	}
	IdentityFlag = Flag{
		Name:  "identity",
		Value: "",
		Usage: "Custom node name" + generateEnvDoc("identity"),
	}
	DocRootFlag = Flag{
		Name:  "docroot",
		Value: xdg.DataHome,
		Usage: "Document Root for HTTPClient file scheme" + generateEnvDoc("docroot"),
	}

	// ****************************************
	// ** 								     **
	// ** 	      PY FLAGS    				 **
	// ** 								     **
	// ****************************************

	ExitWhenSyncedFlag = Flag{
		Name:  "exitwhensynced",
		Value: false,
		Usage: "Exits after block synchronisation completes" + generateEnvDoc("exitwhensynced"),
	}
	IterativeOutputFlag = Flag{
		Name:  "iterative",
		Value: true,
		Usage: "Print streaming JSON iteratively, delimited by newlines" + generateEnvDoc("iterative"),
	}
	ExcludeStorageFlag = Flag{
		Name:  "nostorage",
		Value: false,
		Usage: "Exclude storage entries (save db lookups)" + generateEnvDoc("nostorage"),
	}
	IncludeIncompletesFlag = Flag{
		Name:  "incompletes",
		Value: false,
		Usage: "Include accounts for which we don't have the address (missing preimage)" + generateEnvDoc("incompletes"),
	}
	ExcludeCodeFlag = Flag{
		Name:  "nocode",
		Value: false,
		Usage: "Exclude contract code (save db lookups)" + generateEnvDoc("nocode"),
	}
	StartKeyFlag = Flag{
		Name:  "start",
		Value: "0x0000000000000000000000000000000000000000000000000000000000000000",
		Usage: "Start position. Either a hash or address" + generateEnvDoc("start"),
	}
	DumpLimitFlag = Flag{
		Name:  "limit",
		Value: 0,
		Usage: "Max number of elements (0 = no limit)" + generateEnvDoc("limit"),
	}
	GCModeFlag = Flag{
		Name:  "gcmode",
		Value: "full",
		Usage: `Blockchain garbage collection mode ("full", "archive")` + generateEnvDoc("gcmode"),
	}

	SnapshotFlag = Flag{
		Name:  "snapshot",
		Value: true,
		Usage: `Enables snapshot-database mode (default = true)` + generateEnvDoc("snapshot"),
	}

	TxLookupLimitFlag = Flag{
		Name:  "txlookuplimit",
		Value: QuaiConfigDefaults.TxLookupLimit,
		Usage: "Number of recent blocks to maintain transactions index for (default = about one year, 0 = entire chain)" + generateEnvDoc("txlookuplimit"),
	}

	LightKDFFlag = Flag{
		Name:  "lightkdf",
		Value: false,
		Usage: "Reduce key-derivation RAM & CPU usage at some expense of KDF strength" + generateEnvDoc("lightkdf"),
	}

	WhitelistFlag = Flag{
		Name:  "whitelist",
		Value: "",
		Usage: "Comma separated block number-to-hash mappings to enforce (<number>=<hash>)" + generateEnvDoc("whitelist"),
	}

	BloomFilterSizeFlag = Flag{
		Name:  "bloomfilter.size",
		Value: 2048,
		Usage: "Megabytes of memory allocated to bloom-filter for pruning" + generateEnvDoc("bloomfilter.size"),
	}
	// Transaction pool settings
	TxPoolLocalsFlag = Flag{
		Name:  "txpool.locals",
		Value: "",
		Usage: "Comma separated accounts to treat as locals (no flush, priority inclusion)" + generateEnvDoc("txpool.locals"),
	}
	TxPoolNoLocalsFlag = Flag{
		Name:  "txpool.nolocals",
		Value: false,
		Usage: "Disables price exemptions for locally submitted transactions" + generateEnvDoc("txpool.nolocals"),
	}
	TxPoolJournalFlag = Flag{
		Name:  "txpool.journal",
		Value: CoreConfigDefaults.Journal,
		Usage: "Disk journal for local transaction to survive node restarts" + generateEnvDoc("txpool.journal"),
	}
	TxPoolRejournalFlag = Flag{
		Name:  "txpool.rejournal",
		Value: CoreConfigDefaults.Rejournal,
		Usage: "Time interval to regenerate the local transaction journal" + generateEnvDoc("txpool.rejournal"),
	}
	TxPoolPriceLimitFlag = Flag{
		Name:  "txpool.pricelimit",
		Value: QuaiConfigDefaults.TxPool.PriceLimit,
		Usage: "Minimum gas price limit to enforce for acceptance into the pool" + generateEnvDoc("txpool.pricelimit"),
	}
	TxPoolPriceBumpFlag = Flag{
		Name:  "txpool.pricebump",
		Value: QuaiConfigDefaults.TxPool.PriceBump,
		Usage: "Price bump percentage to replace an already existing transaction" + generateEnvDoc("txpool.pricebump"),
	}
	TxPoolAccountSlotsFlag = Flag{
		Name:  "txpool.accountslots",
		Value: QuaiConfigDefaults.TxPool.AccountSlots,
		Usage: "Minimum number of executable transaction slots guaranteed per account" + generateEnvDoc("txpool.accountslots"),
	}
	TxPoolGlobalSlotsFlag = Flag{
		Name:  "txpool.globalslots",
		Value: QuaiConfigDefaults.TxPool.GlobalSlots,
		Usage: "Maximum number of executable transaction slots for all accounts" + generateEnvDoc("txpool.globalslots"),
	}
	TxPoolAccountQueueFlag = Flag{
		Name:  "txpool.accountqueue",
		Value: QuaiConfigDefaults.TxPool.AccountQueue,
		Usage: "Maximum number of non-executable transaction slots permitted per account" + generateEnvDoc("txpool.accountqueue"),
	}
	TxPoolGlobalQueueFlag = Flag{
		Name:  "txpool.globalqueue",
		Value: QuaiConfigDefaults.TxPool.GlobalQueue,
		Usage: "Maximum number of non-executable transaction slots for all accounts" + generateEnvDoc("txpool.globalqueue"),
	}
	TxPoolLifetimeFlag = Flag{
		Name:  "txpool.lifetime",
		Value: QuaiConfigDefaults.TxPool.Lifetime,
		Usage: "Maximum amount of time non-executable transaction are queued" + generateEnvDoc("txpool.lifetime"),
	}
	CacheFlag = Flag{
		Name:  "cache",
		Value: 1024,
		Usage: "Megabytes of memory allocated to internal caching (default = 4096 quai full node, 128 light mode)" + generateEnvDoc("cache"),
	}
	CacheDatabaseFlag = Flag{
		Name:  "cache.database",
		Value: 50,
		Usage: "Percentage of cache memory allowance to use for database io" + generateEnvDoc("cache.database"),
	}
	CacheTrieFlag = Flag{
		Name:  "cache.trie",
		Value: 15,
		Usage: "Percentage of cache memory allowance to use for trie caching (default = 15% full mode, 30% archive mode)" + generateEnvDoc("cache.trie"),
	}
	CacheTrieJournalFlag = Flag{
		Name:  "cache.trie.journal",
		Value: QuaiConfigDefaults.TrieCleanCacheJournal,
		Usage: "Disk journal directory for trie cache to survive node restarts" + generateEnvDoc("cache.trie.journal"),
	}
	CacheTrieRejournalFlag = Flag{
		Name:  "cache.trie.rejournal",
		Value: QuaiConfigDefaults.TrieCleanCacheRejournal,
		Usage: "Time interval to regenerate the trie cache journal" + generateEnvDoc("cache.trie.rejournal"),
	}
	CacheGCFlag = Flag{
		Name:  "cache.gc",
		Value: 25,
		Usage: "Percentage of cache memory allowance to use for trie pruning (default = 25% full mode, 0% archive mode)" + generateEnvDoc("cache.gc"),
	}
	CacheSnapshotFlag = Flag{
		Name:  "cache.snapshot",
		Value: 10,
		Usage: "Percentage of cache memory allowance to use for snapshot caching (default = 10% full mode, 20% archive mode)" + generateEnvDoc("cache.snapshot"),
	}
	CacheNoPrefetchFlag = Flag{
		Name:  "cache.noprefetch",
		Value: false,
		Usage: "Disable heuristic state prefetch during block import (less CPU and disk IO, more time waiting for data)" + generateEnvDoc("cache.noprefetch"),
	}
	CachePreimagesFlag = Flag{
		Name:  "cache.preimages",
		Value: false,
		Usage: "Enable recording the SHA3/keccak preimages of trie keys" + generateEnvDoc("cache.preimages"),
	}
	// Consensus settings
	ConsensusEngineFlag = Flag{
		Name:  "consensus.engine",
		Value: "progpow",
		Usage: "Consensus engine that the blockchain will run and verify blocks using" + generateEnvDoc("consensus.engine"),
	}
	// Miner settings
	MinerGasPriceFlag = Flag{
		Name:  "miner.gasprice",
		Value: newBigIntValue(QuaiConfigDefaults.Miner.GasPrice),
		Usage: "Minimum gas price for mining a transaction" + generateEnvDoc("miner.gasprice"),
	}
	// Account settings
	UnlockedAccountFlag = Flag{
		Name:  "unlock",
		Value: "",
		Usage: "Comma separated list of accounts to unlock" + generateEnvDoc("unlock"),
	}

	PasswordFileFlag = Flag{
		Name:  "password",
		Value: "",
		Usage: "Password file to use for non-interactive password input" + generateEnvDoc("password"),
	}

	KeyStoreDirFlag = Flag{
		Name:  "keystore",
		Value: "",
		Usage: "Directory for the keystore (default = inside the datadir)",
	}
	ExternalSignerFlag = Flag{
		Name:  "signer",
		Value: "",
		Usage: "External signer (url or path to ipc file)" + generateEnvDoc("signer"),
	}

	VMEnableDebugFlag = Flag{
		Name:  "vmdebug",
		Value: false,
		Usage: "Record information useful for VM and contract debugging" + generateEnvDoc("vmdebug"),
	}
	InsecureUnlockAllowedFlag = Flag{
		Name:  "allow-insecure-unlock",
		Value: false,
		Usage: "Allow insecure account unlocking when account-related RPCs are exposed by http" + generateEnvDoc("allow-insecure-unlock"),
	}
	RPCGlobalTxFeeCapFlag = Flag{
		Name:  "rpc.txfeecap",
		Usage: "Sets a cap on transaction fee (in ether) that can be sent via the RPC APIs (0 = no cap)",
		Value: QuaiConfigDefaults.RPCTxFeeCap,
	}
	RPCGlobalGasCapFlag = Flag{
		Name:  "rpc.gascap",
		Value: QuaiConfigDefaults.RPCGasCap,
		Usage: "Sets a cap on gas that can be used in eth_call/estimateGas (0=infinite)" + generateEnvDoc("vmdebug"),
	}
	QuaiStatsURLFlag = Flag{
		Name:  "quaistats",
		Value: "",
		Usage: "Reporting URL of a quaistats service (nodename:secret@host:port)" + generateEnvDoc("quaistats"),
	}
	SendFullStatsFlag = Flag{
		Name:  "sendfullstats",
		Value: false,
		Usage: "Send full stats boolean flag for quaistats" + generateEnvDoc("sendfullstats"),
	}
	FakePoWFlag = Flag{
		Name:  "fakepow",
		Value: false,
		Usage: "Disables proof-of-work verification" + generateEnvDoc("fakepow"),
	}
	NoCompactionFlag = Flag{
		Name:  "nocompaction",
		Value: false,
		Usage: "Disables db compaction after import" + generateEnvDoc("nocompaction"),
	}
	// RPC settings
	HTTPEnabledFlag = Flag{
		Name:  "http",
		Value: false,
		Usage: "Enable the HTTP-RPC server" + generateEnvDoc("http"),
	}
	HTTPListenAddrFlag = Flag{
		Name:  "http.addr",
		Value: DefaultHTTPHost,
		Usage: "HTTP-RPC server listening interface" + generateEnvDoc("http.addr"),
	}
	HTTPPortFlag = Flag{
		Name:  "http.port",
		Value: DefaultHTTPPort,
		Usage: "HTTP-RPC server listening port" + generateEnvDoc("http.port"),
	}
	HTTPCORSDomainFlag = Flag{
		Name:  "http.corsdomain",
		Value: "",
		Usage: "Comma separated list of domains from which to accept cross origin requests (browser enforced)" + generateEnvDoc("http.corsdomain"),
	}
	HTTPVirtualHostsFlag = Flag{
		Name:  "http.vhosts",
		Value: strings.Join(NodeDefaultConfig.HTTPVirtualHosts, ","),
		Usage: "Comma separated list of virtual hostnames from which to accept requests (server enforced). Accepts '*' wildcard." + generateEnvDoc("http"),
	}
	HTTPApiFlag = Flag{
		Name:  "http.api",
		Value: "",
		Usage: "API's offered over the HTTP-RPC interface" + generateEnvDoc("http"),
	}
	HTTPPathPrefixFlag = Flag{
		Name:  "http.rpcprefix",
		Value: "",
		Usage: "HTTP path path prefix on which JSON-RPC is served. Use '/' to serve on all paths." + generateEnvDoc("http"),
	}

	WSEnabledFlag = Flag{
		Name:  "ws",
		Value: false,
		Usage: "Enable the WS-RPC server" + generateEnvDoc("ws"),
	}
	WSListenAddrFlag = Flag{
		Name:  "ws.addr",
		Value: DefaultWSHost,
		Usage: "WS-RPC server listening interface" + generateEnvDoc("ws"),
	}
	WSPortFlag = Flag{
		Name:  "ws.port",
		Value: DefaultWSPort,
		Usage: "WS-RPC server listening port" + generateEnvDoc("ws"),
	}
	WSApiFlag = Flag{
		Name:  "ws.api",
		Value: "",
		Usage: "API's offered over the WS-RPC interface" + generateEnvDoc("ws"),
	}
	WSAllowedOriginsFlag = Flag{
		Name:  "ws.origins",
		Value: "",
		Usage: "Origins from which to accept websockets requests" + generateEnvDoc("ws"),
	}
	WSPathPrefixFlag = Flag{
		Name:  "ws.rpcprefix",
		Value: "",
		Usage: "HTTP path prefix on which JSON-RPC is served. Use '/' to serve on all paths." + generateEnvDoc("ws"),
	}
	ExecFlag = Flag{
		Name:  "exec",
		Value: "",
		Usage: "Execute JavaScript statement" + generateEnvDoc("exec"),
	}
	PreloadJSFlag = Flag{
		Name:  "preload",
		Value: "",
		Usage: "Comma separated list of JavaScript files to preload into the console" + generateEnvDoc("preload"),
	}

	MaxPendingPeersFlag = Flag{
		Name:  "maxpendpeers",
		Value: NodeDefaultConfig.P2P.MaxPendingPeers,
		Usage: "Maximum number of pending connection attempts (defaults used if set to 0)" + generateEnvDoc("maxpendpeers"),
	}

	BootnodesFlag = Flag{
		Name:  "bootnodes",
		Value: "",
		Usage: "Comma separated enode URLs for P2P discovery bootstrap" + generateEnvDoc("bootnodes"),
	}

	NodeKeyFileFlag = Flag{
		Name:  "nodekey",
		Value: "",
		Usage: "P2P node key file" + generateEnvDoc("nodekey"),
	}
	NodeKeyHexFlag = Flag{
		Name:  "nodekeyhex",
		Value: "",
		Usage: "P2P node key as hex (for testing)" + generateEnvDoc("nodekeyhex"),
	}
	NATFlag = Flag{
		Name:  "nat",
		Value: "any",
		Usage: "NAT port mapping mechanism (any|none|upnp|pmp|extip:<IP>)" + generateEnvDoc("nat"),
	}

	NoDiscoverFlag = Flag{
		Name:  "nodiscover",
		Value: false,
		Usage: "Disables the peer discovery mechanism (manual peer addition)" + generateEnvDoc("nodiscover"),
	}

	DiscoveryV5Flag = Flag{
		Name:  "v5disc",
		Value: false,
		Usage: "Enables the experimental RLPx V5 (Topic Discovery) mechanism" + generateEnvDoc("v5disc"),
	}
	NetrestrictFlag = Flag{
		Name:  "netrestrict",
		Value: "",
		Usage: "Restricts network communication to the given IP networks (CIDR masks)" + generateEnvDoc("netrestrict"),
	}
	DNSDiscoveryFlag = Flag{
		Name:  "discovery.dns",
		Value: "",
		Usage: "Sets DNS discovery entry points (use '' to disable DNS)" + generateEnvDoc("discovery.dns"),
	}
	// ATM the url is left to the user and deployment to
	JSpathFlag = Flag{
		Name:  "jspath",
		Value: ".",
		Usage: "JavaScript root path for `loadScript`" + generateEnvDoc("jspath"),
	}
	// Gas price oracle settings
	GpoBlocksFlag = Flag{
		Name:  "gpo.blocks",
		Value: QuaiConfigDefaults.GPO.Blocks,
		Usage: "Number of recent blocks to check for gas prices" + generateEnvDoc("gpo.blocks"),
	}
	GpoPercentileFlag = Flag{
		Name:  "gpo.percentile",
		Value: QuaiConfigDefaults.GPO.Percentile,
		Usage: "Suggested gas price is the given percentile of a set of recent transaction gas prices" + generateEnvDoc("gpo.percentile"),
	}
	GpoMaxGasPriceFlag = Flag{
		Name:  "gpo.maxprice",
		Value: QuaiConfigDefaults.GPO.MaxPrice.Int64(),
		Usage: "Maximum gas price will be recommended by gpo" + generateEnvDoc("gpo.maxprice"),
	}
	GpoIgnoreGasPriceFlag = Flag{
		Name:  "gpo.ignoreprice",
		Value: QuaiConfigDefaults.GPO.IgnorePrice.Int64(),
		Usage: "Gas price below which gpo will ignore transactions" + generateEnvDoc("gpo.ignoreprice"),
	}

	ShowColorsFlag = Flag{
		Name:  "showcolors",
		Value: false,
		Usage: "Enable colorized logging" + generateEnvDoc("showcolors"),
	}

	LogToStdOutFlag = Flag{
		Name:  "logtostdout",
		Value: false,
		Usage: "Write log messages to stdout" + generateEnvDoc("logtostdout"),
	}
	DomUrl = Flag{
		Name:  "dom.url",
		Value: QuaiConfigDefaults.DomUrl,
		Usage: "Dominant chain websocket url" + generateEnvDoc("dom.url"),
	}
	SubUrls = Flag{
		Name:  "sub.urls",
		Value: QuaiConfigDefaults.DomUrl,
		Usage: "Subordinate chain websocket urls" + generateEnvDoc("sub.urls"),
	}
	CoinbaseAddressFlag = Flag{
		Name:  "coinbase",
		Value: "./coinbases.json",
		Usage: "Coinbase addresses" + generateEnvDoc("coinbase"),
	}
)

func ParseCoinbaseAddresses() (map[string]string, error) {
	coinbaseInput := viper.GetString(CoinbaseAddressFlag.Name)
	coinbaseMap := make(map[string]string)

	// Try to parse the input as JSON
	if err := json.Unmarshal([]byte(coinbaseInput), &coinbaseMap); err != nil {
		// If JSON parsing fails, treat it as a file path
		fileContent, fileErr := os.ReadFile(coinbaseInput)
		if fileErr != nil {
			log.Fatalf("Failed to parse input as JSON and failed to read file: %s", fileErr)
			return nil, fileErr
		}

		// Try to unmarshal the file content
		if err := json.Unmarshal(fileContent, &coinbaseMap); err != nil {
			log.Fatalf("Invalid JSON in file: %s", err)
			return nil, err
		}
	}

	// Fill in missing addresses with defaults
	for i := 0; i < Width; i++ {
		for j := 0; j < Width; j++ {
			hexKey := fmt.Sprintf("%X%X", i, j)
			if _, exists := coinbaseMap[hexKey]; !exists {
				coinbaseMap[hexKey] = DefaultCoinbaseMap[hexKey]
			}
		}
	}

	log.Infof("Coinbase Addresses: %v", coinbaseMap)

	return coinbaseMap, nil
}

func CreateAndBindFlag(flag Flag, cmd *cobra.Command) {
	switch val := flag.Value.(type) {
	case string:
		cmd.PersistentFlags().StringP(flag.GetName(), flag.GetAbbreviation(), val, flag.GetUsage())
	case bool:
		cmd.PersistentFlags().BoolP(flag.GetName(), flag.GetAbbreviation(), val, flag.GetUsage())
	case []string:
		cmd.PersistentFlags().StringSliceP(flag.GetName(), flag.GetAbbreviation(), val, flag.GetUsage())
	case time.Duration:
		cmd.PersistentFlags().DurationP(flag.GetName(), flag.GetAbbreviation(), val, flag.GetUsage())
	case int:
		cmd.PersistentFlags().IntP(flag.GetName(), flag.GetAbbreviation(), val, flag.GetUsage())
	case int64:
		cmd.PersistentFlags().Int64P(flag.GetName(), flag.GetAbbreviation(), val, flag.GetUsage())
	case uint64:
		cmd.PersistentFlags().Uint64P(flag.GetName(), flag.GetAbbreviation(), val, flag.GetUsage())
	case *TextMarshalerValue:
		cmd.PersistentFlags().VarP(val, flag.GetName(), flag.GetAbbreviation(), flag.GetUsage())
	case *BigIntValue:
		cmd.PersistentFlags().VarP(val, flag.GetName(), flag.GetAbbreviation(), flag.GetUsage())
	default:
		log.Error("Flag type not supported: " + flag.GetName() + ", " + fmt.Sprintf("%T", val))
	}
	viper.BindPFlag(flag.GetName(), cmd.PersistentFlags().Lookup(flag.GetName()))
}

// helper function that given a cobra flag name, returns the corresponding
// help legend for the equivalent environment variable
func generateEnvDoc(flag string) string {
	envVar := constants.ENV_PREFIX + "_" + strings.ReplaceAll(strings.ToUpper(flag), "-", "_")
	return fmt.Sprintf(" [%s]", envVar)
}

// setNodeUserIdent creates the user identifier from CLI flags.
func setNodeUserIdent(cfg *node.Config) {
	if identity := viper.GetString(IdentityFlag.Name); len(identity) > 0 {
		cfg.UserIdent = identity
	}
}

// SplitAndTrim splits input separated by a comma
// and trims excessive white space from the substrings.
func SplitAndTrim(input string) (ret []string) {
	l := strings.Split(input, ",")
	for _, r := range l {
		if r = strings.TrimSpace(r); r != "" {
			ret = append(ret, r)
		}
	}
	return ret
}

// setHTTP creates the HTTP RPC listener interface string from the set
// command line flags, returning empty if the HTTP endpoint is disabled.
func setHTTP(cfg *node.Config, nodeLocation common.Location) {
	if viper.GetBool(HTTPEnabledFlag.Name) && cfg.HTTPHost == "" {
		cfg.HTTPHost = "127.0.0.1"
		if viper.IsSet(HTTPListenAddrFlag.Name) {
			cfg.HTTPHost = viper.GetString(HTTPListenAddrFlag.Name)
		}
	}

	if nodeLocation == nil {
		cfg.HTTPPort = 9001
	} else if len(nodeLocation) == 1 {
		cfg.HTTPPort = 9002
	} else if len(nodeLocation) == 2 {
		cfg.HTTPPort = 9003
	}

	if viper.IsSet(HTTPCORSDomainFlag.Name) {
		cfg.HTTPCors = SplitAndTrim(viper.GetString(HTTPCORSDomainFlag.Name))
	}

	if viper.IsSet(HTTPApiFlag.Name) {
		cfg.HTTPModules = SplitAndTrim(viper.GetString(HTTPApiFlag.Name))
	}

	if viper.IsSet(HTTPVirtualHostsFlag.Name) {
		cfg.HTTPVirtualHosts = SplitAndTrim(viper.GetString(HTTPVirtualHostsFlag.Name))
	}

	if viper.IsSet(HTTPPathPrefixFlag.Name) {
		cfg.HTTPPathPrefix = viper.GetString(HTTPPathPrefixFlag.Name)
	}
}

// setWS creates the WebSocket RPC listener interface string from the set
// command line flags, returning empty if the HTTP endpoint is disabled.
func setWS(cfg *node.Config, nodeLocation common.Location) {
	if viper.GetBool(WSEnabledFlag.Name) && cfg.WSHost == "" {
		cfg.WSHost = "127.0.0.1"
		if viper.IsSet(WSListenAddrFlag.Name) {
			cfg.WSHost = viper.GetString(WSListenAddrFlag.Name)
		}
	}
	if nodeLocation == nil {
		cfg.WSPort = 8001
	} else if len(nodeLocation) == 1 {
		cfg.WSPort = 8002
	} else if len(nodeLocation) == 2 {
		cfg.WSPort = 8003
	}

	if viper.IsSet(WSAllowedOriginsFlag.Name) {
		cfg.WSOrigins = SplitAndTrim(viper.GetString(WSAllowedOriginsFlag.Name))
	}

	if viper.IsSet(WSApiFlag.Name) {
		cfg.WSModules = SplitAndTrim(viper.GetString(WSApiFlag.Name))
	}

	if viper.IsSet(WSPathPrefixFlag.Name) {
		cfg.WSPathPrefix = viper.GetString(WSPathPrefixFlag.Name)
	}
}

// setDomUrl sets the dominant chain websocket url.
func setDomUrl(cfg *quaiconfig.Config, nodeLocation common.Location) {
	// only set the dom url if the node is not prime
	if nodeLocation != nil {
		if len(nodeLocation) == 1 {
			cfg.DomUrl = "ws://127.0.0.1:8001"
		} else if len(nodeLocation) == 2 {
			cfg.DomUrl = "ws://127.0.0.1:8002"
		}
	}
	log.Info("Node", "Location", nodeLocation, "domurl", cfg.DomUrl)
}

// setSubUrls sets the subordinate chain urls
func setSubUrls(cfg *quaiconfig.Config, nodeLocation common.Location) {
	// only set the sub urls if its not the zone
	if len(nodeLocation) != 2 {
		if nodeLocation == nil {
			cfg.SubUrls = []string{"ws://127.0.0.1:8002"}
		} else if len(nodeLocation) == 1 {
			cfg.SubUrls = []string{"ws://127.0.0.1:8003"}
		}
	}
}

// setGasLimitCeil sets the gas limit ceils based on the network that is
// running
func setGasLimitCeil(cfg *quaiconfig.Config) {
	switch {
	case viper.GetBool(ColosseumFlag.Name):
		cfg.Miner.GasCeil = params.ColosseumGasCeil
	case viper.GetBool(GardenFlag.Name):
		cfg.Miner.GasCeil = params.GardenGasCeil
	case viper.GetBool(OrchardFlag.Name):
		cfg.Miner.GasCeil = params.OrchardGasCeil
	case viper.GetBool(LighthouseFlag.Name):
		cfg.Miner.GasCeil = params.LighthouseGasCeil
	case viper.GetBool(LocalFlag.Name):
		cfg.Miner.GasCeil = params.LocalGasCeil
	case viper.GetBool(DeveloperFlag.Name):
		cfg.Miner.GasCeil = params.LocalGasCeil
	default:
		cfg.Miner.GasCeil = params.ColosseumGasCeil
	}
}

// makeSubUrls returns the subordinate chain urls
func makeSubUrls() []string {
	return strings.Split(viper.GetString(SubUrls.Name), ",")
}

// setSlicesRunning sets the slices running flag
func setSlicesRunning(cfg *quaiconfig.Config) {
	slices := strings.Split(viper.GetString(SlicesRunningFlag.Name), ",")

	// Sanity checks
	if len(slices) == 0 {
		Fatalf("no slices are specified")
	}
	if len(slices) > common.NumRegionsInPrime*common.NumZonesInRegion {
		Fatalf("number of slices exceed the current ontology")
	}
	slicesRunning := []common.Location{}
	for _, slice := range slices {
		slicesRunning = append(slicesRunning, common.Location{slice[1] - 48, slice[3] - 48})
	}
	cfg.SlicesRunning = slicesRunning
}

// MakeDatabaseHandles raises out the number of allowed file handles per process
// for Quai and returns half of the allowance to assign to the database.
func MakeDatabaseHandles() int {
	limit, err := fdlimit.Maximum()
	if err != nil {
		Fatalf("Failed to retrieve file descriptor allowance: %v", err)
	}
	raised, err := fdlimit.Raise(uint64(limit))
	if err != nil {
		Fatalf("Failed to raise file descriptor allowance: %v", err)
	}
	return int(raised / 2) // Leave half for networking and other stuff
}

// HexAddress converts an account specified directly as a hex encoded string or
// a key index in the key store to an internal account representation.
func HexAddress(account string, nodeLocation common.Location) (common.Address, error) {
	// If the specified account is a valid address, return it
	if common.IsHexAddress(account) {
		return common.HexToAddress(account, nodeLocation), nil
	}
	return common.Address{}, errors.New("invalid account address")
}

// setEtherbase retrieves the etherbase either from the directly specified
// command line flags or from the keystore if CLI indexed.
func setEtherbase(cfg *quaiconfig.Config) {
	coinbaseMap, err := ParseCoinbaseAddresses()
	if err != nil {
		log.Fatalf("error parsing coinbase addresses: %s", err)
	}
	// TODO: Have to handle more shards in the future
	etherbase := coinbaseMap["00"]
	// Convert the etherbase into an address and configure it
	if etherbase != "" {
		account, err := HexAddress(etherbase, cfg.NodeLocation)
		if err != nil {
			Fatalf("Invalid miner etherbase: %v", err)
		}
		cfg.Miner.Etherbase = account
	}
}

// MakePasswordList reads password lines from the file specified by the global --password flag.
func MakePasswordList() []string {
	path := viper.GetString(PasswordFileFlag.Name)
	if path == "" {
		return nil
	}
	text, err := os.ReadFile(path)
	if err != nil {
		Fatalf("Failed to read password file: %v", err)
	}
	lines := strings.Split(string(text), "\n")
	// Sanitise DOS line endings.
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], "\r")
	}
	return lines
}

// SetNodeConfig applies node-related command line flags to the config.
func SetNodeConfig(cfg *node.Config, nodeLocation common.Location) {
	setHTTP(cfg, nodeLocation)
	setWS(cfg, nodeLocation)
	setNodeUserIdent(cfg)
	setDataDir(cfg)

	if viper.IsSet(ExternalSignerFlag.Name) {
		cfg.ExternalSigner = viper.GetString(ExternalSignerFlag.Name)
	}

	if viper.IsSet(KeyStoreDirFlag.Name) {
		cfg.KeyStoreDir = viper.GetString(KeyStoreDirFlag.Name)
	}
	if viper.IsSet(DeveloperFlag.Name) {
		cfg.UseLightweightKDF = true
	}
	if viper.IsSet(NoUSBFlag.Name) || cfg.NoUSB {
		log.Warn("Option nousb is deprecated and USB is deactivated by default. Use --usb to enable")
	}
	if viper.IsSet(USBFlag.Name) {
		cfg.USB = viper.GetBool(USBFlag.Name)
	}
	if viper.IsSet(InsecureUnlockAllowedFlag.Name) {
		cfg.InsecureUnlockAllowed = viper.GetBool(InsecureUnlockAllowedFlag.Name)
	}
	if viper.IsSet(DBEngineFlag.Name) {
		dbEngine := viper.GetString(DBEngineFlag.Name)
		if dbEngine != "leveldb" && dbEngine != "pebble" {
			Fatalf("Invalid choice for db.engine '%s', allowed 'leveldb' or 'pebble'", dbEngine)
		}
		log.Info(fmt.Sprintf("Using %s as db engine", dbEngine))
		cfg.DBEngine = dbEngine
	}
}

func setDataDir(cfg *node.Config) {
	switch {
	case viper.IsSet(DataDirFlag.Name):
		cfg.DataDir = viper.GetString(DataDirFlag.Name)
	case viper.GetBool(DeveloperFlag.Name):
		cfg.DataDir = "" // unless explicitly requested, use memory databases
	case viper.GetBool(GardenFlag.Name) && cfg.DataDir == node.DefaultDataDir():
		cfg.DataDir = filepath.Join(node.DefaultDataDir(), "garden")
	case viper.GetBool(OrchardFlag.Name) && cfg.DataDir == node.DefaultDataDir():
		cfg.DataDir = filepath.Join(node.DefaultDataDir(), "orchard")
	case viper.GetBool(LighthouseFlag.Name) && cfg.DataDir == node.DefaultDataDir():
		cfg.DataDir = filepath.Join(node.DefaultDataDir(), "lighthouse")
	case viper.GetBool(LocalFlag.Name) && cfg.DataDir == node.DefaultDataDir():
		cfg.DataDir = filepath.Join(node.DefaultDataDir(), "local")
	}
	// Set specific directory for node location within the hierarchy
	switch cfg.NodeLocation.Context() {
	case common.PRIME_CTX:
		cfg.DataDir = filepath.Join(cfg.DataDir, "prime")
	case common.REGION_CTX:
		regionNum := strconv.Itoa(cfg.NodeLocation.Region())
		cfg.DataDir = filepath.Join(cfg.DataDir, "region-"+regionNum)
	case common.ZONE_CTX:
		regionNum := strconv.Itoa(cfg.NodeLocation.Region())
		zoneNum := strconv.Itoa(cfg.NodeLocation.Zone())
		cfg.DataDir = filepath.Join(cfg.DataDir, "zone-"+regionNum+"-"+zoneNum)
	}
}

func setGPO(cfg *gasprice.Config) {
	if viper.IsSet(GpoBlocksFlag.Name) {
		cfg.Blocks = viper.GetInt(GpoBlocksFlag.Name)
	}
	if viper.IsSet(GpoPercentileFlag.Name) {
		cfg.Percentile = viper.GetInt(GpoPercentileFlag.Name)
	}
	if viper.IsSet(GpoMaxGasPriceFlag.Name) {
		cfg.MaxPrice = big.NewInt(viper.GetInt64(GpoMaxGasPriceFlag.Name))
	}
	if viper.IsSet(GpoIgnoreGasPriceFlag.Name) {
		cfg.IgnorePrice = big.NewInt(viper.GetInt64(GpoIgnoreGasPriceFlag.Name))
	}
}

func setTxPool(cfg *core.TxPoolConfig, nodeLocation common.Location) {
	if viper.IsSet(TxPoolLocalsFlag.Name) {
		locals := strings.Split(viper.GetString(TxPoolLocalsFlag.Name), ",")
		for _, account := range locals {
			if trimmed := strings.TrimSpace(account); !common.IsHexAddress(trimmed) {
				Fatalf("Invalid account in --txpool.locals: %s", trimmed)
			} else {
				internal, err := common.HexToAddress(account, nodeLocation).InternalAddress()
				if err != nil {
					Fatalf("Invalid account in --txpool.locals: %s", account)
				}
				cfg.Locals = append(cfg.Locals, internal)
			}
		}
	}
	if viper.IsSet(TxPoolNoLocalsFlag.Name) {
		cfg.NoLocals = viper.GetBool(TxPoolNoLocalsFlag.Name)
	}
	if viper.IsSet(TxPoolJournalFlag.Name) {
		cfg.Journal = viper.GetString(TxPoolJournalFlag.Name)
	}
	if viper.IsSet(TxPoolRejournalFlag.Name) {
		cfg.Rejournal = viper.GetDuration(TxPoolRejournalFlag.Name)
	}
	if viper.IsSet(TxPoolPriceLimitFlag.Name) {
		cfg.PriceLimit = viper.GetUint64(TxPoolPriceLimitFlag.Name)
	}
	if viper.IsSet(TxPoolPriceBumpFlag.Name) {
		cfg.PriceBump = viper.GetUint64(TxPoolPriceBumpFlag.Name)
	}
	if viper.IsSet(TxPoolAccountSlotsFlag.Name) {
		cfg.AccountSlots = viper.GetUint64(TxPoolAccountSlotsFlag.Name)
	}
	if viper.IsSet(TxPoolGlobalSlotsFlag.Name) {
		cfg.GlobalSlots = viper.GetUint64(TxPoolGlobalSlotsFlag.Name)
	}
	if viper.IsSet(TxPoolAccountQueueFlag.Name) {
		cfg.AccountQueue = viper.GetUint64(TxPoolAccountQueueFlag.Name)
	}
	if viper.IsSet(TxPoolGlobalQueueFlag.Name) {
		cfg.GlobalQueue = viper.GetUint64(TxPoolGlobalQueueFlag.Name)
	}
	if viper.IsSet(TxPoolLifetimeFlag.Name) {
		cfg.Lifetime = viper.GetDuration(TxPoolLifetimeFlag.Name)
	}
}

func setConsensusEngineConfig(cfg *quaiconfig.Config) {
	if cfg.ConsensusEngine == "blake3" {
		// Override any default configs for hard coded networks.
		switch {
		case viper.GetBool(ColosseumFlag.Name):
			cfg.Blake3Pow.DurationLimit = params.DurationLimit
			cfg.Blake3Pow.GasCeil = params.ColosseumGasCeil
			cfg.Blake3Pow.MinDifficulty = new(big.Int).Div(core.DefaultColosseumGenesisBlock(cfg.ConsensusEngine).Difficulty, common.Big2)
		case viper.GetBool(GardenFlag.Name):
			cfg.Blake3Pow.DurationLimit = params.GardenDurationLimit
			cfg.Blake3Pow.GasCeil = params.GardenGasCeil
			cfg.Blake3Pow.MinDifficulty = new(big.Int).Div(core.DefaultGardenGenesisBlock(cfg.ConsensusEngine).Difficulty, common.Big2)
		case viper.GetBool(OrchardFlag.Name):
			cfg.Blake3Pow.DurationLimit = params.OrchardDurationLimit
			cfg.Blake3Pow.GasCeil = params.OrchardGasCeil
			cfg.Blake3Pow.MinDifficulty = new(big.Int).Div(core.DefaultOrchardGenesisBlock(cfg.ConsensusEngine).Difficulty, common.Big2)
		case viper.GetBool(LighthouseFlag.Name):
			cfg.Blake3Pow.DurationLimit = params.LighthouseDurationLimit
			cfg.Blake3Pow.GasCeil = params.LighthouseGasCeil
			cfg.Blake3Pow.MinDifficulty = new(big.Int).Div(core.DefaultLighthouseGenesisBlock(cfg.ConsensusEngine).Difficulty, common.Big2)
		case viper.GetBool(LocalFlag.Name):
			cfg.Blake3Pow.DurationLimit = params.LocalDurationLimit
			cfg.Blake3Pow.GasCeil = params.LocalGasCeil
			cfg.Blake3Pow.MinDifficulty = new(big.Int).Div(core.DefaultLocalGenesisBlock(cfg.ConsensusEngine).Difficulty, common.Big2)
		case viper.GetBool(DeveloperFlag.Name):
			cfg.Blake3Pow.DurationLimit = params.DurationLimit
			cfg.Blake3Pow.GasCeil = params.LocalGasCeil
			cfg.Blake3Pow.MinDifficulty = new(big.Int).Div(core.DefaultLocalGenesisBlock(cfg.ConsensusEngine).Difficulty, common.Big2)
		default:
			cfg.Blake3Pow.DurationLimit = params.DurationLimit
			cfg.Blake3Pow.GasCeil = params.GasCeil
			cfg.Blake3Pow.MinDifficulty = new(big.Int).Div(core.DefaultColosseumGenesisBlock(cfg.ConsensusEngine).Difficulty, common.Big2)

		}
	} else {
		// Override any default configs for hard coded networks.
		switch {
		case viper.GetBool(ColosseumFlag.Name):
			cfg.Progpow.DurationLimit = params.DurationLimit
			cfg.Progpow.GasCeil = params.ColosseumGasCeil
			cfg.Progpow.MinDifficulty = new(big.Int).Div(core.DefaultColosseumGenesisBlock(cfg.ConsensusEngine).Difficulty, common.Big2)
		case viper.GetBool(GardenFlag.Name):
			cfg.Progpow.DurationLimit = params.GardenDurationLimit
			cfg.Progpow.GasCeil = params.GardenGasCeil
			cfg.Progpow.MinDifficulty = new(big.Int).Div(core.DefaultGardenGenesisBlock(cfg.ConsensusEngine).Difficulty, common.Big2)
		case viper.GetBool(OrchardFlag.Name):
			cfg.Progpow.DurationLimit = params.OrchardDurationLimit
			cfg.Progpow.GasCeil = params.OrchardGasCeil
			cfg.Progpow.GasCeil = params.ColosseumGasCeil
			cfg.Progpow.MinDifficulty = new(big.Int).Div(core.DefaultOrchardGenesisBlock(cfg.ConsensusEngine).Difficulty, common.Big2)
		case viper.GetBool(LighthouseFlag.Name):
			cfg.Progpow.DurationLimit = params.LighthouseDurationLimit
			cfg.Progpow.GasCeil = params.LighthouseGasCeil
			cfg.Progpow.MinDifficulty = new(big.Int).Div(core.DefaultLighthouseGenesisBlock(cfg.ConsensusEngine).Difficulty, common.Big2)
		case viper.GetBool(LocalFlag.Name):
			cfg.Progpow.DurationLimit = params.LocalDurationLimit
			cfg.Progpow.GasCeil = params.LocalGasCeil
			cfg.Progpow.MinDifficulty = new(big.Int).Div(core.DefaultLocalGenesisBlock(cfg.ConsensusEngine).Difficulty, common.Big2)
		case viper.GetBool(DeveloperFlag.Name):
			cfg.Progpow.DurationLimit = params.DurationLimit
			cfg.Progpow.GasCeil = params.LocalGasCeil
			cfg.Progpow.MinDifficulty = new(big.Int).Div(core.DefaultLocalGenesisBlock(cfg.ConsensusEngine).Difficulty, common.Big2)
		default:
			cfg.Progpow.DurationLimit = params.DurationLimit
			cfg.Progpow.GasCeil = params.GasCeil
			cfg.Progpow.MinDifficulty = new(big.Int).Div(core.DefaultColosseumGenesisBlock(cfg.ConsensusEngine).Difficulty, common.Big2)

		}
	}
}

func setWhitelist(cfg *quaiconfig.Config) {
	whitelist := viper.GetString(WhitelistFlag.Name)
	if whitelist == "" {
		return
	}
	cfg.Whitelist = make(map[uint64]common.Hash)
	for _, entry := range strings.Split(whitelist, ",") {
		parts := strings.Split(entry, "=")
		if len(parts) != 2 {
			Fatalf("Invalid whitelist entry: %s", entry)
		}
		number, err := strconv.ParseUint(parts[0], 0, 64)
		if err != nil {
			Fatalf("Invalid whitelist block number %s: %v", parts[0], err)
		}
		var hash common.Hash
		if err = hash.UnmarshalText([]byte(parts[1])); err != nil {
			Fatalf("Invalid whitelist hash %s: %v", parts[1], err)
		}
		cfg.Whitelist[number] = hash
	}
}

// CheckExclusive verifies that only a single instance of the provided flags was
// set by the user. Each flag might optionally be followed by a string type to
// specialize it further.
func CheckExclusive(args ...interface{}) {
	set := make([]string, 0, 1)
	for i := 0; i < len(args); i++ {
		// Ensure the argument is a string (flag name)
		flag, ok := args[i].(Flag)
		if !ok {
			panic(fmt.Sprintf("invalid argument, not string type: %T", args[i]))
		}

		// Check if the next arg extends the current flag
		if i+1 < len(args) {
			switch extension := args[i+1].(type) {
			case string:
				// Extended flag check
				if viper.GetString(flag.Name) == extension {
					set = append(set, "--"+flag.Name+"="+extension)
				}
				i++ // skip the next argument as it's processed
				continue
			case Flag:
			default:
				panic(fmt.Sprintf("invalid argument, not string extension: %T", args[i+1]))
			}
		}

		// Check if the flag is set
		if viper.IsSet(flag.Name) {
			set = append(set, "--"+flag.Name)
		}
	}

	if len(set) > 1 {
		Fatalf("Flags %v can't be used at the same time", strings.Join(set, ", "))
	}
}

// SetQuaiConfig applies quai-related command line flags to the config.
func SetQuaiConfig(stack *node.Node, cfg *quaiconfig.Config, nodeLocation common.Location) {
	// Avoid conflicting network flags
	CheckExclusive(ColosseumFlag, DeveloperFlag, GardenFlag, OrchardFlag, LocalFlag, LighthouseFlag)
	CheckExclusive(DeveloperFlag, ExternalSignerFlag) // Can't use both ephemeral unlocked and external signer

	if viper.GetString(GCModeFlag.Name) == "archive" && viper.GetUint64(TxLookupLimitFlag.Name) != 0 {
		// TODO: see what this is supposed to do
		viper.IsSet(TxLookupLimitFlag.Name)
		log.Warn("Disable transaction unindexing for archive node")
	}

	cfg.NodeLocation = nodeLocation
	// only set etherbase if its a zone chain
	if len(nodeLocation) == 2 {
		setEtherbase(cfg)
	}
	setGPO(&cfg.GPO)
	setTxPool(&cfg.TxPool, nodeLocation)

	// If blake3 consensus engine is specifically asked use the blake3 engine
	if viper.GetString(ConsensusEngineFlag.Name) == "blake3" {
		cfg.ConsensusEngine = "blake3"
	} else {
		cfg.ConsensusEngine = "progpow"
	}
	setConsensusEngineConfig(cfg)

	setWhitelist(cfg)

	// set the dominant chain websocket url
	setDomUrl(cfg, nodeLocation)

	// set the subordinate chain websocket urls
	setSubUrls(cfg, nodeLocation)

	// set the gas limit ceil
	setGasLimitCeil(cfg)

	// set the slices that the node is running
	setSlicesRunning(cfg)

	// Cap the cache allowance and tune the garbage collector
	mem, err := gopsutil.VirtualMemory()
	if err == nil {
		if 32<<(^uintptr(0)>>63) == 32 && mem.Total > 2*1024*1024*1024 {
			log.Warn("Lowering memory allowance on 32bit arch", "available", mem.Total/1024/1024, "addressable", 2*1024)
			mem.Total = 2 * 1024 * 1024 * 1024
		}
		allowance := int(mem.Total / 1024 / 1024 / 3)
		if cache := viper.GetInt(CacheFlag.Name); cache > allowance {
			log.Warn("Sanitizing cache to Go's GC limits", "provided", cache, "updated", allowance)
			viper.GetViper().Set(CacheFlag.Name, strconv.Itoa(allowance))
		}
	}
	// Ensure Go's GC ignores the database cache for trigger percentage
	cache := viper.GetInt(CacheFlag.Name)
	gogc := math.Max(20, math.Min(100, 100/(float64(cache)/1024)))

	log.Debug("Sanitizing Go's GC trigger", "percent", int(gogc))
	godebug.SetGCPercent(int(gogc))

	if viper.IsSet(NetworkIdFlag.Name) {
		cfg.NetworkId = viper.GetUint64(NetworkIdFlag.Name)
	}
	if viper.IsSet(CacheFlag.Name) || viper.IsSet(CacheDatabaseFlag.Name) {
		cfg.DatabaseCache = viper.GetInt(CacheFlag.Name) * viper.GetInt(CacheDatabaseFlag.Name) / 100
	}
	cfg.DatabaseHandles = MakeDatabaseHandles()
	if viper.IsSet(AncientDirFlag.Name) {
		cfg.DatabaseFreezer = viper.GetString(AncientDirFlag.Name)
	}

	if gcmode := viper.GetString(GCModeFlag.Name); gcmode != "full" && gcmode != "archive" {
		Fatalf("--%s must be either 'full' or 'archive'", GCModeFlag.Name)
	}
	if viper.IsSet(GCModeFlag.Name) {
		cfg.NoPruning = viper.GetString(GCModeFlag.Name) == "archive"
	}
	if viper.IsSet(CacheNoPrefetchFlag.Name) {
		cfg.NoPrefetch = viper.GetBool(CacheNoPrefetchFlag.Name)
	}
	// Read the value from the flag no matter if it's set or not.
	cfg.Preimages = viper.GetBool(CachePreimagesFlag.Name)
	if cfg.NoPruning && !cfg.Preimages {
		cfg.Preimages = true
		log.Info("Enabling recording of key preimages since archive mode is used")
	}
	if viper.IsSet(TxLookupLimitFlag.Name) {
		cfg.TxLookupLimit = viper.GetUint64(TxLookupLimitFlag.Name)
	}
	if viper.IsSet(CacheFlag.Name) || viper.IsSet(CacheTrieFlag.Name) {
		cfg.TrieCleanCache = viper.GetInt(CacheFlag.Name) * viper.GetInt(CacheTrieFlag.Name) / 100
	}
	if viper.IsSet(CacheTrieJournalFlag.Name) {
		cfg.TrieCleanCacheJournal = viper.GetString(CacheTrieJournalFlag.Name)
	}
	if viper.IsSet(CacheTrieRejournalFlag.Name) {
		cfg.TrieCleanCacheRejournal = viper.GetDuration(CacheTrieRejournalFlag.Name)
	}
	if viper.IsSet(CacheFlag.Name) || viper.IsSet(CacheGCFlag.Name) {
		cfg.TrieDirtyCache = viper.GetInt(CacheFlag.Name) * viper.GetInt(CacheGCFlag.Name) / 100
	}
	if viper.IsSet(CacheFlag.Name) || viper.IsSet(CacheSnapshotFlag.Name) {
		cfg.SnapshotCache = viper.GetInt(CacheFlag.Name) * viper.GetInt(CacheSnapshotFlag.Name) / 100
	}
	if !viper.GetBool(SnapshotFlag.Name) {
		cfg.TrieCleanCache += cfg.SnapshotCache
		cfg.SnapshotCache = 0 // Disabled
	}
	if viper.IsSet(DocRootFlag.Name) {
		cfg.DocRoot = viper.GetString(DocRootFlag.Name)
	}
	if viper.IsSet(VMEnableDebugFlag.Name) {
		// TODO(fjl): force-enable this in --dev mode
		cfg.EnablePreimageRecording = viper.GetBool(VMEnableDebugFlag.Name)
	}

	if viper.IsSet(RPCGlobalGasCapFlag.Name) {
		cfg.RPCGasCap = viper.GetUint64(RPCGlobalGasCapFlag.Name)
	}
	if cfg.RPCGasCap != 0 {
		log.Info("Set global gas cap", "cap", cfg.RPCGasCap)
	} else {
		log.Info("Global gas cap disabled")
	}
	if viper.IsSet(RPCGlobalTxFeeCapFlag.Name) {
		cfg.RPCTxFeeCap = viper.GetFloat64(RPCGlobalTxFeeCapFlag.Name)
	}
	if viper.IsSet(NoDiscoverFlag.Name) {
		cfg.EthDiscoveryURLs, cfg.SnapDiscoveryURLs = []string{}, []string{}
	} else if viper.IsSet(DNSDiscoveryFlag.Name) {
		urls := viper.GetString(DNSDiscoveryFlag.Name)
		if urls == "" {
			cfg.EthDiscoveryURLs = []string{}
		} else {
			cfg.EthDiscoveryURLs = SplitAndTrim(urls)
		}
	}
	// Override any default configs for hard coded networks.
	switch {
	case viper.GetBool(ColosseumFlag.Name):
		if !viper.IsSet(NetworkIdFlag.Name) {
			cfg.NetworkId = 1
		}
		cfg.Genesis = core.DefaultColosseumGenesisBlock(cfg.ConsensusEngine)
	case viper.GetBool(GardenFlag.Name):
		if !viper.IsSet(NetworkIdFlag.Name) {
			cfg.NetworkId = 2
		}
		cfg.Genesis = core.DefaultGardenGenesisBlock(cfg.ConsensusEngine)
	case viper.GetBool(OrchardFlag.Name):
		if !viper.IsSet(NetworkIdFlag.Name) {
			cfg.NetworkId = 3
		}
		cfg.Genesis = core.DefaultOrchardGenesisBlock(cfg.ConsensusEngine)
	case viper.GetBool(LocalFlag.Name):
		if !viper.IsSet(NetworkIdFlag.Name) {
			cfg.NetworkId = 4
		}
		cfg.Genesis = core.DefaultLocalGenesisBlock(cfg.ConsensusEngine)
	case viper.GetBool(LighthouseFlag.Name):
		if !viper.IsSet(NetworkIdFlag.Name) {
			cfg.NetworkId = 5
		}
		cfg.Genesis = core.DefaultLighthouseGenesisBlock(cfg.ConsensusEngine)
	case viper.GetBool(DeveloperFlag.Name):
		if !viper.IsSet(NetworkIdFlag.Name) {
			cfg.NetworkId = 1337
		}

		if viper.IsSet(DataDirFlag.Name) {
			// Check if we have an already initialized chain and fall back to
			// that if so. Otherwise we need to generate a new genesis spec.
			chaindb := MakeChainDatabase(stack, false) // TODO (MariusVanDerWijden) make this read only
			if rawdb.ReadCanonicalHash(chaindb, 0) != (common.Hash{}) {
				cfg.Genesis = nil // fallback to db content
			}
			chaindb.Close()
		}
		if !viper.IsSet(MinerGasPriceFlag.Name) {
			cfg.Miner.GasPrice = big.NewInt(1)
		}
	}
	if !viper.GetBool(LocalFlag.Name) {
		cfg.Genesis.Nonce = viper.GetUint64(GenesisNonceFlag.Name)
	}

	log.Info("Setting genesis Location", "node", nodeLocation)
	cfg.Genesis.Config.Location = nodeLocation
	log.Info("Location after setting", "genesis", cfg.Genesis.Config.Location)
}

func SplitTagsFlag(tagsFlag string) map[string]string {
	tags := strings.Split(tagsFlag, ",")
	tagsMap := map[string]string{}

	for _, t := range tags {
		if t != "" {
			kv := strings.Split(t, "=")

			if len(kv) == 2 {
				tagsMap[kv[0]] = kv[1]
			}
		}
	}

	return tagsMap
}

// MakeChainDatabase open an LevelDB using the flags passed to the client and will hard crash if it fails.
func MakeChainDatabase(stack *node.Node, readonly bool) ethdb.Database {
	var (
		cache   = viper.GetInt(CacheFlag.Name) * viper.GetInt(CacheDatabaseFlag.Name) / 100
		handles = MakeDatabaseHandles()

		err     error
		chainDb ethdb.Database
	)
	name := "chaindata"
	chainDb, err = stack.OpenDatabaseWithFreezer(name, cache, handles, viper.GetString(AncientDirFlag.Name), "", readonly)
	if err != nil {
		Fatalf("Could not open database: %v", err)
	}
	return chainDb
}

func MakeGenesis() *core.Genesis {
	var genesis *core.Genesis
	switch {
	case viper.GetBool(ColosseumFlag.Name):
		genesis = core.DefaultColosseumGenesisBlock(viper.GetString(ConsensusEngineFlag.Name))
	case viper.GetBool(GardenFlag.Name):
		genesis = core.DefaultGardenGenesisBlock(viper.GetString(ConsensusEngineFlag.Name))
	case viper.GetBool(OrchardFlag.Name):
		genesis = core.DefaultOrchardGenesisBlock(viper.GetString(ConsensusEngineFlag.Name))
	case viper.GetBool(LighthouseFlag.Name):
		genesis = core.DefaultLighthouseGenesisBlock(viper.GetString(ConsensusEngineFlag.Name))
	case viper.GetBool(LocalFlag.Name):
		genesis = core.DefaultLocalGenesisBlock(viper.GetString(ConsensusEngineFlag.Name))
	case viper.GetBool(DeveloperFlag.Name):
		Fatalf("Developer chains are ephemeral")
	}
	return genesis
}

// MakeConsolePreloads retrieves the absolute paths for the console JavaScript
// scripts to preload before starting.
func MakeConsolePreloads() []string {
	// Skip preloading if there's nothing to preload
	if viper.GetString(PreloadJSFlag.Name) == "" {
		return nil
	}
	// Otherwise resolve absolute paths and return them
	var preloads []string

	for _, file := range strings.Split(viper.GetString(PreloadJSFlag.Name), ",") {
		preloads = append(preloads, strings.TrimSpace(file))
	}
	return preloads
}
