package utils

import (
	"fmt"
	"strings"
	"time"

	"github.com/adrg/xdg"
	"github.com/dominant-strategies/go-quai/common/constants"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var GlobalFlags = []Flag{
	ConfigDirFlag,
	DataDirFlag,
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
	SyncModeFlag,
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
	MinerEtherbaseFlag,
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
	RegionFlag,
	ZoneFlag,
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
	RPCGlobalGasCapFlag,
	QuaiStatsURLFlag,
	SendFullStatsFlag,
}

var MetricsFlags = []Flag{
	MetricsEnabledFlag,
	MetricsEnabledExpensiveFlag,
	MetricsHTTPFlag,
	MetricsPortFlag,
	MetricsEnableInfluxDBFlag,
	MetricsInfluxDBEndpointFlag,
	MetricsInfluxDBDatabaseFlag,
	MetricsInfluxDBUsernameFlag,
	MetricsInfluxDBPasswordFlag,
	MetricsInfluxDBTagsFlag,
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
	defaultSyncMode = EthConfigDefaults.SyncMode
	SyncModeFlag    = Flag{
		Name:  "syncmode",
		Value: NewTextMarshalerValue(&defaultSyncMode),
		Usage: `Blockchain sync mode ("fast", "full", or "light")` + generateEnvDoc("syncmode"),
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
		Value: EthConfigDefaults.TxLookupLimit,
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
		Value: EthConfigDefaults.TxPool.PriceLimit,
		Usage: "Minimum gas price limit to enforce for acceptance into the pool" + generateEnvDoc("txpool.pricelimit"),
	}
	TxPoolPriceBumpFlag = Flag{
		Name:  "txpool.pricebump",
		Value: EthConfigDefaults.TxPool.PriceBump,
		Usage: "Price bump percentage to replace an already existing transaction" + generateEnvDoc("txpool.pricebump"),
	}
	TxPoolAccountSlotsFlag = Flag{
		Name:  "txpool.accountslots",
		Value: EthConfigDefaults.TxPool.AccountSlots,
		Usage: "Minimum number of executable transaction slots guaranteed per account" + generateEnvDoc("txpool.accountslots"),
	}
	TxPoolGlobalSlotsFlag = Flag{
		Name:  "txpool.globalslots",
		Value: EthConfigDefaults.TxPool.GlobalSlots,
		Usage: "Maximum number of executable transaction slots for all accounts" + generateEnvDoc("txpool.globalslots"),
	}
	TxPoolAccountQueueFlag = Flag{
		Name:  "txpool.accountqueue",
		Value: EthConfigDefaults.TxPool.AccountQueue,
		Usage: "Maximum number of non-executable transaction slots permitted per account" + generateEnvDoc("txpool.accountqueue"),
	}
	TxPoolGlobalQueueFlag = Flag{
		Name:  "txpool.globalqueue",
		Value: EthConfigDefaults.TxPool.GlobalQueue,
		Usage: "Maximum number of non-executable transaction slots for all accounts" + generateEnvDoc("txpool.globalqueue"),
	}
	TxPoolLifetimeFlag = Flag{
		Name:  "txpool.lifetime",
		Value: EthConfigDefaults.TxPool.Lifetime,
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
		Value: EthConfigDefaults.TrieCleanCacheJournal,
		Usage: "Disk journal directory for trie cache to survive node restarts" + generateEnvDoc("cache.trie.journal"),
	}
	CacheTrieRejournalFlag = Flag{
		Name:  "cache.trie.rejournal",
		Value: EthConfigDefaults.TrieCleanCacheRejournal,
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
		Value: newBigIntValue(EthConfigDefaults.Miner.GasPrice),
		Usage: "Minimum gas price for mining a transaction" + generateEnvDoc("miner.gasprice"),
	}
	MinerEtherbaseFlag = Flag{
		Name:  "miner.etherbase",
		Value: "0",
		Usage: "Public address for block mining rewards (default = first account)" + generateEnvDoc("miner.etherbase"),
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
	RPCGlobalGasCapFlag = Flag{
		Name:  "rpc.gascap",
		Value: EthConfigDefaults.RPCGasCap,
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
		Value: EthConfigDefaults.GPO.Blocks,
		Usage: "Number of recent blocks to check for gas prices" + generateEnvDoc("gpo.blocks"),
	}
	GpoPercentileFlag = Flag{
		Name:  "gpo.percentile",
		Value: EthConfigDefaults.GPO.Percentile,
		Usage: "Suggested gas price is the given percentile of a set of recent transaction gas prices" + generateEnvDoc("gpo.percentile"),
	}
	GpoMaxGasPriceFlag = Flag{
		Name:  "gpo.maxprice",
		Value: EthConfigDefaults.GPO.MaxPrice.Int64(),
		Usage: "Maximum gas price will be recommended by gpo" + generateEnvDoc("gpo.maxprice"),
	}
	GpoIgnoreGasPriceFlag = Flag{
		Name:  "gpo.ignoreprice",
		Value: EthConfigDefaults.GPO.IgnorePrice.Int64(),
		Usage: "Gas price below which gpo will ignore transactions" + generateEnvDoc("gpo.ignoreprice"),
	}

	MetricsEnabledFlag = Flag{
		Name:  "metrics",
		Value: false,
		Usage: "Enable metrics collection and reporting" + generateEnvDoc("metrics"),
	}
	MetricsEnabledExpensiveFlag = Flag{
		Name:  "metrics.expensive",
		Value: false,
		Usage: "Enable expensive metrics collection and reporting" + generateEnvDoc("metrics.expensive"),
	}
	// MetricsHTTPFlag defines the endpoint for a stand-alone metrics HTTP endpoint.
	// Since the pprof service enables sensitive/vulnerable behavior, this allows a user
	// to enable a public-OK metrics endpoint without having to worry about ALSO exposing
	// other profiling behavior or information.
	MetricsHTTPFlag = Flag{
		Name:  "metrics.addr",
		Value: DefaultMetricsConfig.HTTP,
		Usage: "Enable stand-alone metrics HTTP server listening interface" + generateEnvDoc("metrics.addr"),
	}
	MetricsPortFlag = Flag{
		Name:  "metrics.port",
		Value: DefaultMetricsConfig.Port,
		Usage: "Metrics HTTP server listening port" + generateEnvDoc("metrics.port"),
	}
	MetricsEnableInfluxDBFlag = Flag{
		Name:  "metrics.influxdb",
		Value: false,
		Usage: "Enable metrics export/push to an external InfluxDB database" + generateEnvDoc("metrics.influxdb"),
	}
	MetricsInfluxDBEndpointFlag = Flag{
		Name:  "metrics.influxdb.endpoint",
		Value: DefaultMetricsConfig.InfluxDBEndpoint,
		Usage: "InfluxDB API endpoint to report metrics to" + generateEnvDoc("metrics.influxdb.endpoint"),
	}
	MetricsInfluxDBDatabaseFlag = Flag{
		Name:  "metrics.influxdb.database",
		Value: DefaultMetricsConfig.InfluxDBDatabase,
		Usage: "InfluxDB database name to push reported metrics to" + generateEnvDoc("metrics.influxdb.database"),
	}
	MetricsInfluxDBUsernameFlag = Flag{
		Name:  "metrics.influxdb.username",
		Value: DefaultMetricsConfig.InfluxDBUsername,
		Usage: "Username to authorize access to the database" + generateEnvDoc("metrics.influxdb.username"),
	}
	MetricsInfluxDBPasswordFlag = Flag{
		Name:  "metrics.influxdb.password",
		Value: DefaultMetricsConfig.InfluxDBPassword,
		Usage: "Password to authorize access to the database" + generateEnvDoc("metrics.influxdb.password"),
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
	// Tags are part of every measurement sent to InfluxDB. Queries on tags are faster in InfluxDB.
	// For example `host` tag could be used so that we can group all nodes and average a measurement
	// across all of them, but also so that we can select a specific node and inspect its measurements.
	// https://docs.influxdata.com/influxdb/v1.4/concepts/key_concepts/#tag-key
	MetricsInfluxDBTagsFlag = Flag{
		Name:  "metrics.influxdb.tags",
		Value: DefaultMetricsConfig.InfluxDBTags,
		Usage: "Comma-separated InfluxDB tags (key/values) attached to all measurements" + generateEnvDoc("metrics.influxdb.tags"),
	}

	RegionFlag = Flag{
		Name:  "region",
		Value: EthConfigDefaults.Region,
		Usage: "Quai Region flag" + generateEnvDoc("region"),
	}
	ZoneFlag = Flag{
		Name:  "zone",
		Value: EthConfigDefaults.Zone,
		Usage: "Quai Zone flag" + generateEnvDoc("zone"),
	}
	DomUrl = Flag{
		Name:  "dom.url",
		Value: EthConfigDefaults.DomUrl,
		Usage: "Dominant chain websocket url" + generateEnvDoc("dom.url"),
	}
	SubUrls = Flag{
		Name:  "sub.urls",
		Value: EthConfigDefaults.DomUrl,
		Usage: "Subordinate chain websocket urls" + generateEnvDoc("sub.urls"),
	}
)

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
