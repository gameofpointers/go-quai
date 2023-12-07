package utils

import (
	"encoding"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/adrg/xdg"
	"github.com/dominant-strategies/go-quai/common/constants"
)

type StringFlag struct {
	Name         string
	Abbreviation string
	DefaultValue string
	Usage        string
}

type BoolFlag struct {
	Name         string
	Abbreviation string
	DefaultValue bool
	Usage        string
}

type ArrayFlag struct {
	Name         string
	Abbreviation string
	DefaultValue []string
	Usage        string
}

type Uint64Flag struct {
	Name         string
	Abbreviation string
	DefaultValue uint64
	Usage        string
}

type IntFlag struct {
	Name         string
	Abbreviation string
	DefaultValue int
	Usage        string
}

type TextMarshalerFlag struct {
	Name         string
	Abbreviation string
	DefaultValue TextMarshaler
	Usage        string
}

type TextMarshaler interface {
	encoding.TextMarshaler
	encoding.TextUnmarshaler
}

type DurationFlag struct {
	Name         string
	Abbreviation string
	DefaultValue time.Duration
	Usage        string
}

type BigFlag struct {
	Name         string
	Abbreviation string
	DefaultValue *big.Int
	Usage        string
}

type Int64Flag struct {
	Name         string
	Abbreviation string
	DefaultValue int64
	Usage        string
}

var (
	// ****************************************
	// ** 								     **
	// ** 	      LOCAL FLAGS    			 **
	// ** 								     **
	// ****************************************
	IPAddrFlag = StringFlag{
		Name:         "ipaddr",
		Abbreviation: "i",
		DefaultValue: "0.0.0.0",
		Usage:        "ip address to listen on" + generateEnvDoc("ipaddr"),
	}

	P2PPortFlag = StringFlag{
		Name:         "port",
		Abbreviation: "p",
		DefaultValue: "4001",
		Usage:        "p2p port to listen on" + generateEnvDoc("port"),
	}

	BootNodeFlag = BoolFlag{
		Name:         "bootnode",
		Abbreviation: "b",
		Usage:        "start the node as a boot node (no static peers required)" + generateEnvDoc("bootnode"),
	}

	BootPeersFlag = ArrayFlag{
		Name:         "bootpeers",
		DefaultValue: []string{},
		Usage:        "list of bootstrap peers. Syntax: <multiaddress1>,<multiaddress2>,..." + generateEnvDoc("bootpeers"),
	}

	PortMapFlag = BoolFlag{
		Name:         "portmap",
		DefaultValue: true,
		Usage:        "enable NAT portmap" + generateEnvDoc("portmap"),
	}

	KeyFileFlag = StringFlag{
		Name:         "private.key",
		Abbreviation: "k",
		Usage:        "file containing node private key" + generateEnvDoc("keyfile"),
	}

	MinPeersFlag = StringFlag{
		Name:         "min-peers",
		DefaultValue: "5",
		Usage:        "minimum number of peers to maintain connectivity with" + generateEnvDoc("min-peers"),
	}

	MaxPeersFlag = StringFlag{
		Name:         "max-peers",
		DefaultValue: "50",
		Usage:        "maximum number of peers to maintain connectivity with" + generateEnvDoc("max-peers"),
	}

	LocationFlag = StringFlag{
		Name:  "location",
		Usage: "region and zone location" + generateEnvDoc("location"),
	}

	// ****************************************
	// ** 								     **
	// ** 	      GLOBAL FLAGS    			 **
	// ** 								     **
	// ****************************************
	ConfigDirFlag = StringFlag{
		Name:         "config-dir",
		Abbreviation: "c",
		DefaultValue: xdg.ConfigHome + "/" + constants.APP_NAME + "/",
		Usage:        "config directory" + generateEnvDoc("config-dir"),
	}

	DataDirFlag = StringFlag{
		Name:         "data-dir",
		Abbreviation: "d",
		DefaultValue: xdg.DataHome + "/" + constants.APP_NAME + "/",
		Usage:        "data directory" + generateEnvDoc("data-dir"),
	}

	AncientDirFlag = StringFlag{
		Name:  "datadir.ancient",
		Usage: "Data directory for ancient chain segments (default = inside chaindata)",
	}

	LogLevelFlag = StringFlag{
		Name:         "log-level",
		Abbreviation: "l",
		DefaultValue: "info",
		Usage:        "log level (trace, debug, info, warn, error, fatal, panic)" + generateEnvDoc("log-level"),
	}

	SaveConfigFlag = BoolFlag{
		Name:         "save-config",
		Abbreviation: "S",
		Usage:        "save/update config file with current config parameters" + generateEnvDoc("save-config"),
	}

	// ****************************************
	// ** 								     **
	// ** 	      IMPORTED FLAGS    		 **
	// ** 								     **
	// ****************************************
	DBEngineFlag = StringFlag{
		Name:         "db.engine",
		DefaultValue: "leveldb",
		Usage:        "Backing database implementation to use ('leveldb' or 'pebble')" + generateEnvDoc("db.engine"),
	}

	// Is this the same as keyfile?
	KeystoreDirFlag = StringFlag{
		Name:         "keystore",
		DefaultValue: xdg.DataHome + "/" + constants.APP_NAME + "/",
		Usage:        "Directory containing the node's private keys" + generateEnvDoc("keystore"),
	}

	NoUSBFlag = BoolFlag{
		Name:  "no-usb",
		Usage: "Disable USB hardware wallet support" + generateEnvDoc("no-usb"),
	}

	USBFlag = BoolFlag{
		Name:  "usb",
		Usage: "Enable monitoring and management of USB hardware wallets" + generateEnvDoc("usb"),
	}

	NetworkIdFlag = Uint64Flag{
		Name:         "networkid",
		DefaultValue: 1,
		Usage:        "Explicitly set network id (integer)(For testnets: use --garden)" + generateEnvDoc("networkid"),
	}

	SlicesRunningFlag = StringFlag{
		Name:  "slices",
		Usage: "All the slices that are running on this node" + generateEnvDoc("slices"),
	}

	ColosseumFlag = BoolFlag{
		Name:  "colosseum",
		Usage: "Quai Colosseum testnet",
	}

	GardenFlag = BoolFlag{
		Name:  "garden",
		Usage: "Garden network: pre-configured proof-of-work test network" + generateEnvDoc("garden"),
	}
	OrchardFlag = BoolFlag{
		Name:  "orchard",
		Usage: "Orchard network: pre-configured proof-of-work test network" + generateEnvDoc("orchard"),
	}
	LighthouseFlag = BoolFlag{
		Name:  "lighthouse",
		Usage: "Lighthouse network: pre-configured proof-of-work test network" + generateEnvDoc("lighthouse"),
	}
	LocalFlag = BoolFlag{
		Name:  "local",
		Usage: "Local network: localhost proof-of-work node, will not attempt to connect to bootnode or any public network" + generateEnvDoc("local"),
	}
	GenesisNonceFlag = Uint64Flag{
		Name:         "nonce",
		DefaultValue: 0,
		Usage:        "Nonce to use for the genesis block (integer)" + generateEnvDoc("nonce"),
	}
	DeveloperFlag = BoolFlag{
		Name:  "dev",
		Usage: "Ephemeral proof-of-authority network with a pre-funded developer account, mining enabled" + generateEnvDoc("dev"),
	}
	DevPeriodFlag = IntFlag{
		Name:         "dev.period",
		DefaultValue: 0,
		Usage:        "Block period to use for the dev network (integer) (0 = mine only if transaction pending)" + generateEnvDoc("dev.period"),
	}
	IdentityFlag = StringFlag{
		Name:  "identity",
		Usage: "Custom node name" + generateEnvDoc("identity"),
	}
	DocRootFlag = StringFlag{
		Name:         "docroot",
		DefaultValue: xdg.DataHome,
		Usage:        "Document Root for HTTPClient file scheme" + generateEnvDoc("docroot"),
	}

	// ****************************************
	// ** 								     **
	// ** 	      PY FLAGS    				 **
	// ** 								     **
	// ****************************************

	ExitWhenSyncedFlag = BoolFlag{
		Name:  "exitwhensynced",
		Usage: "Exits after block synchronisation completes" + generateEnvDoc("exitwhensynced"),
	}
	IterativeOutputFlag = BoolFlag{
		Name:         "iterative",
		DefaultValue: true,
		Usage:        "Print streaming JSON iteratively, delimited by newlines" + generateEnvDoc("iterative"),
	}
	ExcludeStorageFlag = BoolFlag{
		Name:  "nostorage",
		Usage: "Exclude storage entries (save db lookups)" + generateEnvDoc("nostorage"),
	}
	IncludeIncompletesFlag = BoolFlag{
		Name:  "incompletes",
		Usage: "Include accounts for which we don't have the address (missing preimage)" + generateEnvDoc("incompletes"),
	}
	ExcludeCodeFlag = BoolFlag{
		Name:  "nocode",
		Usage: "Exclude contract code (save db lookups)" + generateEnvDoc("nocode"),
	}
	StartKeyFlag = StringFlag{
		Name:         "start",
		DefaultValue: "0x0000000000000000000000000000000000000000000000000000000000000000",
		Usage:        "Start position. Either a hash or address" + generateEnvDoc("start"),
	}
	DumpLimitFlag = Uint64Flag{
		Name:         "limit",
		DefaultValue: 0,
		Usage:        "Max number of elements (0 = no limit)" + generateEnvDoc("limit"),
	}

	defaultSyncMode = EthConfigDefaults.SyncMode
	SyncModeFlag    = TextMarshalerFlag{
		Name:         "syncmode",
		DefaultValue: &defaultSyncMode,
		Usage:        `Blockchain sync mode ("fast", "full", or "light")` + generateEnvDoc("syncmode"),
	}
	GCModeFlag = StringFlag{
		Name:         "gcmode",
		DefaultValue: "full",
		Usage:        `Blockchain garbage collection mode ("full", "archive")` + generateEnvDoc("gcmode"),
	}

	SnapshotFlag = BoolFlag{
		Name:         "snapshot",
		DefaultValue: true,
		Usage:        `Enables snapshot-database mode (default = true)` + generateEnvDoc("snapshot"),
	}

	TxLookupLimitFlag = Uint64Flag{
		Name:         "txlookuplimit",
		DefaultValue: EthConfigDefaults.TxLookupLimit,
		Usage:        "Number of recent blocks to maintain transactions index for (default = about one year, 0 = entire chain)" + generateEnvDoc("txlookuplimit"),
	}

	LightKDFFlag = BoolFlag{
		Name:  "lightkdf",
		Usage: "Reduce key-derivation RAM & CPU usage at some expense of KDF strength" + generateEnvDoc("lightkdf"),
	}

	WhitelistFlag = StringFlag{
		Name:  "whitelist",
		Usage: "Comma separated block number-to-hash mappings to enforce (<number>=<hash>)" + generateEnvDoc("whitelist"),
	}

	BloomFilterSizeFlag = Uint64Flag{
		Name:         "bloomfilter.size",
		DefaultValue: 2048,
		Usage:        "Megabytes of memory allocated to bloom-filter for pruning" + generateEnvDoc("bloomfilter.size"),
	}

	// Transaction pool settings
	TxPoolLocalsFlag = StringFlag{
		Name:  "txpool.locals",
		Usage: "Comma separated accounts to treat as locals (no flush, priority inclusion)" + generateEnvDoc("txpool.locals"),
	}
	TxPoolNoLocalsFlag = BoolFlag{
		Name:  "txpool.nolocals",
		Usage: "Disables price exemptions for locally submitted transactions" + generateEnvDoc("txpool.nolocals"),
	}
	TxPoolJournalFlag = StringFlag{
		Name:         "txpool.journal",
		Usage:        "Disk journal for local transaction to survive node restarts" + generateEnvDoc("txpool.journal"),
		DefaultValue: CoreConfigDefaults.Journal,
	}
	TxPoolRejournalFlag = DurationFlag{
		Name:         "txpool.rejournal",
		Usage:        "Time interval to regenerate the local transaction journal" + generateEnvDoc("txpool.rejournal"),
		DefaultValue: CoreConfigDefaults.Rejournal,
	}
	TxPoolPriceLimitFlag = Uint64Flag{
		Name:         "txpool.pricelimit",
		Usage:        "Minimum gas price limit to enforce for acceptance into the pool" + generateEnvDoc("txpool.pricelimit"),
		DefaultValue: EthConfigDefaults.TxPool.PriceLimit,
	}
	TxPoolPriceBumpFlag = Uint64Flag{
		Name:         "txpool.pricebump",
		Usage:        "Price bump percentage to replace an already existing transaction" + generateEnvDoc("txpool.pricebump"),
		DefaultValue: EthConfigDefaults.TxPool.PriceBump,
	}
	TxPoolAccountSlotsFlag = Uint64Flag{
		Name:         "txpool.accountslots",
		Usage:        "Minimum number of executable transaction slots guaranteed per account" + generateEnvDoc("txpool.accountslots"),
		DefaultValue: EthConfigDefaults.TxPool.AccountSlots,
	}
	TxPoolGlobalSlotsFlag = Uint64Flag{
		Name:         "txpool.globalslots",
		Usage:        "Maximum number of executable transaction slots for all accounts" + generateEnvDoc("txpool.globalslots"),
		DefaultValue: EthConfigDefaults.TxPool.GlobalSlots,
	}
	TxPoolAccountQueueFlag = Uint64Flag{
		Name:         "txpool.accountqueue",
		Usage:        "Maximum number of non-executable transaction slots permitted per account" + generateEnvDoc("txpool.accountqueue"),
		DefaultValue: EthConfigDefaults.TxPool.AccountQueue,
	}
	TxPoolGlobalQueueFlag = Uint64Flag{
		Name:         "txpool.globalqueue",
		Usage:        "Maximum number of non-executable transaction slots for all accounts" + generateEnvDoc("txpool.globalqueue"),
		DefaultValue: EthConfigDefaults.TxPool.GlobalQueue,
	}
	TxPoolLifetimeFlag = DurationFlag{
		Name:         "txpool.lifetime",
		Usage:        "Maximum amount of time non-executable transaction are queued" + generateEnvDoc("txpool.lifetime"),
		DefaultValue: EthConfigDefaults.TxPool.Lifetime,
	}
	CacheFlag = IntFlag{
		Name:         "cache",
		DefaultValue: 1024,
		Usage:        "Megabytes of memory allocated to internal caching (default = 4096 quai full node, 128 light mode)" + generateEnvDoc("cache"),
	}
	CacheDatabaseFlag = IntFlag{
		Name:         "cache.database",
		Usage:        "Percentage of cache memory allowance to use for database io" + generateEnvDoc("cache.database"),
		DefaultValue: 50,
	}
	CacheTrieFlag = IntFlag{
		Name:         "cache.trie",
		Usage:        "Percentage of cache memory allowance to use for trie caching (default = 15% full mode, 30% archive mode)" + generateEnvDoc("cache.trie"),
		DefaultValue: 15,
	}
	CacheTrieJournalFlag = StringFlag{
		Name:         "cache.trie.journal",
		Usage:        "Disk journal directory for trie cache to survive node restarts" + generateEnvDoc("cache.trie.journal"),
		DefaultValue: EthConfigDefaults.TrieCleanCacheJournal,
	}
	CacheTrieRejournalFlag = DurationFlag{
		Name:         "cache.trie.rejournal",
		Usage:        "Time interval to regenerate the trie cache journal" + generateEnvDoc("cache.trie.rejournal"),
		DefaultValue: EthConfigDefaults.TrieCleanCacheRejournal,
	}
	CacheGCFlag = IntFlag{
		Name:         "cache.gc",
		Usage:        "Percentage of cache memory allowance to use for trie pruning (default = 25% full mode, 0% archive mode)" + generateEnvDoc("cache.gc"),
		DefaultValue: 25,
	}
	CacheSnapshotFlag = IntFlag{
		Name:         "cache.snapshot",
		Usage:        "Percentage of cache memory allowance to use for snapshot caching (default = 10% full mode, 20% archive mode)" + generateEnvDoc("cache.snapshot"),
		DefaultValue: 10,
	}
	CacheNoPrefetchFlag = BoolFlag{
		Name:  "cache.noprefetch",
		Usage: "Disable heuristic state prefetch during block import (less CPU and disk IO, more time waiting for data)" + generateEnvDoc("cache.noprefetch"),
	}
	CachePreimagesFlag = BoolFlag{
		Name:  "cache.preimages",
		Usage: "Enable recording the SHA3/keccak preimages of trie keys" + generateEnvDoc("cache.preimages"),
	}
	// Consensus settings
	ConsensusEngineFlag = StringFlag{
		Name:         "consensus.engine",
		Usage:        "Consensus engine that the blockchain will run and verify blocks using" + generateEnvDoc("consensus.engine"),
		DefaultValue: "progpow",
	}
	// Miner settings
	MinerGasPriceFlag = BigFlag{
		Name:         "miner.gasprice",
		Usage:        "Minimum gas price for mining a transaction" + generateEnvDoc("miner.gasprice"),
		DefaultValue: EthConfigDefaults.Miner.GasPrice,
	}
	MinerEtherbaseFlag = StringFlag{
		Name:         "miner.etherbase",
		Usage:        "Public address for block mining rewards (default = first account)" + generateEnvDoc("miner.etherbase"),
		DefaultValue: "0",
	}

	// Account settings
	UnlockedAccountFlag = StringFlag{
		Name:  "unlock",
		Usage: "Comma separated list of accounts to unlock" + generateEnvDoc("unlock"),
	}

	PasswordFileFlag = StringFlag{
		Name:  "password",
		Usage: "Password file to use for non-interactive password input" + generateEnvDoc("password"),
	}

	ExternalSignerFlag = StringFlag{
		Name:  "signer",
		Usage: "External signer (url or path to ipc file)" + generateEnvDoc("signer"),
	}

	VMEnableDebugFlag = BoolFlag{
		Name:  "vmdebug",
		Usage: "Record information useful for VM and contract debugging" + generateEnvDoc("vmdebug"),
	}
	InsecureUnlockAllowedFlag = BoolFlag{
		Name:  "allow-insecure-unlock",
		Usage: "Allow insecure account unlocking when account-related RPCs are exposed by http" + generateEnvDoc("allow-insecure-unlock"),
	}
	RPCGlobalGasCapFlag = Uint64Flag{
		Name:         "rpc.gascap",
		DefaultValue: EthConfigDefaults.RPCGasCap,
		Usage:        "Sets a cap on gas that can be used in eth_call/estimateGas (0=infinite)" + generateEnvDoc("vmdebug"),
	}
	QuaiStatsURLFlag = StringFlag{
		Name:  "quaistats",
		Usage: "Reporting URL of a quaistats service (nodename:secret@host:port)" + generateEnvDoc("quaistats"),
	}
	SendFullStatsFlag = BoolFlag{
		Name:  "sendfullstats",
		Usage: "Send full stats boolean flag for quaistats" + generateEnvDoc("sendfullstats"),
	}
	FakePoWFlag = BoolFlag{
		Name:  "fakepow",
		Usage: "Disables proof-of-work verification" + generateEnvDoc("fakepow"),
	}
	NoCompactionFlag = BoolFlag{
		Name:  "nocompaction",
		Usage: "Disables db compaction after import" + generateEnvDoc("nocompaction"),
	}
	// RPC settings
	HTTPEnabledFlag = BoolFlag{
		Name:  "http",
		Usage: "Enable the HTTP-RPC server" + generateEnvDoc("http"),
	}
	HTTPListenAddrFlag = StringFlag{
		Name:         "http.addr",
		DefaultValue: DefaultHTTPHost,
		Usage:        "HTTP-RPC server listening interface" + generateEnvDoc("http.addr"),
	}
	HTTPPortFlag = IntFlag{
		Name:         "http.port",
		DefaultValue: DefaultHTTPPort,
		Usage:        "HTTP-RPC server listening port" + generateEnvDoc("http.port"),
	}
	HTTPCORSDomainFlag = StringFlag{
		Name:  "http.corsdomain",
		Usage: "Comma separated list of domains from which to accept cross origin requests (browser enforced)" + generateEnvDoc("http.corsdomain"),
	}
	HTTPVirtualHostsFlag = StringFlag{
		Name:         "http.vhosts",
		DefaultValue: strings.Join(NodeDefaultConfig.HTTPVirtualHosts, ","),
		Usage:        "Comma separated list of virtual hostnames from which to accept requests (server enforced). Accepts '*' wildcard." + generateEnvDoc("http"),
	}
	HTTPApiFlag = StringFlag{
		Name:  "http.api",
		Usage: "API's offered over the HTTP-RPC interface" + generateEnvDoc("http"),
	}
	HTTPPathPrefixFlag = StringFlag{
		Name:  "http.rpcprefix",
		Usage: "HTTP path path prefix on which JSON-RPC is served. Use '/' to serve on all paths." + generateEnvDoc("http"),
	}

	WSEnabledFlag = BoolFlag{
		Name:  "ws",
		Usage: "Enable the WS-RPC server" + generateEnvDoc("ws"),
	}
	WSListenAddrFlag = StringFlag{
		Name:         "ws.addr",
		DefaultValue: DefaultWSHost,
		Usage:        "WS-RPC server listening interface" + generateEnvDoc("ws"),
	}
	WSPortFlag = IntFlag{
		Name:         "ws.port",
		DefaultValue: DefaultWSPort,
		Usage:        "WS-RPC server listening port" + generateEnvDoc("ws"),
	}
	WSApiFlag = StringFlag{
		Name:  "ws.api",
		Usage: "API's offered over the WS-RPC interface" + generateEnvDoc("ws"),
	}
	WSAllowedOriginsFlag = StringFlag{
		Name:  "ws.origins",
		Usage: "Origins from which to accept websockets requests" + generateEnvDoc("ws"),
	}
	WSPathPrefixFlag = StringFlag{
		Name:  "ws.rpcprefix",
		Usage: "HTTP path prefix on which JSON-RPC is served. Use '/' to serve on all paths." + generateEnvDoc("ws"),
	}
	ExecFlag = StringFlag{
		Name:  "exec",
		Usage: "Execute JavaScript statement" + generateEnvDoc("exec"),
	}
	PreloadJSFlag = StringFlag{
		Name:  "preload",
		Usage: "Comma separated list of JavaScript files to preload into the console" + generateEnvDoc("preload"),
	}

	MaxPendingPeersFlag = IntFlag{
		Name:         "maxpendpeers",
		DefaultValue: NodeDefaultConfig.P2P.MaxPendingPeers,
		Usage:        "Maximum number of pending connection attempts (defaults used if set to 0)" + generateEnvDoc("maxpendpeers"),
	}

	BootnodesFlag = StringFlag{
		Name:  "bootnodes",
		Usage: "Comma separated enode URLs for P2P discovery bootstrap" + generateEnvDoc("bootnodes"),
	}

	NodeKeyFileFlag = StringFlag{
		Name:  "nodekey",
		Usage: "P2P node key file" + generateEnvDoc("nodekey"),
	}
	NodeKeyHexFlag = StringFlag{
		Name:  "nodekeyhex",
		Usage: "P2P node key as hex (for testing)" + generateEnvDoc("nodekeyhex"),
	}
	NATFlag = StringFlag{
		Name:         "nat",
		DefaultValue: "any",
		Usage:        "NAT port mapping mechanism (any|none|upnp|pmp|extip:<IP>)" + generateEnvDoc("nat"),
	}

	NoDiscoverFlag = BoolFlag{
		Name:  "nodiscover",
		Usage: "Disables the peer discovery mechanism (manual peer addition)" + generateEnvDoc("nodiscover"),
	}

	DiscoveryV5Flag = BoolFlag{
		Name:  "v5disc",
		Usage: "Enables the experimental RLPx V5 (Topic Discovery) mechanism" + generateEnvDoc("v5disc"),
	}
	NetrestrictFlag = StringFlag{
		Name:  "netrestrict",
		Usage: "Restricts network communication to the given IP networks (CIDR masks)" + generateEnvDoc("netrestrict"),
	}
	DNSDiscoveryFlag = StringFlag{
		Name:  "discovery.dns",
		Usage: "Sets DNS discovery entry points (use '' to disable DNS)" + generateEnvDoc("discovery.dns"),
	}

	// ATM the url is left to the user and deployment to
	JSpathFlag = StringFlag{
		Name:         "jspath",
		DefaultValue: ".",
		Usage:        "JavaScript root path for `loadScript`" + generateEnvDoc("jspath"),
	}
	// Gas price oracle settings
	GpoBlocksFlag = IntFlag{
		Name:         "gpo.blocks",
		DefaultValue: EthConfigDefaults.GPO.Blocks,
		Usage:        "Number of recent blocks to check for gas prices" + generateEnvDoc("gpo.blocks"),
	}
	GpoPercentileFlag = IntFlag{
		Name:         "gpo.percentile",
		DefaultValue: EthConfigDefaults.GPO.Percentile,
		Usage:        "Suggested gas price is the given percentile of a set of recent transaction gas prices" + generateEnvDoc("gpo.percentile"),
	}
	GpoMaxGasPriceFlag = Int64Flag{
		Name:         "gpo.maxprice",
		Usage:        "Maximum gas price will be recommended by gpo" + generateEnvDoc("gpo.maxprice"),
		DefaultValue: EthConfigDefaults.GPO.MaxPrice.Int64(),
	}
	GpoIgnoreGasPriceFlag = Int64Flag{
		Name:         "gpo.ignoreprice",
		DefaultValue: EthConfigDefaults.GPO.IgnorePrice.Int64(),
		Usage:        "Gas price below which gpo will ignore transactions" + generateEnvDoc("gpo.ignoreprice"),
	}

	MetricsEnabledFlag = BoolFlag{
		Name:  "metrics",
		Usage: "Enable metrics collection and reporting" + generateEnvDoc("metrics"),
	}
	MetricsEnabledExpensiveFlag = BoolFlag{
		Name:  "metrics.expensive",
		Usage: "Enable expensive metrics collection and reporting" + generateEnvDoc("metrics.expensive"),
	}

	// MetricsHTTPFlag defines the endpoint for a stand-alone metrics HTTP endpoint.
	// Since the pprof service enables sensitive/vulnerable behavior, this allows a user
	// to enable a public-OK metrics endpoint without having to worry about ALSO exposing
	// other profiling behavior or information.
	MetricsHTTPFlag = StringFlag{
		Name:         "metrics.addr",
		DefaultValue: DefaultMetricsConfig.HTTP,
		Usage:        "Enable stand-alone metrics HTTP server listening interface" + generateEnvDoc("metrics.addr"),
	}
	MetricsPortFlag = IntFlag{
		Name:         "metrics.port",
		DefaultValue: DefaultMetricsConfig.Port,
		Usage:        "Metrics HTTP server listening port" + generateEnvDoc("metrics.port"),
	}
	MetricsEnableInfluxDBFlag = BoolFlag{
		Name:  "metrics.influxdb",
		Usage: "Enable metrics export/push to an external InfluxDB database" + generateEnvDoc("metrics.influxdb"),
	}
	MetricsInfluxDBEndpointFlag = StringFlag{
		Name:         "metrics.influxdb.endpoint",
		DefaultValue: DefaultMetricsConfig.InfluxDBEndpoint,
		Usage:        "InfluxDB API endpoint to report metrics to" + generateEnvDoc("metrics.influxdb.endpoint"),
	}
	MetricsInfluxDBDatabaseFlag = StringFlag{
		Name:         "metrics.influxdb.database",
		DefaultValue: DefaultMetricsConfig.InfluxDBDatabase,
		Usage:        "InfluxDB database name to push reported metrics to" + generateEnvDoc("metrics.influxdb.database"),
	}
	MetricsInfluxDBUsernameFlag = StringFlag{
		Name:         "metrics.influxdb.username",
		DefaultValue: DefaultMetricsConfig.InfluxDBUsername,
		Usage:        "Username to authorize access to the database" + generateEnvDoc("metrics.influxdb.username"),
	}
	MetricsInfluxDBPasswordFlag = StringFlag{
		Name:         "metrics.influxdb.password",
		DefaultValue: DefaultMetricsConfig.InfluxDBPassword,
		Usage:        "Password to authorize access to the database" + generateEnvDoc("metrics.influxdb.password"),
	}

	ShowColorsFlag = BoolFlag{
		Name:  "showcolors",
		Usage: "Enable colorized logging" + generateEnvDoc("showcolors"),
	}

	LogToStdOutFlag = BoolFlag{
		Name:  "logtostdout",
		Usage: "Write log messages to stdout" + generateEnvDoc("logtostdout"),
	}

	// Tags are part of every measurement sent to InfluxDB. Queries on tags are faster in InfluxDB.
	// For example `host` tag could be used so that we can group all nodes and average a measurement
	// across all of them, but also so that we can select a specific node and inspect its measurements.
	// https://docs.influxdata.com/influxdb/v1.4/concepts/key_concepts/#tag-key
	MetricsInfluxDBTagsFlag = StringFlag{
		Name:         "metrics.influxdb.tags",
		DefaultValue: DefaultMetricsConfig.InfluxDBTags,
		Usage:        "Comma-separated InfluxDB tags (key/values) attached to all measurements" + generateEnvDoc("metrics.influxdb.tags"),
	}

	RegionFlag = IntFlag{
		Name:         "region",
		DefaultValue: EthConfigDefaults.Region,
		Usage:        "Quai Region flag" + generateEnvDoc("region"),
	}
	ZoneFlag = IntFlag{
		Name:         "zone",
		DefaultValue: EthConfigDefaults.Zone,
		Usage:        "Quai Zone flag" + generateEnvDoc("zone"),
	}
	DomUrl = StringFlag{
		Name:         "dom.url",
		DefaultValue: EthConfigDefaults.DomUrl,
		Usage:        "Dominant chain websocket url" + generateEnvDoc("dom.url"),
	}
	SubUrls = StringFlag{
		Name:         "sub.urls",
		DefaultValue: EthConfigDefaults.DomUrl,
		Usage:        "Subordinate chain websocket urls" + generateEnvDoc("sub.urls"),
	}
)

// helper function that given a cobra flag name, returns the corresponding
// help legend for the equivalent environment variable
func generateEnvDoc(flag string) string {
	envVar := constants.ENV_PREFIX + "_" + strings.ReplaceAll(strings.ToUpper(flag), "-", "_")
	return fmt.Sprintf(" [%s]", envVar)
}
