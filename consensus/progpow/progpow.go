package progpow

import (
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/common/hexutil"
	"github.com/dominant-strategies/go-quai/consensus"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/metrics"
	"github.com/dominant-strategies/go-quai/rpc"
	mmap "github.com/edsrzf/mmap-go"
	"github.com/hashicorp/golang-lru/simplelru"
)

var (
	// sharedProgpow is a full instance that can be shared between multiple users.
	sharedProgpow *Progpow
	// algorithmRevision is the data structure version used for file naming.
	algorithmRevision = 1
	// dumpMagic is a dataset dump header to sanity check a data dump.
	dumpMagic = []uint32{0xbaddcafe, 0xfee1dead}
)

var ErrInvalidDumpMagic = errors.New("invalid dump magic")

func init() {
	sharedConfig := Config{
		PowMode: ModeNormal,
	}
	sharedProgpow = New(sharedConfig, nil, false)
}

// isLittleEndian returns whether the local system is running in little or big
// endian byte order.
func isLittleEndian() bool {
	n := uint32(0x01020304)
	return *(*byte)(unsafe.Pointer(&n)) == 0x04
}

// memoryMap tries to memory map a file of uint32s for read only access.
func memoryMap(path string, lock bool) (*os.File, mmap.MMap, []uint32, error) {
	file, err := os.OpenFile(path, os.O_RDONLY, 0644)
	if err != nil {
		return nil, nil, nil, err
	}
	mem, buffer, err := memoryMapFile(file, false)
	if err != nil {
		file.Close()
		return nil, nil, nil, err
	}
	for i, magic := range dumpMagic {
		if buffer[i] != magic {
			mem.Unmap()
			file.Close()
			return nil, nil, nil, ErrInvalidDumpMagic
		}
	}
	if lock {
		if err := mem.Lock(); err != nil {
			mem.Unmap()
			file.Close()
			return nil, nil, nil, err
		}
	}
	return file, mem, buffer[len(dumpMagic):], err
}

// memoryMapFile tries to memory map an already opened file descriptor.
func memoryMapFile(file *os.File, write bool) (mmap.MMap, []uint32, error) {
	// Try to memory map the file
	flag := mmap.RDONLY
	if write {
		flag = mmap.RDWR
	}
	mem, err := mmap.Map(file, flag, 0)
	if err != nil {
		return nil, nil, err
	}
	// Yay, we managed to memory map the file, here be dragons
	header := *(*reflect.SliceHeader)(unsafe.Pointer(&mem))
	header.Len /= 4
	header.Cap /= 4

	return mem, *(*[]uint32)(unsafe.Pointer(&header)), nil
}

// memoryMapAndGenerate tries to memory map a temporary file of uint32s for write
// access, fill it with the data from a generator and then move it into the final
// path requested.
func memoryMapAndGenerate(path string, size uint64, lock bool, generator func(buffer []uint32)) (*os.File, mmap.MMap, []uint32, error) {
	// Ensure the data folder exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, nil, nil, err
	}
	// Create a huge temporary empty file to fill with data
	temp := path + "." + strconv.Itoa(rand.Int())

	dump, err := os.Create(temp)
	if err != nil {
		return nil, nil, nil, err
	}
	if err = dump.Truncate(int64(len(dumpMagic))*4 + int64(size)); err != nil {
		return nil, nil, nil, err
	}
	// Memory map the file for writing and fill it with the generator
	mem, buffer, err := memoryMapFile(dump, true)
	if err != nil {
		dump.Close()
		return nil, nil, nil, err
	}
	copy(buffer, dumpMagic)

	data := buffer[len(dumpMagic):]
	generator(data)

	if err := mem.Unmap(); err != nil {
		return nil, nil, nil, err
	}
	if err := dump.Close(); err != nil {
		return nil, nil, nil, err
	}
	if err := os.Rename(temp, path); err != nil {
		return nil, nil, nil, err
	}
	return memoryMap(path, lock)
}

// Mode defines the type and amount of PoW verification a progpow engine makes.
type Mode uint

const (
	ModeNormal Mode = iota
	ModeShared
	ModeTest
	ModeFake
	ModeFullFake
)

// Config are the configuration parameters of the progpow.
type Config struct {
	PowMode Mode

	CacheDir       string
	CachesInMem    int
	CachesOnDisk   int
	CachesLockMmap bool
	DurationLimit  *big.Int
	GasCeil        uint64
	MinDifficulty  *big.Int

	// When set, notifications sent by the remote sealer will
	// be block header JSON objects instead of work package arrays.
	NotifyFull bool

	Log *log.Logger `toml:"-"`
}

// Progpow is a proof-of-work consensus engine using the blake3 hash algorithm
type Progpow struct {
	config Config

	caches *lru // In memory caches to avoid regenerating too often

	// Mining related fields
	rand     *rand.Rand    // Properly seeded random source for nonces
	threads  int           // Number of threads to mine on if mining
	update   chan struct{} // Notification channel to update mining parameters
	hashrate metrics.Meter // Meter tracking the average hashrate
	remote   *remoteSealer

	// The fields below are hooks for testing
	shared    *Progpow      // Shared PoW verifier to avoid cache regeneration
	fakeFail  uint64        // Block number which fails PoW check even in fake mode
	fakeDelay time.Duration // Time delay to sleep for before returning from verify

	lock      sync.Mutex // Ensures thread safety for the in-memory caches and mining fields
	closeOnce sync.Once  // Ensures exit channel will not be closed twice.
}

// New creates a full sized progpow PoW scheme and starts a background thread for
// remote mining, also optionally notifying a batch of remote services of new work
// packages.
func New(config Config, notify []string, noverify bool) *Progpow {
	if config.Log == nil {
		config.Log = &log.Log
	}
	if config.CachesInMem <= 0 {
		config.Log.Warn("One ethash cache must always be in memory", "requested", config.CachesInMem)
		config.CachesInMem = 1
	}
	if config.CacheDir != "" && config.CachesOnDisk > 0 {
		config.Log.Info("Disk storage enabled for ethash caches", "dir", config.CacheDir, "count", config.CachesOnDisk)
	}
	progpow := &Progpow{
		config:   config,
		caches:   newlru("cache", config.CachesInMem, newCache),
		update:   make(chan struct{}),
		hashrate: metrics.NewMeterForced(),
	}
	if config.PowMode == ModeShared {
		progpow.shared = sharedProgpow
	}
	progpow.remote = startRemoteSealer(progpow, notify, noverify)
	return progpow
}

// NewTester creates a small sized progpow PoW scheme useful only for testing
// purposes.
func NewTester(notify []string, noverify bool) *Progpow {
	return New(Config{PowMode: ModeTest}, notify, noverify)
}

// NewFaker creates a progpow consensus engine with a fake PoW scheme that accepts
// all blocks' seal as valid, though they still have to conform to the Quai
// consensus rules.
func NewFaker() *Progpow {
	return &Progpow{
		config: Config{
			PowMode: ModeFake,
			Log:     &log.Log,
		},
	}
}

// NewFakeFailer creates a progpow consensus engine with a fake PoW scheme that
// accepts all blocks as valid apart from the single one specified, though they
// still have to conform to the Quai consensus rules.
func NewFakeFailer(fail uint64) *Progpow {
	return &Progpow{
		config: Config{
			PowMode: ModeFake,
			Log:     &log.Log,
		},
		fakeFail: fail,
	}
}

// NewFakeDelayer creates a progpow consensus engine with a fake PoW scheme that
// accepts all blocks as valid, but delays verifications by some time, though
// they still have to conform to the Quai consensus rules.
func NewFakeDelayer(delay time.Duration) *Progpow {
	return &Progpow{
		config: Config{
			PowMode: ModeFake,
			Log:     &log.Log,
		},
		fakeDelay: delay,
	}
}

// NewFullFaker creates an progpow consensus engine with a full fake scheme that
// accepts all blocks as valid, without checking any consensus rules whatsoever.
func NewFullFaker() *Progpow {
	return &Progpow{
		config: Config{
			PowMode: ModeFullFake,
			Log:     &log.Log,
		},
	}
}

// NewShared creates a full sized progpow PoW shared between all requesters running
// in the same process.
func NewShared() *Progpow {
	return &Progpow{shared: sharedProgpow}
}

// Close closes the exit channel to notify all backend threads exiting.
func (progpow *Progpow) Close() error {
	progpow.closeOnce.Do(func() {
		// Short circuit if the exit channel is not allocated.
		if progpow.remote == nil {
			return
		}
		close(progpow.remote.requestExit)
		<-progpow.remote.exitCh
	})
	return nil
}

// lru tracks caches or datasets by their last use time, keeping at most N of them.
type lru struct {
	what string
	new  func(epoch uint64) interface{}
	mu   sync.Mutex
	// Items are kept in a LRU cache, but there is a special case:
	// We always keep an item for (highest seen epoch) + 1 as the 'future item'.
	cache      *simplelru.LRU
	future     uint64
	futureItem interface{}
}

// newlru create a new least-recently-used cache for either the verification caches
// or the mining datasets.
func newlru(what string, maxItems int, new func(epoch uint64) interface{}) *lru {
	if maxItems <= 0 {
		maxItems = 1
	}
	cache, _ := simplelru.NewLRU(maxItems, func(key, value interface{}) {
		log.Trace("Evicted ethash "+what, "epoch", key)
	})
	return &lru{what: what, new: new, cache: cache}
}

// get retrieves or creates an item for the given epoch. The first return value is always
// non-nil. The second return value is non-nil if lru thinks that an item will be useful in
// the near future.
func (lru *lru) get(epoch uint64) (item, future interface{}) {
	lru.mu.Lock()
	defer lru.mu.Unlock()

	// Get or create the item for the requested epoch.
	item, ok := lru.cache.Get(epoch)
	if !ok {
		if lru.future > 0 && lru.future == epoch {
			item = lru.futureItem
		} else {
			log.Trace("Requiring new ethash "+lru.what, "epoch", epoch)
			item = lru.new(epoch)
		}
		lru.cache.Add(epoch, item)
	}
	// Update the 'future item' if epoch is larger than previously seen.
	if epoch < maxEpoch-1 && lru.future < epoch+1 {
		log.Trace("Requiring new future ethash "+lru.what, "epoch", epoch+1)
		future = lru.new(epoch + 1)
		lru.future = epoch + 1
		lru.futureItem = future
	}
	return item, future
}

// cache wraps an ethash cache with some metadata to allow easier concurrent use.
type cache struct {
	epoch uint64    // Epoch for which this cache is relevant
	dump  *os.File  // File descriptor of the memory mapped cache
	mmap  mmap.MMap // Memory map itself to unmap before releasing
	cache []uint32  // The actual cache data content (may be memory mapped)
	cDag  []uint32  // The cDag used by progpow. May be nil
	once  sync.Once // Ensures the cache is generated only once
}

// newCache creates a new ethash verification cache and returns it as a plain Go
// interface to be usable in an LRU cache.
func newCache(epoch uint64) interface{} {
	return &cache{epoch: epoch}
}

// generate ensures that the cache content is generated before use.
func (c *cache) generate(dir string, limit int, lock bool, test bool) {
	c.once.Do(func() {
		size := cacheSize(c.epoch*epochLength + 1)
		seed := seedHash(c.epoch*epochLength + 1)
		if test {
			size = 1024
		}
		// If we don't store anything on disk, generate and return.
		if dir == "" {
			c.cache = make([]uint32, size/4)
			generateCache(c.cache, c.epoch, seed)
			c.cDag = make([]uint32, progpowCacheWords)
			generateCDag(c.cDag, c.cache, c.epoch)
			return
		}
		// Disk storage is needed, this will get fancy
		var endian string
		if !isLittleEndian() {
			endian = ".be"
		}
		path := filepath.Join(dir, fmt.Sprintf("cache-R%d-%x%s", algorithmRevision, seed[:8], endian))
		logger := log.New("epoch")

		// We're about to mmap the file, ensure that the mapping is cleaned up when the
		// cache becomes unused.
		runtime.SetFinalizer(c, (*cache).finalizer)

		// Try to load the file from disk and memory map it
		var err error
		c.dump, c.mmap, c.cache, err = memoryMap(path, lock)
		if err == nil {
			logger.Debug("Loaded old ethash cache from disk")
			c.cDag = make([]uint32, progpowCacheWords)
			generateCDag(c.cDag, c.cache, c.epoch)
			return
		}
		logger.Debug("Failed to load old ethash cache", "err", err)

		// No previous cache available, create a new cache file to fill
		c.dump, c.mmap, c.cache, err = memoryMapAndGenerate(path, size, lock, func(buffer []uint32) { generateCache(buffer, c.epoch, seed) })
		if err != nil {
			logger.Error("Failed to generate mapped ethash cache", "err", err)

			c.cache = make([]uint32, size/4)
			generateCache(c.cache, c.epoch, seed)
		}
		c.cDag = make([]uint32, progpowCacheWords)
		generateCDag(c.cDag, c.cache, c.epoch)
		// Iterate over all previous instances and delete old ones
		for ep := int(c.epoch) - limit; ep >= 0; ep-- {
			seed := seedHash(uint64(ep)*epochLength + 1)
			path := filepath.Join(dir, fmt.Sprintf("cache-R%d-%x%s", algorithmRevision, seed[:8], endian))
			os.Remove(path)
		}
	})
}

// finalizer unmaps the memory and closes the file.
func (c *cache) finalizer() {
	if c.mmap != nil {
		c.mmap.Unmap()
		c.dump.Close()
		c.mmap, c.dump = nil, nil
	}
}

// cache tries to retrieve a verification cache for the specified block number
// by first checking against a list of in-memory caches, then against caches
// stored on disk, and finally generating one if none can be found.
func (progpow *Progpow) cache(block uint64) *cache {
	epoch := block / epochLength
	currentI, futureI := progpow.caches.get(epoch)
	current := currentI.(*cache)

	// Wait for generation finish.
	current.generate(progpow.config.CacheDir, progpow.config.CachesOnDisk, progpow.config.CachesLockMmap, progpow.config.PowMode == ModeTest)

	// If we need a new future cache, now's a good time to regenerate it.
	if futureI != nil {
		future := futureI.(*cache)
		go future.generate(progpow.config.CacheDir, progpow.config.CachesOnDisk, progpow.config.CachesLockMmap, progpow.config.PowMode == ModeTest)
	}
	return current
}

// Threads returns the number of mining threads currently enabled. This doesn't
// necessarily mean that mining is running!
func (progpow *Progpow) Threads() int {
	progpow.lock.Lock()
	defer progpow.lock.Unlock()

	return progpow.threads
}

// SetThreads updates the number of mining threads currently enabled. Calling
// this method does not start mining, only sets the thread count. If zero is
// specified, the miner will use all cores of the machine. Setting a thread
// count below zero is allowed and will cause the miner to idle, without any
// work being done.
func (progpow *Progpow) SetThreads(threads int) {
	progpow.lock.Lock()
	defer progpow.lock.Unlock()

	if progpow.shared != nil {
		// If we're running a shared PoW, set the thread count on that instead
		progpow.shared.SetThreads(threads)
	} else {
		// Update the threads and ping any running seal to pull in any changes
		progpow.threads = threads
		select {
		case progpow.update <- struct{}{}:
		default:
		}
	}
}

// Hashrate implements PoW, returning the measured rate of the search invocations
// per second over the last minute.
// Note the returned hashrate includes local hashrate, but also includes the total
// hashrate of all remote miner.
func (progpow *Progpow) Hashrate() float64 {
	// Short circuit if we are run the progpow in normal/test mode.
	if progpow.config.PowMode != ModeNormal && progpow.config.PowMode != ModeTest {
		return progpow.hashrate.Rate1()
	}
	var res = make(chan uint64, 1)

	select {
	case progpow.remote.fetchRateCh <- res:
	case <-progpow.remote.exitCh:
		// Return local hashrate only if progpow is stopped.
		return progpow.hashrate.Rate1()
	}

	// Gather total submitted hash rate of remote sealers.
	return progpow.hashrate.Rate1() + float64(<-res)
}

// SubmitHashrate can be used for remote miners to submit their hash rate.
// This enables the node to report the combined hash rate of all miners
// which submit work through this node.
//
// It accepts the miner hash rate and an identifier which must be unique
// between nodes.
func (progpow *Progpow) SubmitHashrate(rate hexutil.Uint64, id common.Hash) bool {
	if progpow.remote == nil {
		return false
	}

	var done = make(chan struct{}, 1)
	select {
	case progpow.remote.submitRateCh <- &hashrate{done: done, rate: uint64(rate), id: id}:
	case <-progpow.remote.exitCh:
		return false
	}

	// Block until hash rate submitted successfully.
	<-done
	return true
}

// APIs implements consensus.Engine, returning the user facing RPC APIs.
func (progpow *Progpow) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	// In order to ensure backward compatibility, we exposes progpow RPC APIs
	// to both eth and progpow namespaces.
	return []rpc.API{
		{
			Namespace: "eth",
			Version:   "1.0",
			Service:   &API{progpow},
			Public:    true,
		},
		{
			Namespace: "progpow",
			Version:   "1.0",
			Service:   &API{progpow},
			Public:    true,
		},
	}
}
