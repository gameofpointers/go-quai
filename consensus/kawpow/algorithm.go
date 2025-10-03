// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.

package kawpow

import (
	"encoding/binary"
	"hash"
	"reflect"
	"runtime/debug"
	"sync"
	"unsafe"

	"golang.org/x/crypto/sha3"

	"github.com/dominant-strategies/go-quai/common/bitutil"
	"github.com/dominant-strategies/go-quai/log"
)

const (
	datasetInitBytes   = 1 << 30 // Bytes in dataset at genesis
	datasetGrowthBytes = 1 << 23 // Dataset growth per epoch
	cacheInitBytes     = 1 << 24 // Bytes in cache at genesis
	cacheGrowthBytes   = 1 << 17 // Cache growth per epoch
	mixBytes           = 128     // Width of mix
	hashBytes          = 64      // Hash length in bytes
	hashWords          = 16      // Number of 32 bit ints in a hash
	datasetParents     = 512     // Number of parents of each dataset element
	cacheRounds        = 3       // Number of rounds in cache production
	loopAccesses       = 64      // Number of accesses in hashimoto loop

	// Kawpow specific constants
	kawpowCacheWords = kawpowCacheBytes / 4
	C_epochLength    = 7500 // Blocks per epoch
	maxCachedEpoch   = 100  // Maximum cached epochs
)

// cacheSize returns the size of the kawpow verification cache that belongs to a certain
// block number.
func cacheSize(block uint64) uint64 {
	epoch := int(block / C_epochLength)
	if epoch < len(cacheSizes) {
		return cacheSizes[epoch]
	}
	return calcCacheSize(epoch)
}

// datasetSize returns the size of the kawpow mining dataset that belongs to a certain
// block number.
func datasetSize(block uint64) uint64 {
	epoch := int(block / C_epochLength)
	if epoch < len(datasetSizes) {
		return datasetSizes[epoch]
	}
	return calcDatasetSize(epoch)
}

// calcCacheSize calculates the cache size for a given epoch
func calcCacheSize(epoch int) uint64 {
	size := cacheInitBytes + cacheGrowthBytes*uint64(epoch)
	size -= hashBytes
	for !isPrime(size / hashBytes) {
		size -= 2 * hashBytes
	}
	return size
}

// calcDatasetSize calculates the dataset size for a given epoch
func calcDatasetSize(epoch int) uint64 {
	size := datasetInitBytes + datasetGrowthBytes*uint64(epoch)
	size -= mixBytes
	for !isPrime(size / mixBytes) {
		size -= 2 * mixBytes
	}
	return size
}

// isPrime returns true if the given number is prime
func isPrime(n uint64) bool {
	if n < 2 {
		return false
	}
	if n == 2 {
		return true
	}
	if n%2 == 0 {
		return false
	}
	for i := uint64(3); i*i <= n; i += 2 {
		if n%i == 0 {
			return false
		}
	}
	return true
}

// seedHash is the seed to use for generating a verification cache and the mining
// dataset.
func seedHash(block uint64) []byte {
	seed := make([]byte, 32)
	if block < C_epochLength {
		return seed
	}
	keccak256 := getHasher256()
	defer returnHasher(keccak256)

	for i := 0; i < int(block/C_epochLength); i++ {
		keccak256.Reset()
		keccak256.Write(seed)
		seed = keccak256.Sum(seed[:0])
	}
	return seed
}

// makeHasher creates a repetition-free keccak256 hasher
var hasherPool = sync.Pool{
	New: func() interface{} { return sha3.NewLegacyKeccak256() },
}

func getHasher256() hash.Hash {
	return hasherPool.Get().(hash.Hash)
}

func returnHasher(h hash.Hash) {
	h.Reset()
	hasherPool.Put(h)
}

// generateCache creates the kawpow verification cache
func generateCache(dest []uint32, epoch uint64, seed []byte, logger *log.Logger) {
	defer func() {
		if r := recover(); r != nil {
			logger.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Error("Go-Quai Panicked")
		}
	}()

	// Convert our destination slice to a byte buffer
	header := *(*reflect.SliceHeader)(unsafe.Pointer(&dest))
	header.Len *= 4
	header.Cap *= 4
	cache := *(*[]byte)(unsafe.Pointer(&header))

	// Calculate the number of theoretical rows (we'll only use a subset)
	size := uint64(len(cache))
	rows := int(size) / hashBytes

	// Create a hasher to reuse between invocations
	keccak512 := sha3.NewLegacyKeccak512()

	// Sequentially produce the initial dataset
	keccak512.Reset()
	keccak512.Write(seed)
	for offset := 0; offset < rows; offset++ {
		keccak512.Reset()
		if offset == 0 {
			keccak512.Write(seed)
		} else {
			keccak512.Write(cache[(offset-1)*hashBytes : offset*hashBytes])
		}
		hash := keccak512.Sum(nil)
		copy(cache[offset*hashBytes:], hash)
	}
	// Use a low-round version of randmemohash
	temp := make([]byte, hashBytes)

	for i := 0; i < cacheRounds; i++ {
		for j := 0; j < rows; j++ {
			var (
				srcOff = ((j - 1 + rows) % rows) * hashBytes
				dstOff = j * hashBytes
				xorOff = (binary.LittleEndian.Uint32(cache[dstOff:]) % uint32(rows)) * hashBytes
			)
			bitutil.XORBytes(temp, cache[srcOff:srcOff+hashBytes], cache[xorOff:xorOff+hashBytes])

			keccak512.Reset()
			keccak512.Write(temp)
			copy(cache[dstOff:], keccak512.Sum(nil))
		}
	}
}

// generateCDag creates the kawpow mining dataset
func generateCDag(cDag []uint32, cache []uint32, epoch uint64, logger *log.Logger) {
	defer func() {
		if r := recover(); r != nil {
			logger.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Error("Go-Quai Panicked")
		}
	}()

	keccak512 := makeHasher(sha3.NewLegacyKeccak512())
	swapped := !isLittleEndian()

	header := *(*reflect.SliceHeader)(unsafe.Pointer(&cDag))
	header.Len *= 4
	header.Cap *= 4
	l1 := *(*[]byte)(unsafe.Pointer(&header))

	rows := len(l1) / hashBytes
	for i := 0; i < rows; i++ {
		item := generateDatasetItem(cache, uint32(i), keccak512, datasetParents)
		if swapped {
			swapBytes(item)
		}
		copy(l1[i*hashBytes:], item)
	}
}

func fillDatasetItem2048Words(dest []uint32, cache []uint32, index uint32, keccak512 hasher) {
	for i := uint32(0); i < kawpowDagLoads; i++ {
		item := generateDatasetItem(cache, index*4+i, keccak512, datasetParents)
		for j := 0; j < hashWords; j++ {
			dest[int(i)*hashWords+j] = binary.LittleEndian.Uint32(item[j*4:])
		}
	}
}

func generateDatasetItem2048(cache []uint32, index uint32, keccak512 hasher) []uint32 {
	words := make([]uint32, hashWords*kawpowDagLoads)
	fillDatasetItem2048Words(words, cache, index, keccak512)
	return words
}

// kawpowConfig holds kawpow-specific configuration
type kawpowConfig struct {
	PeriodLength        uint64
	DagLoads            int
	CacheBytes          uint32
	LaneCount           int
	RegisterCount       int
	RoundCount          int
	RoundCacheAccesses  int
	RoundMathOperations int
}

// kawpowInitialize performs kawpow initialization with ravencoin constants
func kawpowInitialize(hash []byte, nonce uint64) ([25]uint32, [2]uint32) {
	var seed [25]uint32
	for i := 0; i < 8; i++ {
		seed[i] = binary.LittleEndian.Uint32(hash[i*4 : i*4+4])
	}

	seed[8] = uint32(nonce)
	seed[9] = uint32(nonce >> 32)

	// Apply ravencoin kawpow constants
	for i := 10; i < 25; i++ {
		seed[i] = ravencoinKawpow[i-10]
	}

	keccakF800(&seed)

	var hashSeed [2]uint32
	hashSeed[0] = seed[0]
	hashSeed[1] = seed[1]

	return seed, hashSeed
}

// kawpowFinalize performs kawpow finalization with ravencoin constants
func kawpowFinalize(seed [25]uint32, mixHash []byte) []byte {
	var state [25]uint32
	for i := 0; i < 8; i++ {
		state[i] = seed[i]
		state[i+8] = binary.LittleEndian.Uint32(mixHash[i*4 : i*4+4])
	}

	for i := 16; i < 25; i++ {
		state[i] = ravencoinKawpow[i-16]
	}

	keccakF800(&state)

	result := make([]byte, 32)
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(result[i*4:], state[i])
	}

	return result
}

// keccakF800 is the Keccak-f[800] permutation used in kawpow
func keccakF800(state *[25]uint32) {
	// Proper Keccak-f[800] implementation using 22 rounds (same as other kawpow functions)
	for r := 0; r < 22; r++ {
		keccakF800Round(state, r)
	}
}

// kawpowHash computes the kawpow hash using the ProgPoW algorithm with KAWPOW parameters
func kawpowHash(cfg *kawpowConfig, height, seed, datasetSize uint64, lookup func(uint32) []uint32, l1 []uint32) []byte {
	// Convert seed to hash input for kawpow
	hash := make([]byte, 32)
	binary.LittleEndian.PutUint64(hash[0:8], seed)
	binary.LittleEndian.PutUint64(hash[8:16], height)
	_, digest := kawpow(hash, seed, datasetSize, height, l1, lookup)

	return digest
}

// hasher is a repetitive hasher allowing the same hash data structures to be
// reused between hash runs instead of requiring new ones to be created.
type hasher func(dest []byte, data []byte)

// makeHasher creates a repetitive hasher, allowing the same hash data structures to
// be reused between hash runs instead of requiring new ones to be created. The returned
// function is not thread safe!
func makeHasher(h hash.Hash) hasher {
	// sha3.state supports Read to get the sum, use it to avoid the overhead of Sum.
	// Read alters the state but we reset the hash before every operation.
	type readerHash interface {
		hash.Hash
		Read([]byte) (int, error)
	}
	rh := h.(readerHash)

	outputLen := rh.Size()
	return func(dest []byte, data []byte) {
		rh.Reset()
		rh.Write(data)
		rh.Read(dest[:outputLen])
	}
}

// fnv is an algorithm inspired by the FNV hash, which in some cases is used as
// a non-associative substitute for XOR. Note that we multiply the prime with
// the full 32-bit input, in contrast with the FNV-1 spec which multiplies the
// prime with one byte (octet) in turn.
func fnv(a, b uint32) uint32 {
	return a*fnvPrime ^ b
}

// fnvHash mixes in data into mix using the ethash fnv method.
func fnvHash(mix []uint32, data []uint32) {
	for i := 0; i < len(mix); i++ {
		mix[i] = mix[i]*fnvPrime ^ data[i]
	}
}

func swapBytes(buffer []byte) {
	for i := 0; i < len(buffer); i += 4 {
		binary.BigEndian.PutUint32(buffer[i:], binary.LittleEndian.Uint32(buffer[i:]))
	}
}

// generateDatasetItem combines data from 256 pseudorandomly selected cache nodes,
// and hashes that to compute a single dataset node.
func generateDatasetItem(cache []uint32, index uint32, keccak512 hasher, parents uint32) []byte {
	// Calculate the number of theoretical rows (we use one buffer nonetheless)
	rows := uint32(len(cache) / hashWords)

	// Initialize the mix
	mix := make([]byte, hashBytes)

	binary.LittleEndian.PutUint32(mix, cache[(index%rows)*hashWords]^index)
	for i := 1; i < hashWords; i++ {
		binary.LittleEndian.PutUint32(mix[i*4:], cache[(index%rows)*hashWords+uint32(i)])
	}
	keccak512(mix, mix)

	// Convert the mix to uint32s to avoid constant bit shifting
	intMix := make([]uint32, hashWords)
	for i := 0; i < len(intMix); i++ {
		intMix[i] = binary.LittleEndian.Uint32(mix[i*4:])
	}
	// fnv it with a lot of random cache nodes based on index
	for i := uint32(0); i < parents; i++ {
		parent := fnv(index^i, intMix[i%16]) % rows
		fnvHash(intMix, cache[parent*hashWords:])
	}
	// Flatten the uint32 mix into a binary one and return
	for i, val := range intMix {
		binary.LittleEndian.PutUint32(mix[i*4:], val)
	}
	keccak512(mix, mix)
	return mix
}

// The full lookup tables are imported from kawpow_lookup.go
