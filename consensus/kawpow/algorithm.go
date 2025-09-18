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

	// For kawpow, we need to generate a light cache for each epoch
	// This is a simplified version - in a full implementation you'd want
	// to follow the exact kawpow specification
	for i := 0; i < len(cDag); i++ {
		cDag[i] = cache[i%len(cache)]
	}
}

// calculateDatasetItem calculates a single item in the kawpow dataset
func calculateDatasetItem(cache []uint32, index uint32) []uint32 {
	// This is a placeholder implementation
	// In a full kawpow implementation, this would follow the exact dataset generation
	// algorithm as specified in the kawpow documentation
	item := make([]uint32, 64) // 256 bytes = 64 uint32s

	// Use the cache to generate the item
	for i := 0; i < len(item); i++ {
		cacheIndex := (index*uint32(len(item)) + uint32(i)) % uint32(len(cache))
		item[i] = cache[cacheIndex]
	}

	return item
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
func kawpowInitialize(hash []byte, nonce uint64) ([25]uint32, uint64) {
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

	seedHead := uint64(seed[0]) + (uint64(seed[1]) << 32)

	return seed, seedHead
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
	// This is a placeholder - you'd need to implement the full Keccak-f[800]
	// permutation as used in kawpow. For now, we'll use a simplified version.

	// Convert to 64-bit state for standard keccak
	state64 := make([]uint64, 12) // 800 bits = 25*32 bits = 12.5*64 bits
	for i := 0; i < 12; i++ {
		if i*2+1 < 25 {
			state64[i] = uint64((*state)[i*2]) | (uint64((*state)[i*2+1]) << 32)
		} else {
			state64[i] = uint64((*state)[i*2])
		}
	}

	// Apply a simplified permutation (not the full Keccak-f[800])
	for i := 0; i < len(state64); i++ {
		state64[i] ^= state64[(i+1)%len(state64)]
		state64[i] = ((state64[i] << 1) | (state64[i] >> 63))
	}

	// Convert back to 32-bit state
	for i := 0; i < 12; i++ {
		if i*2 < 25 {
			(*state)[i*2] = uint32(state64[i])
		}
		if i*2+1 < 25 {
			(*state)[i*2+1] = uint32(state64[i] >> 32)
		}
	}
}

// kawpowHash computes the kawpow hash
func kawpowHash(cfg *kawpowConfig, height, seed, datasetSize uint64, lookup func(uint32) []uint32, l1 []uint32) []byte {
	// This is a simplified kawpow hash implementation
	// A full implementation would follow the exact kawpow specification

	mix := make([]byte, 32)
	binary.LittleEndian.PutUint64(mix[0:8], seed)
	binary.LittleEndian.PutUint64(mix[8:16], height)

	// Simplified mixing with cache
	for i := 0; i < len(mix); i++ {
		mix[i] ^= byte(l1[i%len(l1)])
	}

	return mix
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
	return a*0x01000193 ^ b
}

// fnvHash mixes in data into mix using the ethash fnv method.
func fnvHash(mix []uint32, data []uint32) {
	for i := 0; i < len(mix); i++ {
		mix[i] = mix[i]*0x01000193 ^ data[i]
	}
}

// generateDatasetItem combines data from 256 pseudorandomly selected cache nodes,
// and hashes that to compute a single dataset node.
func generateDatasetItem(cache []uint32, index uint32, keccak512 hasher) []byte {
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
	for i := uint32(0); i < datasetParents; i++ {
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
