// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.

package kawpow

import (
	"encoding/binary"
	"hash"
	"math/big"
	"reflect"
	"runtime/debug"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/crypto/sha3"

	"github.com/dominant-strategies/go-quai/common"
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

	// Kawpow specific constants
	C_epochLength  = 7500 // Blocks per epoch
	maxCachedEpoch = 100  // Maximum cached epochs
)

// cacheSize returns the size of the ethash verification cache that belongs to a certain
// block number.
func cacheSize(block uint64) uint64 {
	epoch := int(block / C_epochLength)
	if epoch < maxCachedEpoch {
		return cacheSizes[epoch]
	}
	return calcCacheSize(epoch)
}

// calcCacheSize calculates the cache size for epoch. The cache size grows linearly,
// however, we always take the highest prime below the linearly growing threshold in order
// to reduce the risk of accidental regularities leading to cyclic behavior.
func calcCacheSize(epoch int) uint64 {
	size := cacheInitBytes + cacheGrowthBytes*uint64(epoch) - hashBytes
	for !new(big.Int).SetUint64(size / hashBytes).ProbablyPrime(1) { // Always accurate for n < 2^64
		size -= 2 * hashBytes
	}
	return size
}

// datasetSize returns the size of the ethash mining dataset that belongs to a certain
// block number.
func datasetSize(block uint64) uint64 {
	epoch := int(block / C_epochLength)
	if epoch < maxCachedEpoch {
		return datasetSizes[epoch]
	}
	return calcDatasetSize(epoch)
}

// calcDatasetSize calculates the dataset size for epoch. The dataset size grows linearly,
// however, we always take the highest prime below the linearly growing threshold in order
// to reduce the risk of accidental regularities leading to cyclic behavior.
func calcDatasetSize(epoch int) uint64 {
	size := datasetInitBytes + datasetGrowthBytes*uint64(epoch) - mixBytes
	for !new(big.Int).SetUint64(size / mixBytes).ProbablyPrime(1) { // Always accurate for n < 2^64
		size -= 2 * mixBytes
	}
	return size
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
	rh, ok := h.(readerHash)
	if !ok {
		panic("can't find Read method on hash")
	}
	outputLen := rh.Size()
	return func(dest []byte, data []byte) {
		rh.Reset()
		rh.Write(data)
		rh.Read(dest[:outputLen])
	}
}

// seedHash is the seed to use for generating a verification cache and the mining
// dataset.
func seedHash(block uint64) []byte {
	seed := make([]byte, 32)
	if block < C_epochLength {
		return seed
	}
	keccak256 := makeHasher(sha3.NewLegacyKeccak256())
	for i := 0; i < int(block/C_epochLength); i++ {
		keccak256(seed, seed)
	}
	return seed
}

// SeedHash is the seed to use for generating a verification cache and the mining
// dataset.
func SeedHash(block uint64) []byte {
	return seedHash(block)
}

// generateCache creates a verification cache of a given size for an input seed.
// The cache production process involves first sequentially filling up 32 MB of
// memory, then performing two passes of Sergio Demian Lerner's RandMemoHash
// algorithm from Strict Memory Hard Hashing Functions (2014). The output is a
// set of 524288 64-byte values.
// This method places the result into dest in machine byte order.
func generateCache(dest []uint32, epoch uint64, seed []byte, logger *log.Logger) {
	// Print some debug logs to allow analysis on low end devices

	start := time.Now()
	defer func() {
		elapsed := time.Since(start)

		logEntry := logger.WithFields(log.Fields{
			"elapsed": common.PrettyDuration(elapsed),
		})

		if elapsed > 3*time.Second {
			logEntry.Info("Generating ethash verification cache")
		} else {
			logEntry.Debug("Generating ethash verification cache")
		}
	}()
	// Convert our destination slice to a byte buffer
	header := *(*reflect.SliceHeader)(unsafe.Pointer(&dest))
	header.Len *= 4
	header.Cap *= 4
	cache := *(*[]byte)(unsafe.Pointer(&header))

	// Calculate the number of theoretical rows (we'll store in one buffer nonetheless)
	size := uint64(len(cache))
	rows := int(size) / hashBytes

	// Start a monitoring goroutine to report progress on low end devices
	var progress uint32

	done := make(chan struct{})
	defer close(done)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.WithFields(log.Fields{
					"error":      r,
					"stacktrace": string(debug.Stack()),
				}).Error("Go-Quai Panicked")
			}
		}()
		for {
			select {
			case <-done:
				return
			case <-time.After(3 * time.Second):
				logger.WithFields(log.Fields{
					"percentage": uint64(atomic.LoadUint32(&progress) * 100 / uint32(rows) / 4),
					"elapsed":    common.PrettyDuration(time.Since(start)),
				}).Info("Generating ethash verification cache")
			}
		}
	}()
	// Create a hasher to reuse between invocations
	keccak512 := makeHasher(sha3.NewLegacyKeccak512())

	// Sequentially produce the initial dataset
	keccak512(cache, seed)
	for offset := uint64(hashBytes); offset < size; offset += hashBytes {
		keccak512(cache[offset:], cache[offset-hashBytes:offset])
		atomic.AddUint32(&progress, 1)
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
			keccak512(cache[dstOff:], temp)

			atomic.AddUint32(&progress, 1)
		}
	}
	// Swap the byte order on big endian systems and return
	if !isLittleEndian() {
		swap(cache)
	}
}

// generateCDag generates the cDag used for progpow. If the 'cDag' is nil, this method is a no-op. Otherwise
// it expects the cDag to be of size progpowCacheWords
func generateCDag(cDag, cache []uint32, epoch uint64, logger *log.Logger) {
	if cDag == nil {
		return
	}
	start := time.Now()
	keccak512 := makeHasher(sha3.NewLegacyKeccak512())

	for i := uint32(0); i < kawpowCacheWords/16; i++ {
		rawData := generateDatasetItem(cache, i, keccak512)
		// 64 bytes in rawData -> 16 uint32
		for j := uint32(0); j < 16; j++ {
			cDag[i*16+j] = binary.LittleEndian.Uint32(rawData[4*j:])
		}
	}

	elapsed := time.Since(start)
	logger.WithFields(log.Fields{
		"elapsed": common.PrettyDuration(elapsed),
		"epoch":   epoch,
	}).Debug("Generated progpow cDag")
}

// swap changes the byte order of the buffer assuming a uint32 representation.
func swap(buffer []byte) {
	for i := 0; i < len(buffer); i += 4 {
		binary.BigEndian.PutUint32(buffer[i:], binary.LittleEndian.Uint32(buffer[i:]))
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
