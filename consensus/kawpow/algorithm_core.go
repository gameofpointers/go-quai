// Copyright 2019 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package kawpow

import (
	"encoding/binary"
	"math/bits"

	"golang.org/x/crypto/sha3"
)

const (
	// KAWPOW specific constants (different from ProgPoW)
	kawpowLanes    = 16 // The number of parallel lanes
	kawpowRegs     = 32 // The register file usage size
	kawpowCntCache = 11 // Cache accesses per round
	kawpowCntMath  = 18 // Math operations per round
	kawpowCntDag   = 64 // Number of DAG accesses
	kawpowMixBytes = 256
)

const (
	fnvOffsetBasis = 0x811c9dc5
	fnvPrime       = 0x01000193
)

// Core algorithm functions (identical to ProgPoW but with KAWPOW parameters)

func rotl32(x uint32, n uint32) uint32 {
	return ((x) << (n % 32)) | ((x) >> (32 - (n % 32)))
}

func rotr32(x uint32, n uint32) uint32 {
	return ((x) >> (n % 32)) | ((x) << (32 - (n % 32)))
}

func lower32(in uint64) uint32 {
	return uint32(in)
}

func higher32(in uint64) uint32 {
	return uint32(in >> 32)
}

var keccakfRNDC = [24]uint32{
	0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b, 0x80000001,
	0x80008081, 0x00008009, 0x0000008a, 0x00000088, 0x80008009, 0x8000000a,
	0x8000808b, 0x0000008b, 0x00008089, 0x00008003, 0x00008002, 0x00000080,
	0x0000800a, 0x8000000a, 0x80008081, 0x00008080, 0x80000001, 0x80008008}

func keccakF800Round(st *[25]uint32, r int) {
	var keccakfROTC = [24]uint32{1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2,
		14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61,
		20, 44}
	var keccakfPILN = [24]uint32{10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24,
		4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9,
		6, 1}
	bc := make([]uint32, 5)
	// Theta
	for i := 0; i < 5; i++ {
		bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20]
	}

	for i := 0; i < 5; i++ {
		t := bc[(i+4)%5] ^ rotl32(bc[(i+1)%5], 1)
		for j := 0; j < 25; j += 5 {
			st[j+i] ^= t
		}
	}

	// Rho Pi
	t := st[1]
	for i, j := range keccakfPILN {
		bc[0] = st[j]
		st[j] = rotl32(t, keccakfROTC[i])
		t = bc[0]
	}

	//  Chi
	for j := 0; j < 25; j += 5 {
		bc[0] = st[j+0]
		bc[1] = st[j+1]
		bc[2] = st[j+2]
		bc[3] = st[j+3]
		bc[4] = st[j+4]
		st[j+0] ^= ^bc[1] & bc[2]
		st[j+1] ^= ^bc[2] & bc[3]
		st[j+2] ^= ^bc[3] & bc[4]
		st[j+3] ^= ^bc[4] & bc[0]
		st[j+4] ^= ^bc[0] & bc[1]
	}

	//  Iota
	st[0] ^= keccakfRNDC[r]
}

// KAWPOW-specific Keccak functions with RAVENCOINKAWAOW padding
func keccakF800Short(headerHash []byte, nonce uint64, result []uint32) uint64 {
	var st [25]uint32

	for i := 0; i < 8; i++ {
		st[i] = (uint32(headerHash[4*i])) +
			(uint32(headerHash[4*i+1]) << 8) +
			(uint32(headerHash[4*i+2]) << 16) +
			(uint32(headerHash[4*i+3]) << 24)
	}

	st[8] = lower32(nonce)
	st[9] = higher32(nonce)

	// KAWPOW: Add RAVENCOINKAWAOW padding
	for i := 0; i < 15; i++ {
		if i < 8 {
			st[10+i] = result[i]
		} else {
			st[10+i] = ravencoinKawpow[i-8]
		}
	}

	for r := 0; r < 21; r++ {
		keccakF800Round(&st, r)
	}
	keccakF800Round(&st, 21)
	ret := make([]byte, 8)
	binary.BigEndian.PutUint32(ret[4:], st[0])
	binary.BigEndian.PutUint32(ret, st[1])
	return binary.LittleEndian.Uint64(ret)
}

func keccakF800Long(headerHash []byte, nonce uint64, result []uint32) []byte {
	var st [25]uint32

	for i := 0; i < 8; i++ {
		st[i] = (uint32(headerHash[4*i])) +
			(uint32(headerHash[4*i+1]) << 8) +
			(uint32(headerHash[4*i+2]) << 16) +
			(uint32(headerHash[4*i+3]) << 24)
	}

	st[8] = lower32(nonce)
	st[9] = higher32(nonce)

	// KAWPOW: Add RAVENCOINKAWAOW padding
	for i := 0; i < 8; i++ {
		st[10+i] = result[i]
	}
	for i := 0; i < 7; i++ {
		st[18+i] = ravencoinKawpow[i]
	}

	for r := 0; r <= 21; r++ {
		keccakF800Round(&st, r)
	}
	ret := make([]byte, 32)
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(ret[i*4:], st[i])
	}
	return ret
}

func fnv1a(h *uint32, d uint32) uint32 {
	*h = (*h ^ d) * fnvPrime
	return *h
}

func fnv1aInline(hash, data uint32) uint32 {
	return (hash ^ data) * fnvPrime
}

type mixRNGState struct {
	rng        kiss99State
	dstSeq     [kawpowRegs]uint32
	srcSeq     [kawpowRegs]uint32
	dstCounter uint32
	srcCounter uint32
}

func newMixRNGState(seedLo, seedHi uint32) mixRNGState {
	z := fnv1aInline(0x811c9dc5, seedLo)
	w := fnv1aInline(z, seedHi)
	jsr := fnv1aInline(w, seedLo)
	jcong := fnv1aInline(jsr, seedHi)
	state := mixRNGState{
		rng: kiss99State{
			z:     z,
			w:     w,
			jsr:   jsr,
			jcong: jcong,
		},
	}
	for i := uint32(0); i < kawpowRegs; i++ {
		state.dstSeq[i] = i
		state.srcSeq[i] = i
	}
	for i := uint32(kawpowRegs); i > 1; i-- {
		j := state.rand() % i
		state.dstSeq[i-1], state.dstSeq[j] = state.dstSeq[j], state.dstSeq[i-1]
		j = state.rand() % i
		state.srcSeq[i-1], state.srcSeq[j] = state.srcSeq[j], state.srcSeq[i-1]
	}
	return state
}

func (s *mixRNGState) nextDst() uint32 {
	val := s.dstSeq[s.dstCounter%kawpowRegs]
	s.dstCounter++
	return val
}

func (s *mixRNGState) nextSrc() uint32 {
	val := s.srcSeq[s.srcCounter%kawpowRegs]
	s.srcCounter++
	return val
}

func (s *mixRNGState) rand() uint32 {
	return kiss99(&s.rng)
}

type kiss99State struct {
	z     uint32
	w     uint32
	jsr   uint32
	jcong uint32
}

func kiss99(st *kiss99State) uint32 {
	var MWC uint32
	st.z = 36969*(st.z&65535) + (st.z >> 16)
	st.w = 18000*(st.w&65535) + (st.w >> 16)
	MWC = ((st.z << 16) + st.w)
	st.jsr ^= (st.jsr << 17)
	st.jsr ^= (st.jsr >> 13)
	st.jsr ^= (st.jsr << 5)
	st.jcong = 69069*st.jcong + 1234567
	return ((MWC ^ st.jcong) + st.jsr)
}

func initKawpowMix(hashSeed [2]uint32) [kawpowLanes][kawpowRegs]uint32 {
	var mix [kawpowLanes][kawpowRegs]uint32
	z := fnv1aInline(fnvOffsetBasis, hashSeed[0])
	w := fnv1aInline(z, hashSeed[1])
	for lane := uint32(0); lane < kawpowLanes; lane++ {
		jsr := fnv1aInline(w, lane)
		jcong := fnv1aInline(jsr, lane)
		state := kiss99State{z: z, w: w, jsr: jsr, jcong: jcong}
		for i := 0; i < kawpowRegs; i++ {
			mix[lane][i] = kiss99(&state)
		}
	}
	return mix
}

// Merge new data from b into the value in a
func merge(a *uint32, b uint32, r uint32) {
	switch r % 4 {
	case 0:
		*a = (*a * 33) + b
	case 1:
		*a = (*a ^ b) * 33
	case 2:
		*a = rotl32(*a, ((r>>16)%31)+1) ^ b
	default:
		*a = rotr32(*a, ((r>>16)%31)+1) ^ b
	}
}

// Random math between two input values
func kawpowMath(a uint32, b uint32, r uint32) uint32 {
	switch r % 11 {
	case 0:
		return a + b
	case 1:
		return a * b
	case 2:
		return higher32(uint64(a) * uint64(b))
	case 3:
		if a < b {
			return a
		}
		return b
	case 4:
		return rotl32(a, b)
	case 5:
		return rotr32(a, b)
	case 6:
		return a & b
	case 7:
		return a | b
	case 8:
		return a ^ b
	case 9:
		return uint32(bits.LeadingZeros32(a) + bits.LeadingZeros32(b))
	case 10:
		return uint32(bits.OnesCount32(a) + bits.OnesCount32(b))

	default:
		return 0
	}
}

func kawpowLoop(period uint64, round uint32, mix *[kawpowLanes][kawpowRegs]uint32,
	lookup func(index uint32) []uint32,
	cDag []uint32, datasetItems uint32) {
	if datasetItems == 0 {
		return
	}

	itemIndex := mix[round%kawpowLanes][0] % datasetItems
	dagWords := lookup(itemIndex)
	if len(dagWords) == 0 {
		return
	}

	wordsPerLane := len(dagWords) / int(kawpowLanes)
	if wordsPerLane == 0 {
		return
	}

	state := newMixRNGState(uint32(period), uint32(period>>32))

	maxOps := kawpowCntCache
	if kawpowCntMath > maxOps {
		maxOps = kawpowCntMath
	}

	cacheLen := uint32(len(cDag))
	for op := 0; op < maxOps; op++ {
		if op < kawpowCntCache && cacheLen > 0 {
			src := state.nextSrc()
			dst := state.nextDst()
			sel := state.rand()
			for lane := uint32(0); lane < kawpowLanes; lane++ {
				offset := mix[lane][src] % cacheLen
				data32 := cDag[offset]
				merge(&mix[lane][dst], data32, sel)
			}
		}

		if op < kawpowCntMath {
			srcRnd := state.rand() % (kawpowRegs * (kawpowRegs - 1))
			src1 := srcRnd % kawpowRegs
			src2 := srcRnd / kawpowRegs
			if src2 >= src1 {
				src2++
			}
			sel1 := state.rand()
			dst := state.nextDst()
			sel2 := state.rand()
			for lane := uint32(0); lane < kawpowLanes; lane++ {
				data32 := kawpowMath(mix[lane][src1], mix[lane][src2], sel1)
				merge(&mix[lane][dst], data32, sel2)
			}
		}
	}

	dsts := make([]uint32, wordsPerLane)
	sels := make([]uint32, wordsPerLane)
	for i := 0; i < wordsPerLane; i++ {
		if i == 0 {
			dsts[i] = 0
		} else {
			dsts[i] = state.nextDst()
		}
		sels[i] = state.rand()
	}

	for lane := uint32(0); lane < kawpowLanes; lane++ {
		offset := int(((lane ^ round) % kawpowLanes) * uint32(wordsPerLane))
		for i := 0; i < wordsPerLane; i++ {
			word := dagWords[offset+i]
			merge(&mix[lane][dsts[i]], word, sels[i])
		}
	}
}

// Main KAWPOW algorithm (ProgPoW with KAWPOW parameters)
func kawpow(hash []byte, nonce uint64, size uint64, blockNumber uint64, cDag []uint32,
	lookup func(index uint32) []uint32) ([]byte, []byte) {
	var laneResults [kawpowLanes]uint32

	// KAWPOW: Use kawpowInitialize instead of keccakF800Short to get seed with RAVENCOINKAWAOW
	result := make([]uint32, 8)
	seed, hashSeed := kawpowInitialize(hash, nonce)
	mix := initKawpowMix(hashSeed)
	// KAWPOW: Use period length 3 instead of 10
	period := (blockNumber / kawpowPeriodLength)
	datasetItems := uint32(size / kawpowMixBytes)
	for l := uint32(0); l < kawpowCntDag; l++ {
		kawpowLoop(period, l, &mix, lookup, cDag, datasetItems)
	}

	// Reduce mix data to a single per-lane result
	for lane := uint32(0); lane < kawpowLanes; lane++ {
		laneResults[lane] = 0x811c9dc5
		for i := uint32(0); i < kawpowRegs; i++ {
			fnv1a(&laneResults[lane], mix[lane][i])
		}
	}
	for i := uint32(0); i < 8; i++ {
		result[i] = 0x811c9dc5
	}
	for lane := uint32(0); lane < kawpowLanes; lane++ {
		fnv1a(&result[lane%8], laneResults[lane])
	}

	// Create mix hash from result
	mixHash := make([]byte, 8*4)
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(mixHash[i*4:], result[i])
	}

	// KAWPOW: Use kawpowFinalize instead of keccakF800Long to get final digest with RAVENCOINKAWAOW
	finalHash := kawpowFinalize(seed, mixHash)

	return mixHash[:], finalHash[:]
}

// kawpowLight computes the proof-of-work value for KAWPOW using on-the-fly dataset generation
func kawpowLight(size uint64, cache []uint32, hash []byte, nonce uint64,
	blockNumber uint64, cDag []uint32) ([]byte, []byte) {
	keccak512 := makeHasher(sha3.NewLegacyKeccak512())
	lookup := func(index uint32) []uint32 {
		return generateDatasetItem2048(cache, index, keccak512)
	}
	return kawpow(hash, nonce, size, blockNumber, cDag, lookup)
}

// kawpowFull computes the proof-of-work value for KAWPOW using the full dataset
func kawpowFull(dataset []uint32, hash []byte, nonce uint64, blockNumber uint64) ([]byte, []byte) {
	wordsPerItem := hashWords * kawpowDagLoads
	lookup := func(index uint32) []uint32 {
		start := int(index) * wordsPerItem
		end := start + wordsPerItem
		if start < 0 || end > len(dataset) {
			return nil
		}
		out := make([]uint32, wordsPerItem)
		copy(out, dataset[start:end])
		return out
	}
	cDag := make([]uint32, kawpowCacheWords)
	copy(cDag, dataset[:len(cDag)])
	return kawpow(hash, nonce, uint64(len(dataset))*4, blockNumber, cDag, lookup)
}
