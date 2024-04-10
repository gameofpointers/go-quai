// Copyright 2020 The go-ethereum Authors
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

package snap

import (
	"bytes"
	"fmt"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/state/snapshot"
)

// Unpack retrieves the accounts from the range packet and converts from slim
// wire representation to consensus format. The returned data is RLP encoded
// since it's expected to be serialized to disk without further interpretation.
//
// Note, this method does a round of RLP decoding and reencoding, so only use it
// once and cache the results if need be. Ideally discard the packet afterwards
// to not double the memory use.
func (p *AccountRangeResponse) Unpack() ([]common.Hash, [][]byte, error) {
	var (
		hashes   = make([]common.Hash, len(p.Accounts))
		accounts = make([][]byte, len(p.Accounts))
	)
	for i, acc := range p.Accounts {
		val, err := snapshot.FullAccountRLP(acc.Body)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid account %x: %v", acc.Body, err)
		}
		// Read the hash from the wire format
		var hash common.Hash
		hash.ProtoDecode(acc.Hash)

		hashes[i], accounts[i] = hash, val
	}
	return hashes, accounts, nil
}

// RequestAccountRange fetches a batch of accounts rooted in a specific account
// trie, starting with the origin.
func (s *Syncer) RequestAccountRange(id uint64, root common.Hash, origin, limit common.Hash, bytesMax uint64) error {
	s.logger.Trace("Fetching range of accounts", "reqid", id, "root", root, "origin", origin, "limit", limit, "bytes", common.StorageSize(bytesMax))

	resultCh := s.p2p.Request(s.nodeLocation, &AccountRangeRequest{
		Id:     id,
		Root:   root.ProtoEncode(),
		Origin: origin.ProtoEncode(),
		Limit:  limit.ProtoEncode(),
		Bytes:  &bytesMax,
	}, &AccountRangeResponse{})

	response := <-resultCh
	if response != nil {
		accountRangeResponse := response.(*AccountRangeResponse)
		if accountRangeResponse.Accounts == nil || accountRangeResponse.Proof == nil {
			// TODO: decide what to do if the peer sent a empty response
			return nil
		}
		hashes, accounts, err := accountRangeResponse.Unpack()
		if err != nil {
			return err
		}
		// Ensure the range is monotonically increasing
		for i := 1; i < len(accountRangeResponse.Accounts); i++ {
			if bytes.Compare(hashes[i-1][:], hashes[i][:]) >= 0 {
				return fmt.Errorf("accounts not monotonically increasing: #%d [%x] vs #%d [%x]", i-1, hashes[i-1][:], i, hashes[i][:])
			}
		}
		s.OnAccounts(accountRangeResponse.Id, hashes, accounts, accountRangeResponse.Proof)
	} else {
		// TODO: derank the peer because it cannot serve the data
		return nil
	}
	return nil
}

// Unpack retrieves the storage slots from the range packet and returns them in
// a split flat format that's more consistent with the internal data structures.
func (p *StorageRangesResponse) Unpack() ([][]common.Hash, [][][]byte) {
	var (
		hashset = make([][]common.Hash, len(p.Slots))
		slotset = make([][][]byte, len(p.Slots))
	)
	for i, slots := range p.Slots {
		hashset[i] = make([]common.Hash, len(slots.Data))
		slotset[i] = make([][]byte, len(slots.Data))
		for j, slot := range slots.Data {
			// Read the hash from the wire format
			var hash common.Hash
			hash.ProtoDecode(slot.Hash)
			hashset[i][j] = hash
			slotset[i][j] = slot.Body
		}
	}
	return hashset, slotset
}

// RequestStorageRange fetches a batch of storage slots belonging to one or more
// accounts. If slots from only one accout is requested, an origin marker may also
// be used to retrieve from there.
func (s *Syncer) RequestStorageRanges(id uint64, root common.Hash, accounts []common.Hash, origin, limit []byte, bytesMax uint64) error {
	if len(accounts) == 1 && origin != nil {
		s.logger.Trace("Fetching range of large storage slots", "reqid", id, "root", root, "account", accounts[0], "origin", common.BytesToHash(origin), "limit", common.BytesToHash(limit), "bytes", common.StorageSize(bytesMax))
	} else {
		s.logger.Trace("Fetching ranges of small storage slots", "reqid", id, "root", root, "accounts", len(accounts), "first", accounts[0], "bytes", common.StorageSize(bytesMax))
	}
	resultCh := s.p2p.Request(s.nodeLocation, &StorageRangesRequest{
		Id:       id,
		Root:     root.ProtoEncode(),
		Accounts: common.Hashes(accounts).ProtoEncode(),
		Origin:   origin,
		Limit:    limit,
		Bytes:    &bytesMax,
	}, &StorageRangesResponse{})

	response := <-resultCh
	if response != nil {
		storageRangesResponse := response.(*StorageRangesResponse)
		if storageRangesResponse.Slots == nil || storageRangesResponse.Proof == nil {
			// TODO: decide what to do if the peer sent a empty response
			return nil
		}
		hashSet, slotSet := storageRangesResponse.Unpack()
		// Ensure the range is monotonically increasing
		for i := 0; i < len(storageRangesResponse.Slots); i++ {
			for j := 1; j < len(hashSet); j++ {
				if bytes.Compare(hashSet[i][j-1][:], hashSet[i][j][:]) >= 0 {
					return fmt.Errorf("storage slots not monotonically increasing for account #%d: #%d [%x] vs #%d [%x]", i, j-1, hashSet[i][j-1][:], j, hashSet[i][j][:])
				}
			}
		}
		s.OnStorage(storageRangesResponse.Id, hashSet, slotSet, storageRangesResponse.Proof)
	} else {
		// TODO: derank the peer because it cannot serve the data
		return nil
	}
	return nil
}

// RequestByteCodes fetches a batch of bytecodes by hash.
func (s *Syncer) RequestByteCodes(id uint64, hashes []common.Hash, bytes uint64) error {
	s.logger.Trace("Fetching set of byte codes", "reqid", id, "hashes", len(hashes), "bytes", common.StorageSize(bytes))

	resultCh := s.p2p.Request(s.nodeLocation, &ByteCodesRequest{
		Id:     id,
		Hashes: common.Hashes(hashes).ProtoEncode(),
		Bytes:  &bytes,
	}, &ByteCodesResponse{})

	response := <-resultCh
	if response != nil {
		byteCodesResponse := response.(*ByteCodesResponse)
		if byteCodesResponse.Codes == nil {
			return nil
		}
		s.onByteCodes(byteCodesResponse.Id, byteCodesResponse.Codes)
	} else {
		return nil
	}
	return nil
}

// RequestTrieNodes fetches a batch of account or storage trie nodes rooted in
// a specificstate trie.
func (s *Syncer) RequestTrieNodes(id uint64, root common.Hash, paths []TrieNodePathSet, bytes uint64) error {
	s.logger.Trace("Fetching set of trie nodes", "reqid", id, "root", root, "pathsets", len(paths), "bytes", common.StorageSize(bytes))

	protoTrieNodePathSets := make([]*ProtoTrieNodePathSet, len(paths))
	for i, path := range paths {
		protoTrieNodePathSets[i] = path.ProtoEncode()
	}

	resultCh := s.p2p.Request(s.nodeLocation, &TrieNodesRequest{
		Id:    id,
		Root:  root.ProtoEncode(),
		Paths: protoTrieNodePathSets,
		Bytes: &bytes,
	}, &TrieNodesResponse{})

	response := <-resultCh
	if response != nil {
		trieNodesResponse := response.(*TrieNodesResponse)
		if trieNodesResponse.Nodes == nil {
			return nil
		}
		s.OnTrieNodes(trieNodesResponse.Id, trieNodesResponse.Nodes)
	} else {
		return nil
	}
	return nil
}
