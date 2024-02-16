package downloader

import (
	"sync"

	"bytes"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/crypto"
	"github.com/dominant-strategies/go-quai/ethdb"
	"github.com/pkg/errors"
)

type Downloader struct {
	p2pNode P2PNode
	f       *fetcher
}

func NewDownloader(p2pNode P2PNode, chainDb ethdb.Database, quitCh chan struct{}) *Downloader {
	f := &fetcher{
		p2pNode: p2pNode,
		db:      chainDb,
		mu:      sync.Mutex{},
		quitCh:  quitCh,
	}
	return &Downloader{
		p2pNode: p2pNode,
		f:       f,
	}
}

func (d *Downloader) StartSnapSync(loc common.Location, blockNumber uint64) error {
	header, err := d.f.fetchBlockHeader(loc, blockNumber)
	if err != nil {
		return errors.Errorf("failed to fetch block header %d: %v", blockNumber, err)
	}

	err = d.f.fetchStateTrie(header.Hash(), header.Root())
	if err != nil {
		return errors.Wrap(err, "failed to fetch state trie")
	}

	return nil
}

// VerifyNodeHash verifies a expected hash against the RLP encoding of the received trie node
func verifyNodeHash(rlpBytes []byte, expectedHash []byte) bool {
	hash := crypto.Keccak256(rlpBytes)
	return bytes.Equal(hash, expectedHash)
}
