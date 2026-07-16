package rawdb

import (
	"encoding/binary"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/ethdb"
)

func downloadQueueKey(number uint64, hash common.Hash) []byte {
	key := make([]byte, len(downloadQueuePrefix)+8+common.HashLength)
	copy(key, downloadQueuePrefix)
	binary.BigEndian.PutUint64(key[len(downloadQueuePrefix):], number)
	copy(key[len(downloadQueuePrefix)+8:], hash.Bytes())
	return key
}

// WriteDownloadedBlock marks a durably stored block as awaiting import.
func WriteDownloadedBlock(db ethdb.KeyValueWriter, number uint64, hash common.Hash) {
	if err := db.Put(downloadQueueKey(number, hash), []byte{1}); err != nil {
		db.Logger().WithField("err", err).Fatal("Failed to store downloaded block marker")
	}
}

// DeleteDownloadedBlock removes a block from the durable import queue.
func DeleteDownloadedBlock(db ethdb.KeyValueWriter, number uint64, hash common.Hash) {
	if err := db.Delete(downloadQueueKey(number, hash)); err != nil {
		db.Logger().WithField("err", err).Fatal("Failed to delete downloaded block marker")
	}
}

// ReadDownloadedBlocks returns the durable import queue in block-number order.
func ReadDownloadedBlocks(db ethdb.Iteratee) []types.HashAndNumber {
	return ReadDownloadedBlocksLimit(db, 0)
}

// ReadDownloadedBlocksLimit returns at most limit queue entries. A non-positive
// limit reads the complete queue.
func ReadDownloadedBlocksLimit(db ethdb.Iteratee, limit int) []types.HashAndNumber {
	it := db.NewIterator(downloadQueuePrefix, nil)
	defer it.Release()
	blocks := make([]types.HashAndNumber, 0)
	for it.Next() {
		key := it.Key()
		if len(key) != len(downloadQueuePrefix)+8+common.HashLength {
			continue
		}
		number := binary.BigEndian.Uint64(key[len(downloadQueuePrefix):])
		hash := common.BytesToHash(key[len(downloadQueuePrefix)+8:])
		blocks = append(blocks, types.HashAndNumber{Hash: hash, Number: number})
		if limit > 0 && len(blocks) >= limit {
			break
		}
	}
	return blocks
}

// WriteDownloadedHead stores the highest contiguous downloaded block.
func WriteDownloadedHead(db ethdb.KeyValueWriter, number uint64, hash common.Hash) {
	data := make([]byte, 8+common.HashLength)
	binary.BigEndian.PutUint64(data, number)
	copy(data[8:], hash.Bytes())
	if err := db.Put(downloadHeadKey, data); err != nil {
		db.Logger().WithField("err", err).Fatal("Failed to store downloaded head")
	}
}

// ReadDownloadedHead retrieves the highest contiguous downloaded block.
func ReadDownloadedHead(db ethdb.KeyValueReader) (uint64, common.Hash, bool) {
	data, _ := db.Get(downloadHeadKey)
	if len(data) != 8+common.HashLength {
		return 0, common.Hash{}, false
	}
	return binary.BigEndian.Uint64(data[:8]), common.BytesToHash(data[8:]), true
}
