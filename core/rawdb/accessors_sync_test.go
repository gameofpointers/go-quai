package rawdb

import (
	"testing"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/stretchr/testify/require"
)

func TestDownloadedQueueAndHead(t *testing.T) {
	db := NewMemoryDatabase(log.Global)
	hash1 := common.Hash{1}
	hash2 := common.Hash{2}

	WriteDownloadedBlock(db, 2, hash2)
	WriteDownloadedBlock(db, 1, hash1)
	queue := ReadDownloadedBlocks(db)
	require.Len(t, queue, 2)
	require.Equal(t, uint64(1), queue[0].Number)
	require.Equal(t, hash1, queue[0].Hash)
	require.Equal(t, uint64(2), queue[1].Number)

	DeleteDownloadedBlock(db, 1, hash1)
	queue = ReadDownloadedBlocks(db)
	require.Len(t, queue, 1)
	require.Equal(t, hash2, queue[0].Hash)

	_, _, ok := ReadDownloadedHead(db)
	require.False(t, ok)
	WriteDownloadedHead(db, 9, hash2)
	number, hash, ok := ReadDownloadedHead(db)
	require.True(t, ok)
	require.Equal(t, uint64(9), number)
	require.Equal(t, hash2, hash)
}
