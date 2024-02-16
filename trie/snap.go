package trie

import (
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/crypto"
	"github.com/dominant-strategies/go-quai/rlp"
)

// Used to send a trie node request to a peer
type TrieNodeRequest struct {
	BlockHash common.Hash // Hash of the block to which the requested trie node belongs
	NodeHash  common.Hash // Hash of the trie node being requested
}

// Used to get a trie node response from a peer
type TrieNodeResponse struct {
	NodeData []byte
	NodeHash common.Hash
}

// GetTrieNode returns the trie node from a TrieNodeResponse
func (t *TrieNodeResponse) GetTrieNode() *TrieNode {
	node, err := decodeNode(t.NodeHash[:], t.NodeData)
	if err != nil {
		panic(err)
	}
	return &TrieNode{n: node}
}

// TrieNode is a public wrapper around a trie node that exposes
// methods for handling trie nodes.
type TrieNode struct {
	n node
}

// CalculateNodeHash calculates the Keccak-256 hash of a trie node's RLP encoding.
func calculateNodeHash(n node) ([]byte, error) {
	rlpBytes, err := rlp.EncodeToBytes(n)
	if err != nil {
		return nil, err
	}
	return crypto.Keccak256(rlpBytes), nil
}

// ChildHashes returns the hashes of the children of a fullNode trie node
func (t *TrieNode) ChildHashes() []common.Hash {
	switch n := t.n.(type) {
	case *fullNode:
		hashes := make([]common.Hash, 0, 17)
		for _, child := range n.Children {
			if child != nil {
				hashBytes, err := calculateNodeHash(child)
				if err != nil {
					panic(err)
				}
				hashes = append(hashes, common.BytesToHash(hashBytes))
			}
		}
		return hashes
	default:
		return nil
	}
}

// IsFullNode returns true if the trie node is a fullNode
func (t *TrieNode) IsFullNode() bool {
	_, ok := t.n.(*fullNode)
	return ok
}
