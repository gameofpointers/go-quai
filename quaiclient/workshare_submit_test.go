package quaiclient

import (
	"context"
	"fmt"
	"math/big"
	"testing"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/log"
	"google.golang.org/protobuf/proto"
)

// TestWorkShareMineAndSubmitFlow demonstrates the full cache-free mining flow:
//
//  1. Connect to a live node via quaiclient
//  2. Call GetPendingHeader(SHA_BCH, coinbase) to get a WorkObject with AuxPow
//  3. Extract the WorkObjectHeader and mining parameters
//  4. "Mine" — rebuild the aux header with a nonce, check powHash < target
//  5. Submit the mined WorkObjectHeader via ReceiveWorkShare
//
// Requires a running go-quai node at localhost:9200.
func TestWorkShareMineAndSubmitFlow(t *testing.T) {
	ctx := context.Background()
	logger := log.Global

	// ──────────────────────────────────────────────────────────────────
	// STEP 1: Connect to the node
	// ──────────────────────────────────────────────────────────────────

	client, err := Dial("ws://localhost:9200", logger)
	if err != nil {
		t.Fatalf("Failed to connect to node: %v", err)
	}
	defer client.Close()
	t.Log("Connected to node at localhost:9200")

	// ──────────────────────────────────────────────────────────────────
	// STEP 2: Get pending header for SHA mining
	// ──────────────────────────────────────────────────────────────────

	powId := types.SHA_BCH
	location := common.Location{0, 0}
	coinbase := common.HexToAddress("0x001234567890abcdef1234567890abcdef12345678", location)

	pending, err := client.GetPendingHeader(ctx, &powId, &coinbase)
	if err != nil {
		t.Fatalf("GetPendingHeader failed: %v", err)
	}
	if pending == nil || pending.WorkObjectHeader() == nil {
		t.Fatal("GetPendingHeader returned nil")
	}

	header := pending.WorkObjectHeader()
	auxPow := header.AuxPow()
	if auxPow == nil || auxPow.Header() == nil {
		t.Fatal("Pending header missing AuxPow")
	}

	t.Logf("PowID:          %d (%s)", auxPow.PowID(), auxPow.PowID().String())
	t.Logf("SealHash:       %s", header.SealHash().Hex())
	t.Logf("Block number:   %d", header.NumberU64())
	t.Logf("AuxPow bits:    0x%x", auxPow.Header().Bits())
	t.Logf("AuxPow height:  %d", auxPow.Header().Height())
	t.Logf("Coinbase tx:    %d bytes", len(auxPow.Transaction()))
	t.Logf("Merkle branch:  %d entries", len(auxPow.MerkleBranch()))

	sealHash := header.SealHash()

	// ──────────────────────────────────────────────────────────────────
	// STEP 3: "Mine" — miner rebuilds the aux header with a nonce
	//
	// In real mining, the miner would:
	//   a) Optionally insert extranonce1/extranonce2 into the coinbase tx
	//   b) Recalculate the merkle root
	//   c) Build a new aux header with the updated merkle root + mined nonce
	//   d) Check if powHash < target
	//
	// For this test, we use the coinbase tx as-is and just set a nonce.
	// ──────────────────────────────────────────────────────────────────

	minerCoinbaseTx := auxPow.Transaction()

	// Recalculate merkle root (would change if extranonce was modified)
	minerMerkleRoot := types.CalculateMerkleRoot(auxPow.PowID(), minerCoinbaseTx, auxPow.MerkleBranch())

	// Verify merkle root matches the template
	if minerMerkleRoot != auxPow.Header().MerkleRoot() {
		t.Fatalf("Merkle root mismatch: got %x, want %x",
			minerMerkleRoot, auxPow.Header().MerkleRoot())
	}
	t.Logf("Merkle root verified: %x", minerMerkleRoot)

	// Miner finds a nonce (in practice, iterates billions of nonces)
	minedNonce := uint32(42)

	// Build the mined header with the nonce
	minedAuxHeader := types.NewBlockHeader(
		auxPow.PowID(),
		auxPow.Header().Version(),
		auxPow.Header().PrevBlock(),
		minerMerkleRoot,
		auxPow.Header().Timestamp(),
		auxPow.Header().Bits(),
		minedNonce,
		0,
	)

	// Compute the PoW hash
	powHash := minedAuxHeader.PowHash()
	powHashBigInt := new(big.Int).SetBytes(powHash.Bytes())

	// Check against workshare target
	var workShareTarget *big.Int
	switch auxPow.PowID() {
	case types.Scrypt:
		workShareTarget = new(big.Int).Div(common.Big2e256, header.ScryptDiffAndCount().Difficulty())
	default:
		workShareTarget = new(big.Int).Div(common.Big2e256, header.ShaDiffAndCount().Difficulty())
	}
	meetsTarget := powHashBigInt.Cmp(workShareTarget) < 0

	t.Logf("Mined PowHash:  %s", powHash.Hex())
	t.Logf("Target:         %s", workShareTarget.Text(16))
	t.Logf("Meets target:   %v", meetsTarget)

	// Update the AuxPow with the mined header
	header.AuxPow().SetHeader(minedAuxHeader)
	header.AuxPow().SetTransaction(minerCoinbaseTx)

	// ──────────────────────────────────────────────────────────────────
	// STEP 4: Verify the WorkObjectHeader round-trips through protobuf
	//   This is exactly what ReceiveWorkShare does internally.
	// ──────────────────────────────────────────────────────────────────

	protoWs, err := header.ProtoEncode()
	if err != nil {
		t.Fatalf("ProtoEncode failed: %v", err)
	}
	submitBytes, err := proto.Marshal(protoWs)
	if err != nil {
		t.Fatalf("proto.Marshal failed: %v", err)
	}
	t.Logf("Submit payload:  %d bytes", len(submitBytes))

	// Decode it back (simulating what the node does in ReceiveRawWorkShare)
	decodedProto := &types.ProtoWorkObjectHeader{}
	if err := proto.Unmarshal(submitBytes, decodedProto); err != nil {
		t.Fatalf("proto.Unmarshal failed: %v", err)
	}
	decoded := &types.WorkObjectHeader{}
	if err := decoded.ProtoDecode(decodedProto, location); err != nil {
		t.Fatalf("ProtoDecode failed: %v", err)
	}

	// Verify critical fields survived the round-trip
	if decoded.SealHash() != sealHash {
		t.Errorf("SealHash mismatch: got %s, want %s", decoded.SealHash().Hex(), sealHash.Hex())
	}
	if decoded.AuxPow() == nil {
		t.Fatal("Decoded header missing AuxPow")
	}
	if decoded.AuxPow().Header().PowHash() != powHash {
		t.Errorf("PowHash mismatch: got %s, want %s",
			decoded.AuxPow().Header().PowHash().Hex(), powHash.Hex())
	}

	// Verify coinbase seal hash
	scriptSig := types.ExtractScriptSigFromCoinbaseTx(decoded.AuxPow().Transaction())
	if len(scriptSig) == 0 {
		t.Fatal("Failed to extract scriptSig from coinbase")
	}
	coinbaseSealHash, err := types.ExtractSealHashFromCoinbase(scriptSig)
	if err != nil {
		t.Fatalf("Failed to extract seal hash from coinbase: %v", err)
	}
	if coinbaseSealHash != decoded.SealHash() {
		t.Errorf("Coinbase seal hash mismatch: got %s, want %s",
			coinbaseSealHash.Hex(), decoded.SealHash().Hex())
	}

	// ──────────────────────────────────────────────────────────────────
	// STEP 5: Submit the workshare via ReceiveWorkShare
	// ──────────────────────────────────────────────────────────────────

	result, err := client.ReceiveWorkShare(ctx, header)
	if err != nil {
		// Expected if powHash doesn't meet target (nonce 42 is unlikely to be valid)
		t.Logf("ReceiveWorkShare returned error (expected for test nonce): %v", err)
	} else {
		t.Logf("ReceiveWorkShare result: %v", result)
	}

	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("PowID:          %s\n", auxPow.PowID().String())
	fmt.Printf("SealHash:       %s\n", sealHash.Hex())
	fmt.Printf("PowHash:        %s\n", powHash.Hex())
	fmt.Printf("Meets target:   %v\n", meetsTarget)
	fmt.Printf("Protobuf size:  %d bytes\n", len(submitBytes))
	fmt.Printf("✓ Full flow: GetPendingHeader → mine → ReceiveWorkShare\n")
}
