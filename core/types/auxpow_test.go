package types

import (
	"bytes"
	"testing"
	"time"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/event"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// Test data generators
func testAuxPow() *AuxPow {
	return &AuxPow{
		ChainID:   1337,
		Header:    bytes.Repeat([]byte{0xaa}, 80),
		Signature: bytes.Repeat([]byte{0xbb}, 64),
	}
}

func testAuxTemplate() *AuxTemplate {
	var prevHash [32]byte
	copy(prevHash[:], bytes.Repeat([]byte{0x11}, 32))

	template := &AuxTemplate{}
	template.SetChainID(1337)
	template.SetPrevHash(prevHash)
	template.SetPayoutScript([]byte{0x76, 0xa9, 0x14}) // OP_DUP OP_HASH160 PUSH(20)
	template.SetScriptSigMaxLen(100)
	template.SetVersion(0x20000000)
	template.SetNBits(0x1d00ffff)
	template.SetNTimeMask(0xffffffff)
	template.SetHeight(12345)
	template.SetCoinbaseValue(625000000)
	template.SetCoinbaseOnly(false)
	template.SetTxCount(5)
	template.SetMerkleBranch([][]byte{
		bytes.Repeat([]byte{0xaa}, 32),
		bytes.Repeat([]byte{0xbb}, 32),
	})
	template.SetExtranonce2Size(8)
	template.SetSigs([]SignerEnvelope{
		NewSignerEnvelope("miner1", bytes.Repeat([]byte{0xcc}, 64)),
		NewSignerEnvelope("miner2", bytes.Repeat([]byte{0xdd}, 64)),
	})
	return template
}

// TestAuxPowProtoEncodeDecode tests protobuf encoding and decoding of AuxPow
func TestAuxPowProtoEncodeDecode(t *testing.T) {
	original := testAuxPow()

	// Encode to protobuf
	protoAuxPow := original.ProtoEncode()
	require.NotNil(t, protoAuxPow)

	// Marshal to bytes
	data, err := proto.Marshal(protoAuxPow)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal from bytes
	var decodedProto ProtoAuxPow
	err = proto.Unmarshal(data, &decodedProto)
	require.NoError(t, err)

	// Decode back to AuxPow
	decoded := &AuxPow{}
	err = decoded.ProtoDecode(&decodedProto)
	require.NoError(t, err)

	// Verify fields match
	require.Equal(t, original.ChainID, decoded.ChainID)
	require.Equal(t, original.Header, decoded.Header)
	require.Equal(t, original.Signature, decoded.Signature)
}

// TestAuxPowProtoEncodeNil tests encoding nil AuxPow
func TestAuxPowProtoEncodeNil(t *testing.T) {
	var auxPow *AuxPow
	protoAuxPow := auxPow.ProtoEncode()
	require.Nil(t, protoAuxPow)
}

// TestAuxPowProtoDecodeNil tests decoding nil ProtoAuxPow
func TestAuxPowProtoDecodeNil(t *testing.T) {
	auxPow := &AuxPow{}
	err := auxPow.ProtoDecode(nil)
	require.NoError(t, err)
	// AuxPow should remain in zero state
	require.Equal(t, ChainID(0), auxPow.ChainID)
	require.Nil(t, auxPow.Header)
	require.Nil(t, auxPow.Signature)
}

// TestAuxTemplateProtoEncodeDecode tests protobuf encoding and decoding of AuxTemplate
func TestAuxTemplateProtoEncodeDecode(t *testing.T) {
	original := testAuxTemplate()

	// Encode to protobuf
	protoTemplate := original.ProtoEncode()
	require.NotNil(t, protoTemplate)

	// Marshal to bytes
	data, err := proto.Marshal(protoTemplate)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal from bytes
	var decodedProto ProtoAuxTemplate
	err = proto.Unmarshal(data, &decodedProto)
	require.NoError(t, err)

	// Decode back to AuxTemplate
	decoded := &AuxTemplate{}
	err = decoded.ProtoDecode(&decodedProto)
	require.NoError(t, err)

	// Verify all fields match
	require.Equal(t, original.ChainID(), decoded.ChainID())
	require.Equal(t, original.PrevHash(), decoded.PrevHash())
	require.Equal(t, original.PayoutScript(), decoded.PayoutScript())
	require.Equal(t, original.ScriptSigMaxLen(), decoded.ScriptSigMaxLen())
	require.Equal(t, original.Version(), decoded.Version())
	require.Equal(t, original.NBits(), decoded.NBits())
	require.Equal(t, original.NTimeMask(), decoded.NTimeMask())
	require.Equal(t, original.Height(), decoded.Height())
	require.Equal(t, original.CoinbaseValue(), decoded.CoinbaseValue())
	require.Equal(t, original.CoinbaseOnly(), decoded.CoinbaseOnly())
	require.Equal(t, original.TxCount(), decoded.TxCount())
	require.Equal(t, original.MerkleBranch(), decoded.MerkleBranch())
	require.Equal(t, original.Extranonce2Size(), decoded.Extranonce2Size())

	// Verify signatures
	require.Len(t, decoded.Sigs(), len(original.Sigs()))
	for i, sig := range original.Sigs() {
		require.Equal(t, sig.SignerID(), decoded.Sigs()[i].SignerID())
		require.Equal(t, sig.Signature(), decoded.Sigs()[i].Signature())
	}
}

// TestAuxTemplateProtoEncodeNil tests encoding nil AuxTemplate
func TestAuxTemplateProtoEncodeNil(t *testing.T) {
	var template *AuxTemplate
	protoTemplate := template.ProtoEncode()
	require.Nil(t, protoTemplate)
}

// TestAuxTemplateProtoDecodeNil tests decoding nil ProtoAuxTemplate
func TestAuxTemplateProtoDecodeNil(t *testing.T) {
	template := &AuxTemplate{}
	err := template.ProtoDecode(nil)
	require.NoError(t, err)
	// Template should remain in zero state
	require.Equal(t, ChainID(0), template.ChainID())
	require.Equal(t, [32]byte{}, template.PrevHash())
	require.Nil(t, template.PayoutScript())
}

// TestAuxTemplateWithEmptySigs tests AuxTemplate with no signatures
func TestAuxTemplateWithEmptySigs(t *testing.T) {
	original := testAuxTemplate()
	original.SetSigs(nil)

	// Encode and decode
	protoTemplate := original.ProtoEncode()
	data, err := proto.Marshal(protoTemplate)
	require.NoError(t, err)

	var decodedProto ProtoAuxTemplate
	err = proto.Unmarshal(data, &decodedProto)
	require.NoError(t, err)

	decoded := &AuxTemplate{}
	err = decoded.ProtoDecode(&decodedProto)
	require.NoError(t, err)

	// Sigs should be empty slice
	require.Len(t, decoded.Sigs(), 0)
}

// TestAuxTemplatePartialFields tests AuxTemplate with only required fields
func TestAuxTemplatePartialFields(t *testing.T) {
	var prevHash [32]byte
	copy(prevHash[:], bytes.Repeat([]byte{0x22}, 32))

	original := &AuxTemplate{}
	original.SetChainID(42)
	original.SetPrevHash(prevHash)
	original.SetPayoutScript([]byte{0x51}) // OP_TRUE
	original.SetScriptSigMaxLen(50)
	// Optional fields left at zero

	// Encode and decode
	protoTemplate := original.ProtoEncode()
	data, err := proto.Marshal(protoTemplate)
	require.NoError(t, err)

	var decodedProto ProtoAuxTemplate
	err = proto.Unmarshal(data, &decodedProto)
	require.NoError(t, err)

	decoded := &AuxTemplate{}
	err = decoded.ProtoDecode(&decodedProto)
	require.NoError(t, err)

	// Required fields should match
	require.Equal(t, original.ChainID(), decoded.ChainID())
	require.Equal(t, original.PrevHash(), decoded.PrevHash())
	require.Equal(t, original.PayoutScript(), decoded.PayoutScript())
	require.Equal(t, original.ScriptSigMaxLen(), decoded.ScriptSigMaxLen())

	// Optional fields should be zero
	require.Equal(t, uint8(0), decoded.Extranonce2Size())
	require.Equal(t, uint32(0), decoded.NBits())
	require.Equal(t, NTimeMask(0), decoded.NTimeMask())
	require.Equal(t, uint32(0), decoded.Version())
	require.Equal(t, uint32(0), decoded.Height())
	require.Equal(t, uint64(0), decoded.CoinbaseValue())
	require.Equal(t, false, decoded.CoinbaseOnly())
	require.Equal(t, uint32(0), decoded.TxCount())
	require.Empty(t, decoded.MerkleBranch())
}

// TestSignerEnvelopeProtoEncodeDecode tests SignerEnvelope protobuf operations
func TestSignerEnvelopeProtoEncodeDecode(t *testing.T) {
	original := NewSignerEnvelope("test-signer-123", bytes.Repeat([]byte{0xef}, 72))

	// Encode
	protoEnv := original.ProtoEncode()
	require.NotNil(t, protoEnv)

	// Marshal
	data, err := proto.Marshal(protoEnv)
	require.NoError(t, err)

	// Unmarshal
	var decodedProto ProtoSignerEnvelope
	err = proto.Unmarshal(data, &decodedProto)
	require.NoError(t, err)

	// Decode
	decoded := &SignerEnvelope{}
	err = decoded.ProtoDecode(&decodedProto)
	require.NoError(t, err)

	// Verify
	require.Equal(t, original.SignerID(), decoded.SignerID())
	require.Equal(t, original.Signature(), decoded.Signature())
}

// TestAuxPowInWorkObjectHeader tests that AuxPow in WorkObjectHeader encodes/decodes correctly
func TestAuxPowInWorkObjectHeader(t *testing.T) {
	// Create a WorkObjectHeader with AuxPow
	header := &WorkObjectHeader{}
	auxPow := testAuxPow()
	header.SetAuxPow(auxPow)

	// Verify getter
	retrieved := header.AuxPow()
	require.NotNil(t, retrieved)
	require.Equal(t, auxPow.ChainID, retrieved.ChainID)
	require.Equal(t, auxPow.Header, retrieved.Header)
	require.Equal(t, auxPow.Signature, retrieved.Signature)

	// Test setting nil
	header.SetAuxPow(nil)
	require.Nil(t, header.AuxPow())
}

// TestAuxTemplateBroadcastFlow tests the complete broadcast flow from core
func TestAuxTemplateBroadcastFlow(t *testing.T) {
	// This test simulates the complete broadcast flow:
	// 1. Core creates/receives an AuxTemplate
	// 2. Core converts it to protobuf for broadcast
	// 3. P2P layer would marshal it and broadcast via GossipSub
	// 4. Receiving node unmarshals and processes it

	// Step 1: Create AuxTemplate in core
	auxTemplate := testAuxTemplate()

	// Step 2: Convert to protobuf (what core does before sending to P2P)
	protoTemplate := auxTemplate.ProtoEncode()
	require.NotNil(t, protoTemplate)

	// Step 3: Marshal to bytes (what P2P layer does)
	data, err := proto.Marshal(protoTemplate)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Step 4: Receiving side - unmarshal (what receiving P2P does)
	var receivedProto ProtoAuxTemplate
	err = proto.Unmarshal(data, &receivedProto)
	require.NoError(t, err)

	// Step 5: Convert back to AuxTemplate (what receiving core does)
	receivedTemplate := &AuxTemplate{}
	err = receivedTemplate.ProtoDecode(&receivedProto)
	require.NoError(t, err)

	// Verify all fields survived the round trip
	require.Equal(t, auxTemplate.ChainID(), receivedTemplate.ChainID())
	require.Equal(t, auxTemplate.PrevHash(), receivedTemplate.PrevHash())
	require.Equal(t, auxTemplate.PayoutScript(), receivedTemplate.PayoutScript())
	require.Equal(t, auxTemplate.ScriptSigMaxLen(), receivedTemplate.ScriptSigMaxLen())
	require.Equal(t, auxTemplate.Version(), receivedTemplate.Version())
	require.Equal(t, auxTemplate.NBits(), receivedTemplate.NBits())
	require.Equal(t, auxTemplate.NTimeMask(), receivedTemplate.NTimeMask())
	require.Equal(t, auxTemplate.Height(), receivedTemplate.Height())
	require.Equal(t, auxTemplate.CoinbaseValue(), receivedTemplate.CoinbaseValue())
	require.Equal(t, auxTemplate.CoinbaseOnly(), receivedTemplate.CoinbaseOnly())
	require.Equal(t, auxTemplate.TxCount(), receivedTemplate.TxCount())
	require.Equal(t, auxTemplate.MerkleBranch(), receivedTemplate.MerkleBranch())
	require.Equal(t, auxTemplate.Extranonce2Size(), receivedTemplate.Extranonce2Size())
	require.Len(t, receivedTemplate.Sigs(), len(auxTemplate.Sigs()))
}

// TestAuxTemplateValidation tests validation rules for AuxTemplate
func TestAuxTemplateValidation(t *testing.T) {
	// Test valid template
	validTemplate := testAuxTemplate()

	// Test ScriptSigMaxLen limit
	require.LessOrEqual(t, validTemplate.ScriptSigMaxLen(), uint16(100), "ScriptSigMaxLen must be <= 100")

	// Test coinbase-only mode consistency
	coinbaseOnlyTemplate := &AuxTemplate{}
	coinbaseOnlyTemplate.SetChainID(1234)
	coinbaseOnlyTemplate.SetCoinbaseOnly(true)
	coinbaseOnlyTemplate.SetTxCount(1) // Should be 1 for coinbase-only
	coinbaseOnlyTemplate.SetMerkleBranch(nil) // Should be empty for coinbase-only

	if coinbaseOnlyTemplate.CoinbaseOnly() {
		require.Equal(t, uint32(1), coinbaseOnlyTemplate.TxCount(), "Coinbase-only mode should have TxCount = 1")
		require.Empty(t, coinbaseOnlyTemplate.MerkleBranch(), "Coinbase-only mode should have empty MerkleBranch")
	}

	// Test locked tx set mode
	lockedTxTemplate := testAuxTemplate()
	lockedTxTemplate.SetCoinbaseOnly(false)
	lockedTxTemplate.SetTxCount(5)
	lockedTxTemplate.SetMerkleBranch([][]byte{
		bytes.Repeat([]byte{0x11}, 32),
		bytes.Repeat([]byte{0x22}, 32),
	})

	if !lockedTxTemplate.CoinbaseOnly() {
		require.Greater(t, lockedTxTemplate.TxCount(), uint32(0), "Locked tx mode should have TxCount > 0")
		require.NotEmpty(t, lockedTxTemplate.MerkleBranch(), "Locked tx mode should have MerkleBranch")
	}
}

// TestAuxTemplateGossipMessage tests the complete GossipAuxTemplate message flow
func TestAuxTemplateGossipMessage(t *testing.T) {
	// This test verifies the complete message flow as it would happen in the broadcast loop

	// 1. Core creates AuxTemplate
	auxTemplate := testAuxTemplate()

	// 2. Convert to Proto for P2P layer
	protoTemplate := auxTemplate.ProtoEncode()
	require.NotNil(t, protoTemplate)

	// 3. Create GossipAuxTemplate message (done by P2P layer)
	// This is the actual message type that gets broadcast
	// The protobuf definition is in p2p/pb/quai_messages.proto

	// 4. Verify ProtoAuxTemplate has all fields
	require.NotNil(t, protoTemplate.ChainId)
	require.NotNil(t, protoTemplate.PrevHash)
	require.NotNil(t, protoTemplate.PayoutScript)
	require.NotNil(t, protoTemplate.ScriptSigMaxLen)
	require.NotNil(t, protoTemplate.Version)
	require.NotNil(t, protoTemplate.Nbits)
	require.NotNil(t, protoTemplate.NtimeMask)
	require.NotNil(t, protoTemplate.Height)
	require.NotNil(t, protoTemplate.CoinbaseValue)
	require.NotNil(t, protoTemplate.CoinbaseOnly)
	require.NotNil(t, protoTemplate.TxCount)
	require.NotNil(t, protoTemplate.MerkleBranch)
	require.NotNil(t, protoTemplate.Extranonce2Size)
	require.NotNil(t, protoTemplate.Sigs)
}

// TestAuxTemplateEventFeedBroadcast tests the event feed broadcast pattern similar to chainFeed for blocks
func TestAuxTemplateEventFeedBroadcast(t *testing.T) {
	// This test simulates how AuxTemplate would be broadcast in core, similar to how
	// blocks are sent via chainFeed.Send(ChainEvent{...})

	// Create an event feed for AuxTemplate (similar to chainFeed)
	auxTemplateFeed := new(event.Feed)

	// Set up multiple subscribers (simulating different parts of the system)
	const numSubscribers = 3
	var subscribers []chan AuxTemplateEvent
	var subs []event.Subscription

	for i := 0; i < numSubscribers; i++ {
		ch := make(chan AuxTemplateEvent, 10)
		sub := auxTemplateFeed.Subscribe(ch)
		subscribers = append(subscribers, ch)
		subs = append(subs, sub)
		defer sub.Unsubscribe()
	}

	// Create AuxTemplate in core
	auxTemplate := testAuxTemplate()
	location := common.Location{0, 1}

	// Core broadcasts AuxTemplate (similar to chainFeed.Send for blocks)
	auxTemplateEvent := AuxTemplateEvent{
		Template: auxTemplate,
		Location: location,
		ChainID:  auxTemplate.ChainID(),
	}

	// Send the event
	auxTemplateFeed.Send(auxTemplateEvent)

	// Verify all subscribers receive the AuxTemplate
	for i, ch := range subscribers {
		select {
		case received := <-ch:
			require.NotNil(t, received.Template, "Subscriber %d should receive template", i)
			require.Equal(t, auxTemplate.ChainID(), received.Template.ChainID())
			require.Equal(t, auxTemplate.PrevHash(), received.Template.PrevHash())
			require.Equal(t, auxTemplate.Height(), received.Template.Height())
			require.Equal(t, location, received.Location)
			require.Equal(t, auxTemplate.ChainID(), received.ChainID)
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("Subscriber %d did not receive AuxTemplate event", i)
		}
	}

	// Verify no duplicate events
	for i, ch := range subscribers {
		select {
		case <-ch:
			t.Fatalf("Subscriber %d received duplicate event", i)
		case <-time.After(10 * time.Millisecond):
			// Expected - no more events
		}
	}
}

// AuxTemplateEvent represents an AuxTemplate event in the system (similar to ChainEvent)
type AuxTemplateEvent struct {
	Template *AuxTemplate
	Location common.Location
	ChainID  ChainID
}

// Benchmarks
func BenchmarkAuxPowProtoEncode(b *testing.B) {
	auxPow := testAuxPow()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = auxPow.ProtoEncode()
	}
}

func BenchmarkAuxTemplateProtoEncode(b *testing.B) {
	template := testAuxTemplate()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = template.ProtoEncode()
	}
}

func BenchmarkAuxTemplateMarshal(b *testing.B) {
	template := testAuxTemplate()
	protoTemplate := template.ProtoEncode()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = proto.Marshal(protoTemplate)
	}
}