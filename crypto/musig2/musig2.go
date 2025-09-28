package musig2

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/dominant-strategies/go-quai/params"
)

// Manager handles MuSig2 operations
type Manager struct {
	privateKey       *btcec.PrivateKey
	publicKeys       []*btcec.PublicKey
	participantIndex int
}

// NewManager creates a new MuSig2 manager with the configured keys
func NewManager() (*Manager, error) {
	// Load private key from environment
	privKeyHex := os.Getenv("MUSIG2_PRIVKEY")
	if privKeyHex == "" {
		return nil, errors.New("MUSIG2_PRIVKEY environment variable not set")
	}

	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}

	privateKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)

	// Load public keys from protocol params
	if len(params.MuSig2PublicKeys) != 3 {
		return nil, fmt.Errorf("expected 3 MuSig2 public keys, got %d", len(params.MuSig2PublicKeys))
	}

	publicKeys := make([]*btcec.PublicKey, len(params.MuSig2PublicKeys))
	participantIndex := -1

	for i, pubKeyHex := range params.MuSig2PublicKeys {
		pubKeyBytes, err := hex.DecodeString(pubKeyHex)
		if err != nil {
			return nil, fmt.Errorf("invalid public key hex at index %d: %w", i, err)
		}

		pubKey, err := btcec.ParsePubKey(pubKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key at index %d: %w", i, err)
		}

		publicKeys[i] = pubKey

		// Check if this matches our private key
		if pubKey.IsEqual(privateKey.PubKey()) {
			participantIndex = i
		}
	}

	if participantIndex == -1 {
		return nil, errors.New("private key does not match any of the configured public keys")
	}

	return &Manager{
		privateKey:       privateKey,
		publicKeys:       publicKeys,
		participantIndex: participantIndex,
	}, nil
}

// SigningSession represents an active signing session
type SigningSession struct {
	manager    *Manager
	context    *musig2.Context
	session    *musig2.Session
	msgHash    [32]byte
	otherIndex int
}

// sortKeys sorts public keys lexicographically by their compressed serialization
func sortKeys(keys []*btcec.PublicKey) []*btcec.PublicKey {
	sorted := make([]*btcec.PublicKey, len(keys))
	copy(sorted, keys)

	sort.Slice(sorted, func(i, j int) bool {
		return strings.Compare(
			hex.EncodeToString(sorted[i].SerializeCompressed()),
			hex.EncodeToString(sorted[j].SerializeCompressed()),
		) < 0
	})

	return sorted
}

// NewSigningSession creates a new signing session for a message with another participant
func (m *Manager) NewSigningSession(message []byte, otherParticipantIndex int) (*SigningSession, error) {
	if otherParticipantIndex < 0 || otherParticipantIndex >= len(m.publicKeys) {
		return nil, fmt.Errorf("invalid other participant index: %d", otherParticipantIndex)
	}

	if otherParticipantIndex == m.participantIndex {
		return nil, errors.New("cannot sign with ourselves")
	}

	// Get the two signing keys
	signers := []*btcec.PublicKey{
		m.publicKeys[m.participantIndex],
		m.publicKeys[otherParticipantIndex],
	}

	// Don't sort keys - maintain deterministic ordering (participant index order)
	// This must match what go-quai API does

	// Create MuSig2 context without sorting
	musigCtx, err := musig2.NewContext(
		m.privateKey,
		false, // don't sort keys
		musig2.WithKnownSigners(signers),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create MuSig2 context: %w", err)
	}

	// Create session
	session, err := musigCtx.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	msgHash := sha256.Sum256(message)
	fmt.Printf("MuSig2 NewSigningSession - participant: %d, otherParticipant: %d, messageLen: %d, msgHash: %x\n",
		m.participantIndex, otherParticipantIndex, len(message), msgHash)

	return &SigningSession{
		manager:    m,
		context:    musigCtx,
		session:    session,
		msgHash:    msgHash,
		otherIndex: otherParticipantIndex,
	}, nil
}

// GetPublicNonce returns the public nonce for this session
func (s *SigningSession) GetPublicNonce() []byte {
	nonce := s.session.PublicNonce()
	return nonce[:]
}

// CreatePartialSignature creates a partial signature after registering the other party's nonce
func (s *SigningSession) CreatePartialSignature(otherNonce []byte) ([]byte, error) {
	if len(otherNonce) != 66 {
		return nil, fmt.Errorf("invalid nonce size: expected 66, got %d", len(otherNonce))
	}

	// Parse other nonce
	var otherPubNonce [66]byte
	copy(otherPubNonce[:], otherNonce)

	// Register the other party's nonce
	haveAllNonces, err := s.session.RegisterPubNonce(otherPubNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to register other nonce: %w", err)
	}

	if !haveAllNonces {
		return nil, errors.New("don't have all nonces yet")
	}

	// Sign the message
	partialSig, err := s.session.Sign(s.msgHash)
	if err != nil {
		return nil, fmt.Errorf("failed to create partial signature: %w", err)
	}

	// Return the S value bytes (32 bytes)
	sBytes := partialSig.S.Bytes()
	return sBytes[:], nil
}

// CombinePartialSignatures combines partial signatures into a final Schnorr signature
func CombinePartialSignatures(session *SigningSession, ourPartialSig, theirPartialSig []byte) ([]byte, error) {
	fmt.Printf("CombinePartialSignatures - ourPartialSig: %x, theirPartialSig: %x\n", ourPartialSig, theirPartialSig)
	fmt.Printf("CombinePartialSignatures - session participant: %d, other participant: %d\n",
		session.manager.participantIndex, session.otherIndex)

	// Create PartialSignature objects from bytes
	ourSig := &musig2.PartialSignature{
		S: new(btcec.ModNScalar),
	}
	ourSig.S.SetByteSlice(ourPartialSig)

	theirSig := &musig2.PartialSignature{
		S: new(btcec.ModNScalar),
	}
	theirSig.S.SetByteSlice(theirPartialSig)

	// Combine signatures
	haveAllSigs, err := session.session.CombineSig(theirSig)
	if err != nil {
		return nil, fmt.Errorf("failed to combine signatures: %w", err)
	}

	if !haveAllSigs {
		// Try adding our own signature
		_, err = session.session.CombineSig(ourSig)
		if err != nil {
			return nil, fmt.Errorf("failed to add our signature: %w", err)
		}
	}

	// Get final signature
	finalSig := session.session.FinalSig()
	// Schnorr signatures are 64 bytes (R || S)
	return finalSig.Serialize(), nil
}

// VerifyCompositeSignature verifies a composite Schnorr signature
func VerifyCompositeSignature(message []byte, signature []byte, signerIndices []int) error {
	if len(signature) != 64 {
		return errors.New("invalid signature length")
	}

	if len(signerIndices) != 2 {
		return errors.New("exactly 2 signers required for 2-of-3 MuSig2")
	}

	// Load public keys from protocol params
	if len(params.MuSig2PublicKeys) != 3 {
		return fmt.Errorf("expected 3 MuSig2 public keys, got %d", len(params.MuSig2PublicKeys))
	}

	publicKeys := make([]*btcec.PublicKey, len(params.MuSig2PublicKeys))
	for i, pubKeyHex := range params.MuSig2PublicKeys {
		pubKeyBytes, err := hex.DecodeString(pubKeyHex)
		if err != nil {
			return fmt.Errorf("invalid public key hex at index %d: %w", i, err)
		}

		pubKey, err := btcec.ParsePubKey(pubKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse public key at index %d: %w", i, err)
		}
		publicKeys[i] = pubKey
	}

	// Get the signing public keys
	signingKeys := make([]*btcec.PublicKey, len(signerIndices))
	for i, idx := range signerIndices {
		if idx < 0 || idx >= len(publicKeys) {
			return fmt.Errorf("invalid signer index: %d", idx)
		}
		signingKeys[i] = publicKeys[idx]
	}

	// Sort keys for consistent aggregation
	sortedSigners := sortKeys(signingKeys)

	// Aggregate the signing public keys
	aggregatedKey, _, _, err := musig2.AggregateKeys(sortedSigners, false)
	if err != nil {
		return fmt.Errorf("failed to aggregate signing keys: %w", err)
	}

	// Parse the signature
	sig, err := schnorr.ParseSignature(signature)
	if err != nil {
		return fmt.Errorf("failed to parse signature: %w", err)
	}

	// Hash the message
	msgHash := sha256.Sum256(message)

	// Verify the signature
	if !sig.Verify(msgHash[:], aggregatedKey.FinalKey) {
		return errors.New("signature verification failed")
	}

	return nil
}

// GetParticipantIndex returns the participant index
func (m *Manager) GetParticipantIndex() int {
	return m.participantIndex
}

// GetPublicKey returns the public key for this participant
func (m *Manager) GetPublicKey() *btcec.PublicKey {
	return m.privateKey.PubKey()
}

// GetAllPublicKeys returns all configured public keys
func (m *Manager) GetAllPublicKeys() []*btcec.PublicKey {
	return m.publicKeys
}