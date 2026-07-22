package quaiapi

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/common/hexutil"
	"github.com/dominant-strategies/go-quai/core/types"
)

func TestSubmitShaWithPowID(t *testing.T) {
	t.Run("BCH success does not try BTC", func(t *testing.T) {
		wantHash := common.HexToHash("0x01")
		var calls []types.PowID
		hash, number, validity, err := submitShaWithPowID(func(powID types.PowID) (common.Hash, uint64, types.WorkShareValidity, error) {
			calls = append(calls, powID)
			return wantHash, 11, types.Block, nil
		})
		if err != nil {
			t.Fatalf("submitShaWithPowID returned error: %v", err)
		}
		if len(calls) != 1 || calls[0] != types.SHA_BCH {
			t.Fatalf("expected only SHA_BCH, got %v", calls)
		}
		if hash != wantHash || number != 11 || validity != types.Block {
			t.Fatalf("unexpected result: hash=%s number=%d validity=%v", hash, number, validity)
		}
	})

	t.Run("BTC is tried after BCH failure", func(t *testing.T) {
		wantHash := common.HexToHash("0x02")
		var calls []types.PowID
		hash, number, validity, err := submitShaWithPowID(func(powID types.PowID) (common.Hash, uint64, types.WorkShareValidity, error) {
			calls = append(calls, powID)
			if powID == types.SHA_BCH {
				return common.Hash{}, 0, types.Invalid, errors.New("not a BCH template")
			}
			return wantHash, 12, types.Valid, nil
		})
		if err != nil {
			t.Fatalf("submitShaWithPowID returned error: %v", err)
		}
		if len(calls) != 2 || calls[0] != types.SHA_BCH || calls[1] != types.SHA_BTC {
			t.Fatalf("expected SHA_BCH then SHA_BTC, got %v", calls)
		}
		if hash != wantHash || number != 12 || validity != types.Valid {
			t.Fatalf("unexpected result: hash=%s number=%d validity=%v", hash, number, validity)
		}
	})

	t.Run("both failures are returned", func(t *testing.T) {
		var calls []types.PowID
		_, _, _, err := submitShaWithPowID(func(powID types.PowID) (common.Hash, uint64, types.WorkShareValidity, error) {
			calls = append(calls, powID)
			return common.Hash{}, 0, types.Invalid, errors.New(powID.String() + " rejected")
		})
		if len(calls) != 2 || calls[0] != types.SHA_BCH || calls[1] != types.SHA_BTC {
			t.Fatalf("expected SHA_BCH then SHA_BTC, got %v", calls)
		}
		if err == nil || !strings.Contains(err.Error(), "BCH") || !strings.Contains(err.Error(), "BTC") {
			t.Fatalf("expected both failures in error, got %v", err)
		}
	})
}

func TestBlockTemplatePowID(t *testing.T) {
	tests := []struct {
		name  string
		rules []string
		want  types.PowID
	}{
		{name: "default", want: types.Kawpow},
		{name: "legacy sha remains bch", rules: []string{"sha"}, want: types.SHA_BCH},
		{name: "explicit bch", rules: []string{"sha_bch"}, want: types.SHA_BCH},
		{name: "explicit btc", rules: []string{"sha_btc"}, want: types.SHA_BTC},
		{name: "bitcoin alias", rules: []string{"bitcoin"}, want: types.SHA_BTC},
		{name: "case insensitive", rules: []string{"BTC"}, want: types.SHA_BTC},
		{name: "scrypt", rules: []string{"scrypt"}, want: types.Scrypt},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := blockTemplatePowID(tt.rules)
			if err != nil {
				t.Fatalf("blockTemplatePowID returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected %s, got %s", tt.want, got)
			}
		})
	}
}

func TestBlockTemplatePowIDRejectsUnknownRule(t *testing.T) {
	if _, err := blockTemplatePowID([]string{"unknown"}); err == nil {
		t.Fatal("expected unsupported rule error")
	}
}

type testNetBackend struct {
	total    uint
	incoming uint
	outgoing uint
}

func (b testNetBackend) PeerCount() uint {
	return b.total
}

func (b testNetBackend) PeerCountByDirection() (uint, uint) {
	return b.incoming, b.outgoing
}

func TestPublicNetAPIPeerCounts(t *testing.T) {
	api := NewPublicNetAPI(1, testNetBackend{
		total:    5,
		incoming: 2,
		outgoing: 3,
	})

	if got := api.PeerCount(); got != hexutil.Uint(5) {
		t.Fatalf("expected peer count 5, got %d", got)
	}

	byDirection := api.PeerCountByDirection()
	if byDirection.Incoming != hexutil.Uint(2) {
		t.Fatalf("expected incoming peer count 2, got %d", byDirection.Incoming)
	}
	if byDirection.Outgoing != hexutil.Uint(3) {
		t.Fatalf("expected outgoing peer count 3, got %d", byDirection.Outgoing)
	}
}

func TestMarshalPendingWorkSharesByPow(t *testing.T) {
	workShares := []*types.WorkObjectHeader{
		newTestPendingWorkShare(1, nil),
		newTestPendingWorkShare(2, newTestAuxPow(types.Kawpow, 2)),
		newTestPendingWorkShare(3, newTestAuxPow(types.SHA_BTC, 3)),
		newTestPendingWorkShare(4, newTestAuxPow(types.SHA_BCH, 4)),
	}

	marshaled := marshalPendingWorkSharesByPow(workShares, "v1")

	if len(marshaled[types.Progpow.String()]) != 1 {
		t.Fatalf("expected 1 progpow workshare, got %d", len(marshaled[types.Progpow.String()]))
	}
	if len(marshaled[types.Kawpow.String()]) != 1 {
		t.Fatalf("expected 1 kawpow workshare, got %d", len(marshaled[types.Kawpow.String()]))
	}
	if len(marshaled[types.SHA_BTC.String()]) != 1 {
		t.Fatalf("expected 1 sha_btc workshare, got %d", len(marshaled[types.SHA_BTC.String()]))
	}
	if len(marshaled[types.SHA_BCH.String()]) != 1 {
		t.Fatalf("expected 1 sha_bch workshare, got %d", len(marshaled[types.SHA_BCH.String()]))
	}

	for pow, entries := range marshaled {
		if len(entries) == 0 {
			t.Fatalf("expected entries for %s", pow)
		}
		entry := entries[0]
		if _, ok := entry["hash"]; !ok {
			t.Fatalf("expected hash field for %s", pow)
		}
		if _, ok := entry["number"]; !ok {
			t.Fatalf("expected number field for %s", pow)
		}
		if _, ok := entry["auxpow"]; ok {
			t.Fatalf("did not expect auxpow field in v1 marshaling for %s", pow)
		}
	}
}

func newTestPendingWorkShare(number int64, auxpow *types.AuxPow) *types.WorkObjectHeader {
	return types.NewWorkObjectHeader(
		common.Hash{byte(number), 0x01},
		common.Hash{byte(number), 0x02},
		big.NewInt(number),
		big.NewInt(1000+number),
		big.NewInt(3000001),
		common.Hash{byte(number), 0x03},
		types.BlockNonce{byte(number)},
		0,
		uint64(1700000000+number),
		common.Location{0, 0},
		common.Address{},
		[]byte{byte(number)},
		auxpow,
		&types.PowShareDiffAndCount{},
		&types.PowShareDiffAndCount{},
		big.NewInt(10),
		big.NewInt(20),
		big.NewInt(30),
	)
}

func newTestAuxPow(powID types.PowID, seed byte) *types.AuxPow {
	return types.NewAuxPow(
		powID,
		types.NewBlockHeader(powID, 1, [32]byte{seed}, [32]byte{seed + 1}, 1700000000, 1, uint32(seed), 1),
		nil,
		nil,
		nil,
		nil,
	)
}
