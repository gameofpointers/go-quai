package tracers

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core"
	"github.com/dominant-strategies/go-quai/core/rawdb"
	"github.com/dominant-strategies/go-quai/core/state"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/core/vm"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/params"
)

type codeOnlyStateDB struct{ vm.StateDB }

func (codeOnlyStateDB) GetCode(common.InternalAddress) []byte { return []byte{0x60, 0x00} }

func newNoEVMTracer(t *testing.T) *Tracer {
	t.Helper()
	tracer, err := New(`{
		step: function() {},
		fault: function() {},
		result: function(ctx, db) {
			return toHex(db.getCode(toAddress('0x0000000000000000000000000000000000000001')));
		}
	}`, &Context{}, log.Global, common.Location{0, 0})
	if err != nil {
		t.Fatal(err)
	}
	return tracer
}

func TestGetResultWithoutCaptureStart(t *testing.T) {
	tracer := newNoEVMTracer(t)
	tracer.dbWrapper.db = codeOnlyStateDB{}
	got, err := tracer.GetResult()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `"0x6000"` {
		t.Fatalf("unexpected code: %s", got)
	}
}

func TestGetResultWithoutStateDBReturnsError(t *testing.T) {
	tracer := newNoEVMTracer(t)
	_, err := tracer.GetResult()
	if err == nil || !strings.Contains(err.Error(), "state database was not initialized") {
		t.Fatalf("expected missing state database error, got %v", err)
	}
}

func TestGetResultWithoutStateDBPreservesTraceError(t *testing.T) {
	tracer := newNoEVMTracer(t)
	want := errors.New("execution timeout")
	tracer.err = want
	_, err := tracer.GetResult()
	if err != want {
		t.Fatalf("expected original trace error, got %v", err)
	}
}

type noEVMTraceBackend struct {
	Backend
	config *params.ChainConfig
}

func (b noEVMTraceBackend) ChainConfig() *params.ChainConfig { return b.config }
func (b noEVMTraceBackend) Logger() *log.Logger              { return log.Global }
func (b noEVMTraceBackend) NodeLocation() common.Location    { return b.config.Location }

type noEVMTraceMessage struct {
	core.Message
	from common.Address
}

func (m noEVMTraceMessage) From() common.Address         { return m.from }
func (m noEVMTraceMessage) To() *common.Address          { return &m.from }
func (m noEVMTraceMessage) GasPrice() *big.Int           { return new(big.Int) }
func (m noEVMTraceMessage) Gas() uint64                  { return params.TxGas }
func (m noEVMTraceMessage) Value() *big.Int              { return new(big.Int) }
func (m noEVMTraceMessage) Nonce() uint64                { return 0 }
func (m noEVMTraceMessage) IsETX() bool                  { return false }
func (m noEVMTraceMessage) Data() []byte                 { return nil }
func (m noEVMTraceMessage) AccessList() types.AccessList { return nil }
func (m noEVMTraceMessage) ETXSender() common.Address    { return common.Address{} }
func (m noEVMTraceMessage) Type() byte                   { return 0 }
func (m noEVMTraceMessage) Hash() common.Hash            { return common.Hash{1} }

func TestTraceTxWithoutEVMCallCanReadState(t *testing.T) {
	loc := common.Location{0, 0}
	config := *params.TestChainConfig
	config.Location = loc
	db := rawdb.NewMemoryDatabase(log.Global)
	defer db.Close()
	statedb, err := state.New(common.Hash{}, common.Hash{}, new(big.Int), state.NewDatabase(db), state.NewDatabase(db), nil, loc, log.Global)
	if err != nil {
		t.Fatal(err)
	}
	codeAddress := common.HexToAddress("0x0000000000000000000000000000000000000001", loc)
	internalCodeAddress, err := codeAddress.InternalAddress()
	if err != nil {
		t.Fatal(err)
	}
	statedb.SetCode(internalCodeAddress, []byte{0x60, 0x00})

	// This sender returns from TransitionDb after the first year, before EVM.Call.
	sender := common.HexToAddress("0x00640d82EF6552085e494DF2a2EAec18D8215913", loc)
	msg := noEVMTraceMessage{from: sender}
	tracerCode := `{step: function() {}, fault: function() {}, result: function(ctx, db) {
		return String(ctx.type === undefined) + ':' + toHex(db.getCode(toAddress('0x0000000000000000000000000000000000000001')));
	}}`
	api := NewAPI(noEVMTraceBackend{config: &config})
	result, err := api.traceTx(context.Background(), msg, &Context{}, vm.BlockContext{
		BlockNumber:   new(big.Int).SetUint64(params.BlocksPerYear + 1),
		BaseFee:       new(big.Int),
		QuaiStateSize: new(big.Int),
		CanTransfer:   func(vm.StateDB, common.Address, *big.Int) bool { return true },
	}, statedb, &TraceConfig{Tracer: &tracerCode})
	if err != nil {
		t.Fatal(err)
	}
	if string(result.(json.RawMessage)) != `"true:0x6000"` {
		t.Fatalf("unexpected trace result: %s", result)
	}
}
