// Copyright 2017 The go-ethereum Authors
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

package tracers

import (
	"encoding/json"
	"math/big"
	"time"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/tracing"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/core/vm"
	"github.com/dominant-strategies/go-quai/params"
)

// Context contains some contextual infos for a transaction execution that is not
// available from within the EVM object.
type Context struct {
	BlockHash   common.Hash // Hash of the block the tx is contained within (zero if dangling tx or call)
	BlockNumber *big.Int    // Number of the block the tx is contained within (zero if dangling tx or call)
	TxIndex     int         // Index of the transaction within a block (zero if dangling tx or call)
	TxHash      common.Hash // Hash of the transaction being traced (zero if dangling call)
}

// The set of methods that must be exposed by a tracer
// for it to be available through the RPC interface.
// This involves a method to retrieve results and one to
// stop tracing.
type Tracer struct {
	*tracing.Hooks

	GetResult func() (json.RawMessage, error)
	// Stop terminates execution of the tracer at the first opportune moment.
	Stop func(err error)
}

func (t *Tracer) OnTxStart(vm *vm.VMContext, tx *types.Transaction, from common.Address) {
	if t.OnStartTx != nil {
		t.OnStartTx(vm, tx, from)
	}
}

func (t *Tracer) OnTxEnd(receipt *types.Receipt, err error) {
	if t.OnEndTx != nil {
		t.OnEndTx(receipt, err)
	}
}

func (t *Tracer) OnLog(log *types.Log) {
	if t.OnLogAdd != nil {
		t.OnLogAdd(log)
	}
}

func (t *Tracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	if t.OnStart != nil {
		t.OnStart(env, from, to, create, input, gas, value)
	}
}
func (t *Tracer) CaptureState(env *vm.EVM, pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error, nodeLocation common.Location) {
	if t.OnState != nil {
		t.OnState(env, pc, op, gas, cost, scope, rData, depth, err, nodeLocation)
	}
}
func (t *Tracer) CaptureFault(env *vm.EVM, pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, depth int, err error) {
	if t.OnFault != nil {
		t.OnFault(env, pc, op, gas, cost, scope, depth, err)
	}
}
func (t *Tracer) CaptureEnd(depth int, output []byte, gasUsed uint64, tim time.Duration, err error, reverted bool) {
	if t.OnEnd != nil {
		t.OnEnd(depth, output, gasUsed, tim, err, reverted)
	}
}

type ctorFn func(*Context, json.RawMessage, *params.ChainConfig) (*Tracer, error)
type jsCtorFn func(string, *Context, json.RawMessage, *params.ChainConfig) (*Tracer, error)

type elem struct {
	ctor ctorFn
	isJS bool
}

// DefaultDirectory is the collection of tracers bundled by default.
var DefaultDirectory = directory{elems: make(map[string]elem)}

// directory provides functionality to lookup a tracer by name
// and a function to instantiate it. It falls back to a JS code evaluator
// if no tracer of the given name exists.
type directory struct {
	elems  map[string]elem
	jsEval jsCtorFn
}

// Register registers a method as a lookup for tracers, meaning that
// users can invoke a named tracer through that lookup.
func (d *directory) Register(name string, f ctorFn, isJS bool) {
	d.elems[name] = elem{ctor: f, isJS: isJS}
}

// RegisterJSEval registers a tracer that is able to parse
// dynamic user-provided JS code.
func (d *directory) RegisterJSEval(f jsCtorFn) {
	d.jsEval = f
}

// New returns a new instance of a tracer, by iterating through the
// registered lookups. Name is either name of an existing tracer
// or an arbitrary JS code.
func (d *directory) New(name string, ctx *Context, cfg json.RawMessage, chainConfig *params.ChainConfig) (*Tracer, error) {
	if len(cfg) == 0 {
		cfg = json.RawMessage("{}")
	}
	if elem, ok := d.elems[name]; ok {
		return elem.ctor(ctx, cfg, chainConfig)
	}
	// Assume JS code
	return d.jsEval(name, ctx, cfg, chainConfig)
}

// IsJS will return true if the given tracer will evaluate
// JS code. Because code evaluation has high overhead, this
// info will be used in determining fast and slow code paths.
func (d *directory) IsJS(name string) bool {
	if elem, ok := d.elems[name]; ok {
		return elem.isJS
	}
	// JS eval will execute JS code
	return true
}
