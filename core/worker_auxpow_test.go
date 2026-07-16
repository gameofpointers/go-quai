package core

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dominant-strategies/go-quai/core/types"
)

func TestGetBestAuxTemplateRequiresSignedBitcoinTemplate(t *testing.T) {
	w := &worker{auxpowCache: make(map[types.PowID]*types.AuxTemplate)}
	require.Nil(t, w.GetBestAuxTemplate(types.SHA_BTC))

	template := types.NewAuxTemplate()
	template.SetPowID(types.SHA_BTC)
	template.SetHeight(840000)
	w.auxpowCache[types.SHA_BTC] = template

	require.Same(t, template, w.GetBestAuxTemplate(types.SHA_BTC))
}
