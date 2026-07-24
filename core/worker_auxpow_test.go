package core

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dominant-strategies/go-quai/core/types"
)

func TestGetBestAuxTemplateSelectsLatestShaTemplate(t *testing.T) {
	newShaTemplate := func(powID types.PowID, signatureTime uint32) *types.AuxTemplate {
		template := types.NewAuxTemplate()
		template.SetPowID(powID)
		template.SetSignatureTime(signatureTime)
		return template
	}

	btcOlder := newShaTemplate(types.SHA_BTC, 100)
	btcNewer := newShaTemplate(types.SHA_BTC, 300)
	bchOlder := newShaTemplate(types.SHA_BCH, 200)
	bchNewer := newShaTemplate(types.SHA_BCH, 400)
	bchSameTime := newShaTemplate(types.SHA_BCH, 300)

	tests := []struct {
		name      string
		cache     map[types.PowID]*types.AuxTemplate
		expected  *types.AuxTemplate
		defaultID types.PowID
	}{
		{
			name:     "only bitcoin",
			cache:    map[types.PowID]*types.AuxTemplate{types.SHA_BTC: btcOlder},
			expected: btcOlder,
		},
		{
			name:     "only bitcoin cash",
			cache:    map[types.PowID]*types.AuxTemplate{types.SHA_BCH: bchOlder},
			expected: bchOlder,
		},
		{
			name: "bitcoin is newer",
			cache: map[types.PowID]*types.AuxTemplate{
				types.SHA_BTC: btcNewer,
				types.SHA_BCH: bchOlder,
			},
			expected: btcNewer,
		},
		{
			name: "bitcoin cash is newer",
			cache: map[types.PowID]*types.AuxTemplate{
				types.SHA_BTC: btcNewer,
				types.SHA_BCH: bchNewer,
			},
			expected: bchNewer,
		},
		{
			name: "equal times prefer bitcoin",
			cache: map[types.PowID]*types.AuxTemplate{
				types.SHA_BTC: btcNewer,
				types.SHA_BCH: bchSameTime,
			},
			expected: btcNewer,
		},
		{
			name:      "no signed template uses bitcoin cash default",
			cache:     map[types.PowID]*types.AuxTemplate{},
			defaultID: types.SHA_BCH,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			w := &worker{auxpowCache: test.cache}
			for _, requestedPowID := range []types.PowID{types.SHA_BTC, types.SHA_BCH} {
				actual := w.GetBestAuxTemplate(requestedPowID)
				if test.expected != nil {
					require.Same(t, test.expected, actual)
				} else {
					require.Equal(t, test.defaultID, actual.PowID())
				}
			}
		})
	}
}
