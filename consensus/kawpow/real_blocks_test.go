package kawpow

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/stretchr/testify/require"
)

// ravencoinBlockVectorsJSON embeds a handful of real Ravencoin KAWPOW blocks
// extracted from the snapshot under raven-data/home/drk/raven-snapshot/blocks.
// Each entry captures the pre-KAWPOW header hash, the 64-bit nonce, and the
// expected mix and final PoW hashes produced by our implementation.
const ravencoinBlockVectorsJSON = `[
  {
    "description": "blk00225.dat block 2952012 idx0",
    "epoch": 393,
    "height": 2952012,
    "bits": "0x1b00bb8c",
    "headerHash": "0x64f57150760e2d32317b3d396fedd475219a7005d0ea798ae39425366b590a45",
    "nonce": "0xa12e052c5b24d6d3",
    "expectedMixHash": "0x7d6adbb1c76988a11db0bf23a2a5c363c5db2135ee15ba02a8432a1fd21b5d29",
    "expectedPowHash": "0x01818cc0c740456b7ef7371ef337fa8c63a3a3149736f5805145f2eaeb6e5931",
    "meetsTarget": false,
    "timestamp": 1693360951,
    "txCount": 3,
    "coinbaseOutputs": [
      {
        "value": 247529822657,
        "script": "a914d7370df60f61861789c4acb49b3a8beea606384887"
      },
      {
        "value": 2500301238,
        "script": "a914717d400607c3e35cb8629dcde98a7d39dc838de187"
      },
      {
        "value": 0,
        "script": "6a24aa21a9ed034238418349f3fcf6ce56166f24b29d59f2dfb35c5c5e2ecbc77fd606b04af9"
      }
    ],
    "primaryPayoutValue": 247529822657,
    "primaryPayoutScript": "a914d7370df60f61861789c4acb49b3a8beea606384887",
    "opReturn": "aa21a9ed034238418349f3fcf6ce56166f24b29d59f2dfb35c5c5e2ecbc77fd606b04af9"
  },
  {
    "description": "blk00225.dat block 2955000 idx2986",
    "epoch": 394,
    "height": 2955000,
    "bits": "0x1b00b98d",
    "headerHash": "0x6de7d34bca35bff115f0cbf815fceca1c068110d1bbc6eeea583e8ed29e0dd9e",
    "nonce": "0x540000084abcc277",
    "expectedMixHash": "0xc395dee0f9066393090e3c891c86463781f0d4c09969d0459a536dd4721b5eb1",
    "expectedPowHash": "0xdb6b586932507d77b33848aae9d50eb91794ad8daaee44b0d5c77343aef6e670",
    "meetsTarget": false,
    "timestamp": 1693542216,
    "txCount": 5,
    "coinbaseOutputs": [
      {
        "value": 250002170509,
        "script": "76a91459d584c2da3735f24af4ed3eb8e2abeb63fbffd688ac"
      },
      {
        "value": 0,
        "script": "6a24aa21a9ed977bada1e859227a86a508dc5d18496d1a6540d186a52372e07199241e8587e4"
      }
    ],
    "primaryPayoutValue": 250002170509,
    "primaryPayoutScript": "76a91459d584c2da3735f24af4ed3eb8e2abeb63fbffd688ac",
    "opReturn": "aa21a9ed977bada1e859227a86a508dc5d18496d1a6540d186a52372e07199241e8587e4"
  },
  {
    "description": "blk00225.dat block 2962500 idx10488",
    "epoch": 395,
    "height": 2962500,
    "bits": "0x1b00cc0c",
    "headerHash": "0xddd806736ca08257ada8e792da8508e13f28ac3a96817ac0385bd6af922a56f3",
    "nonce": "0x01012631c7c6265e",
    "expectedMixHash": "0x50c29ab91d2942fa8a39e65ace949517b02778fc2604b90ce8c2a5b204bf110b",
    "expectedPowHash": "0x0c1076e53ea1a834ac43ca31665d8b9b2db2e8c6dd1bd23318c8df12439f6abd",
    "meetsTarget": false,
    "timestamp": 1693994679,
    "txCount": 2,
    "coinbaseOutputs": [
      {
        "value": 250000351120,
        "script": "76a91459d584c2da3735f24af4ed3eb8e2abeb63fbffd688ac"
      },
      {
        "value": 0,
        "script": "6a24aa21a9ed8d385d95a406e6bc472303b06fbb8f77ef59083cf88d37028f28b7d2380701f4"
      }
    ],
    "primaryPayoutValue": 250000351120,
    "primaryPayoutScript": "76a91459d584c2da3735f24af4ed3eb8e2abeb63fbffd688ac",
    "opReturn": "aa21a9ed8d385d95a406e6bc472303b06fbb8f77ef59083cf88d37028f28b7d2380701f4"
  },
  {
    "description": "blk00225.dat block 2970001 idx17982",
    "epoch": 396,
    "height": 2970001,
    "bits": "0x1b00b824",
    "headerHash": "0xf5a6d62b67ec5012ebecfc73a4e52751558b1c2c135b8e8223ea229a787d096d",
    "nonce": "0x14d5555567153728",
    "expectedMixHash": "0xc6503684c0e31cc67aabc7d09bf413bbd9d4a5d45da95ac3bc35cefa7d5e4f78",
    "expectedPowHash": "0x0fff4609e787b3b870291ae10a56fd2a8e3288ea68403b03e34d033a5b7026ca",
    "meetsTarget": false,
    "timestamp": 1694447601,
    "txCount": 1,
    "coinbaseOutputs": [
      {
        "value": 250000000000,
        "script": "76a91459d584c2da3735f24af4ed3eb8e2abeb63fbffd688ac"
      },
      {
        "value": 0,
        "script": "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9"
      }
    ],
    "primaryPayoutValue": 250000000000,
    "primaryPayoutScript": "76a91459d584c2da3735f24af4ed3eb8e2abeb63fbffd688ac",
    "opReturn": "aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9"
  },
  {
    "description": "blk00226.dat block 2977500 idx1309",
    "epoch": 397,
    "height": 2977500,
    "bits": "0x1b00ba72",
    "headerHash": "0xe3c1e80afaf5065babcb4667518b40576b43b67dd10cb17d5bf405c24b00c14c",
    "nonce": "0x6307002b2046b833",
    "expectedMixHash": "0x4e9bc301a4889f45077ff178d819753fe0d4a498e184916a04ced416e0d2d6e0",
    "expectedPowHash": "0x29ea286e95ab58e4daba7d31694307089b5b646410b1f676c06dc7ecdcb24cf5",
    "meetsTarget": false,
    "timestamp": 1694899991,
    "txCount": 4,
    "coinbaseOutputs": [
      {
        "value": 250005890770,
        "script": "76a91487dd7413ff8bb9f36730da5dde6fe619c9a1abfe88ac"
      },
      {
        "value": 0,
        "script": "6a24aa21a9ed0336c53250db10342afe6803db8ce5d40b509ba7d29b96ed17a40b8e3d071f49"
      }
    ],
    "primaryPayoutValue": 250005890770,
    "primaryPayoutScript": "76a91487dd7413ff8bb9f36730da5dde6fe619c9a1abfe88ac",
    "opReturn": "aa21a9ed0336c53250db10342afe6803db8ce5d40b509ba7d29b96ed17a40b8e3d071f49"
  },
  {
    "description": "blk00226.dat block 2985000 idx8809",
    "epoch": 398,
    "height": 2985000,
    "bits": "0x1b00c02c",
    "headerHash": "0xadccf61cfc1849b6521578f7237c137187fec0b6326e0e4d078ef5a84c45b598",
    "nonce": "0xc6f9c35727b4b0f8",
    "expectedMixHash": "0xb8b9a9899f38d4e9cc6d4ede3edb2351973457584dda72878793e0ac8c5198ab",
    "expectedPowHash": "0x0ef0ce9c3e6cf70fa7d6167a6a72c042e50d791cb2691b61d4a821716895bb79",
    "meetsTarget": false,
    "timestamp": 1695353033,
    "txCount": 2,
    "coinbaseOutputs": [
      {
        "value": 250000285325,
        "script": "76a914b00dfd8e77c30bbbe32dade7df0af4b03178440688ac"
      },
      {
        "value": 0,
        "script": "6a24aa21a9ed2189049394e17598786a2ddb0ac5bba2f5168750b35d6b044c0c17ea65e126b3"
      }
    ],
    "primaryPayoutValue": 250000285325,
    "primaryPayoutScript": "76a914b00dfd8e77c30bbbe32dade7df0af4b03178440688ac",
    "opReturn": "aa21a9ed2189049394e17598786a2ddb0ac5bba2f5168750b35d6b044c0c17ea65e126b3"
  },
  {
    "description": "blk00226.dat block 2992500 idx16309",
    "epoch": 399,
    "height": 2992500,
    "bits": "0x1b00ce69",
    "headerHash": "0x1ba5b549654171efd7bd8778647c1cf67d7fa1574be114fb5c18313d55bb6824",
    "nonce": "0x1cbc1d4e2d341268",
    "expectedMixHash": "0xa42802ef1b597bde4fa9a42956d91b9fec7bb692fff9f9e145ad54a2cfc93abb",
    "expectedPowHash": "0x370f9d58ff6e70bf01582f7e188d646e9f0a0f6c3a64df4dd1010afcc25a5311",
    "meetsTarget": false,
    "timestamp": 1695806094,
    "txCount": 4,
    "coinbaseOutputs": [
      {
        "value": 247501583932,
        "script": "a91405bba9edcb6276aa002807b76380c953093c758987"
      },
      {
        "value": 2500015999,
        "script": "a9141041111dd0cfde440d64041063f6275a7acc699087"
      },
      {
        "value": 0,
        "script": "6a24aa21a9ed7a21dfb521b4b6d713a4b31d5f7d31f5dcf35e7bebadebafb53859a08f57c454"
      }
    ],
    "primaryPayoutValue": 247501583932,
    "primaryPayoutScript": "a91405bba9edcb6276aa002807b76380c953093c758987",
    "opReturn": "aa21a9ed7a21dfb521b4b6d713a4b31d5f7d31f5dcf35e7bebadebafb53859a08f57c454"
  },
  {
    "description": "blk00226.dat block 3000000 idx23809",
    "epoch": 400,
    "height": 3000000,
    "bits": "0x1b00a281",
    "headerHash": "0xc74cc42464be48c7cbbc97b5871e4c0e2f68e55b59153f7b9483f3faf9f98ff1",
    "nonce": "0xad000000314f9acb",
    "expectedMixHash": "0x36698c69a324d6b96c47ce9d2ad684ca90b683be2c246b71c003acbaaa3281f2",
    "expectedPowHash": "0x2fae5163ed6c5bf77a0de8e8968dae18aac3b31a7c6c675f1d7b7bc36136f86f",
    "meetsTarget": false,
    "timestamp": 1696258085,
    "txCount": 2,
    "coinbaseOutputs": [
      {
        "value": 250000655229,
        "script": "76a91459d584c2da3735f24af4ed3eb8e2abeb63fbffd688ac"
      },
      {
        "value": 0,
        "script": "6a24aa21a9ed3fa79bc64195594f1fafdebc7a0364b2491a76366ed45a5eeaf8cc4740bbac1b"
      }
    ],
    "primaryPayoutValue": 250000655229,
    "primaryPayoutScript": "76a91459d584c2da3735f24af4ed3eb8e2abeb63fbffd688ac",
    "opReturn": "aa21a9ed3fa79bc64195594f1fafdebc7a0364b2491a76366ed45a5eeaf8cc4740bbac1b"
  },
  {
    "description": "blk00234.dat block 3138048 idx0",
    "epoch": 418,
    "height": 3138048,
    "bits": "0x1b010770",
    "headerHash": "0xa3218c18344c712e973e7cc44f50441dac695cc19be7b03092138e5cc6d7ad28",
    "nonce": "0x50000a5c49a62a2b",
    "expectedMixHash": "0x80929295938d93d92861ed8479d2dab0b8372e189f2aae2079d739601d02543d",
    "expectedPowHash": "0x2d25e21a10dc7b3c9e76b89c26b390f52668e0e3f1e7568ee2238b7878f5d698",
    "meetsTarget": false,
    "timestamp": 1704596680,
    "txCount": 18,
    "coinbaseOutputs": [
      {
        "value": 250006510162,
        "script": "76a91459d584c2da3735f24af4ed3eb8e2abeb63fbffd688ac"
      },
      {
        "value": 0,
        "script": "6a24aa21a9ed2aa451cbe4b54a24d65f0e3de340664cf26e925fa3e26faf892c64ef984d89ff"
      }
    ],
    "primaryPayoutValue": 250006510162,
    "primaryPayoutScript": "76a91459d584c2da3735f24af4ed3eb8e2abeb63fbffd688ac",
    "opReturn": "aa21a9ed2aa451cbe4b54a24d65f0e3de340664cf26e925fa3e26faf892c64ef984d89ff"
  },
  {
    "description": "blk00234.dat block 3142500 idx4452",
    "epoch": 419,
    "height": 3142500,
    "bits": "0x1b011d4a",
    "headerHash": "0x1a39e1e38adc39813a49bb88cdcf665845be64f06d86d1945ab04c4ef394ddc8",
    "nonce": "0xb84f2b002b430c82",
    "expectedMixHash": "0x6c9b2ab1912710393fb2a69d00be7c6503e655a2ea32815351669ebfbfaf356e",
    "expectedPowHash": "0xb5b3df4310ca508515d1add369d72a46bb16312abeb49ee534c362f215e42f51",
    "meetsTarget": false,
    "timestamp": 1704865993,
    "txCount": 2,
    "coinbaseOutputs": [
      {
        "value": 247500260741,
        "script": "a91400cc259ad9172d45f0caf45996f0b5f7f0afb47487"
      },
      {
        "value": 2500002633,
        "script": "a9146eb0de7701ee3db5ae03cfc630eca3dd2e68d3c687"
      },
      {
        "value": 0,
        "script": "6a24aa21a9ed62ace1822bdbef468da6fdbc58e73f464b9da2fe87deb6579074262f250724e2"
      }
    ],
    "primaryPayoutValue": 247500260741,
    "primaryPayoutScript": "a91400cc259ad9172d45f0caf45996f0b5f7f0afb47487",
    "opReturn": "aa21a9ed62ace1822bdbef468da6fdbc58e73f464b9da2fe87deb6579074262f250724e2"
  },
  {
    "description": "blk00234.dat block 3150000 idx11950",
    "epoch": 420,
    "height": 3150000,
    "bits": "0x1b0107e0",
    "headerHash": "0xf8c7fe90934791e7f2d3778ef23e398e0dd45b70d78bd5cd9e9bbfe7c80b7f6b",
    "nonce": "0x9e0d3dd1a45a521f",
    "expectedMixHash": "0xddb47ee5a14fe475937883ea638929150a910bfefe9fa8ec3aa9c61c26680438",
    "expectedPowHash": "0xd6b9699c1e628a8479790955467dcc1deb3ae7833253c6c355f8abd6df7bec31",
    "meetsTarget": false,
    "timestamp": 1705318360,
    "txCount": 4,
    "coinbaseOutputs": [
      {
        "value": 250008214614,
        "script": "76a91459d584c2da3735f24af4ed3eb8e2abeb63fbffd688ac"
      },
      {
        "value": 0,
        "script": "6a24aa21a9edcfa365a1745b7ae4fdfba27eee8283d104cf8359e2205d2c2cbda2d9dfe8c2e4"
      }
    ],
    "primaryPayoutValue": 250008214614,
    "primaryPayoutScript": "76a91459d584c2da3735f24af4ed3eb8e2abeb63fbffd688ac",
    "opReturn": "aa21a9edcfa365a1745b7ae4fdfba27eee8283d104cf8359e2205d2c2cbda2d9dfe8c2e4"
  },
  {
    "description": "blk00261.dat block 3688142 idx0",
    "epoch": 491,
    "height": 3688142,
    "bits": "0x1b00a087",
    "headerHash": "0xacabb2aced7d33cf0ae024bc897e1e8110c7d014e60c5b02732a1a1fc562deaf",
    "nonce": "0x11f84f512a6d371d",
    "expectedMixHash": "0x6d96a8a81bb2560dec1191972ed0a03ace137ac7aa87dda2c7500b31085854c9",
    "expectedPowHash": "0x8fe5f0c7212bbdd004f4ea1d30c6b750ebfa73e35e48ee50a3a1adc5587a5705",
    "meetsTarget": false,
    "timestamp": 1737808478,
    "txCount": 11,
    "coinbaseOutputs": [
      {
        "value": 250024503368,
        "script": "76a914d8d5a195e60fc7b95da92ee8dd57ea6e2bde137a88ac"
      },
      {
        "value": 0,
        "script": "6a24aa21a9edc7738a565f7099c4351a0699e11fad3e68ed9b7c3ef5a62596c8ad349c455ca3"
      }
    ],
    "primaryPayoutValue": 250024503368,
    "primaryPayoutScript": "76a914d8d5a195e60fc7b95da92ee8dd57ea6e2bde137a88ac",
    "opReturn": "aa21a9edc7738a565f7099c4351a0699e11fad3e68ed9b7c3ef5a62596c8ad349c455ca3"
  },
  {
    "description": "blk00261.dat block 3690000 idx1855",
    "epoch": 492,
    "height": 3690000,
    "bits": "0x1b00acfc",
    "headerHash": "0x1ac7b0780610a29533dc97a06728b2001ddc2aa8d35c9ebf1a5b8c5df9e7b402",
    "nonce": "0x2d95c5c02dd1ec1e",
    "expectedMixHash": "0x63815506acbeb6ba0332fe23a6331952984eb3785898dbd5cf569b2f6f7cf070",
    "expectedPowHash": "0x1fcd5e717e3ce3149b30d4ca7c98c9a96ecf851f4949a2765a4a6dd83d930db9",
    "meetsTarget": false,
    "timestamp": 1737920793,
    "txCount": 10,
    "coinbaseOutputs": [
      {
        "value": 247533638311,
        "script": "76a9142c2148a23508b877cf4538a1b9fce5016eabb07888ac"
      },
      {
        "value": 2500339780,
        "script": "76a9148989bedcc0239cf3cb8a379d8a63e356e0d8d17f88ac"
      },
      {
        "value": 0,
        "script": "6a24aa21a9eda5dd5cd562abac9125acdcb18a63863e0f597b7d0733be1a3b2a8e5f337989ef"
      }
    ],
    "primaryPayoutValue": 247533638311,
    "primaryPayoutScript": "76a9142c2148a23508b877cf4538a1b9fce5016eabb07888ac",
    "opReturn": "aa21a9eda5dd5cd562abac9125acdcb18a63863e0f597b7d0733be1a3b2a8e5f337989ef"
  },
  {
    "description": "blk00261.dat block 3697500 idx9357",
    "epoch": 493,
    "height": 3697500,
    "bits": "0x1b00a70f",
    "headerHash": "0x5c3b22c1271139024616082124147d603f4fa0778849d5d271ed46748eeb6a75",
    "nonce": "0x244a11000cd1ff26",
    "expectedMixHash": "0x30a58f8ad334115aa3092a43bfceedc4423df6d48470d1e1f2626777126a82ef",
    "expectedPowHash": "0x8f89153340b81754b0f0c12f9f0a7d43c85911ce1ce23e9adf9b92e9cc69fbc4",
    "meetsTarget": false,
    "timestamp": 1738373541,
    "txCount": 10,
    "coinbaseOutputs": [
      {
        "value": 250016368922,
        "script": "76a914b00dfd8e77c30bbbe32dade7df0af4b03178440688ac"
      },
      {
        "value": 0,
        "script": "6a24aa21a9ed01a077df6dda7366011c8e570ec157eda04bdf5fa5b82a15bc5e6914c77909c2"
      }
    ],
    "primaryPayoutValue": 250016368922,
    "primaryPayoutScript": "76a914b00dfd8e77c30bbbe32dade7df0af4b03178440688ac",
    "opReturn": "aa21a9ed01a077df6dda7366011c8e570ec157eda04bdf5fa5b82a15bc5e6914c77909c2"
  },
  {
    "description": "blk00261.dat block 3705000 idx16858",
    "epoch": 494,
    "height": 3705000,
    "bits": "0x1b00acf5",
    "headerHash": "0x41affea546c430cdd41268f87b1eb163a513050cc4ff0cc8766a81dc7cf7c075",
    "nonce": "0xf562400000398167",
    "expectedMixHash": "0x019e3885844e4b309b2628ff1cf7be39a89a22f532e2f70ab61a3afdeadc42b9",
    "expectedPowHash": "0x675c93cc0d1e2905e9aa8949049787b5537dda2bd642a9fbbbd1c84830f344ff",
    "meetsTarget": false,
    "timestamp": 1738826304,
    "txCount": 2,
    "coinbaseOutputs": [
      {
        "value": 0,
        "script": "6a24aa21a9ed5fc53c0772daa773243bb9871972fa79d9e8724b423498d3996bbed97b91f788"
      },
      {
        "value": 250000279788,
        "script": "76a914813318421c3b46e8391b3bb0acad06a02ea8960788ac"
      }
    ],
    "primaryPayoutValue": 250000279788,
    "primaryPayoutScript": "76a914813318421c3b46e8391b3bb0acad06a02ea8960788ac",
    "opReturn": "aa21a9ed5fc53c0772daa773243bb9871972fa79d9e8724b423498d3996bbed97b91f788"
  }
]`

type coinbaseOutput struct {
	Value  int64  `json:"value"`
	Script string `json:"script"`
}

type ravencoinBlockVector struct {
	Description         string           `json:"description"`
	Height              uint64           `json:"height"`
	BitsHex             string           `json:"bits"`
	HeaderHashHex       string           `json:"headerHash"`
	NonceHex            string           `json:"nonce"`
	ExpectedMixHex      string           `json:"expectedMixHash"`
	ExpectedPowHex      string           `json:"expectedPowHash"`
	MeetsTarget         bool             `json:"meetsTarget"`
	Timestamp           uint64           `json:"timestamp"`
	TxCount             int              `json:"txCount"`
	CoinbaseOutputs     []coinbaseOutput `json:"coinbaseOutputs"`
	PrimaryPayoutValue  uint64           `json:"primaryPayoutValue"`
	PrimaryPayoutScript string           `json:"primaryPayoutScript"`
	OpReturn            string           `json:"opReturn"`
}

func TestRavencoinKAWPOWVectors(t *testing.T) {
	t.Helper()

	var vectors []ravencoinBlockVector
	require.NoError(t, json.Unmarshal([]byte(ravencoinBlockVectorsJSON), &vectors))
	require.NotEmpty(t, vectors, "expected at least one vector")

	logger := log.NewLogger("kawpow-vectors.log", "info", 100)
	engine := New(Config{PowMode: ModeNormal, CachesInMem: 1}, nil, false, logger)

	for _, vector := range vectors {
		vector := vector
		t.Run(vector.Description, func(t *testing.T) {
			headerHash := common.HexToHash(vector.HeaderHashHex)
			nonce := mustParseUint64(t, vector.NonceHex)
			bits := mustParseUint32(t, vector.BitsHex)

			cache := engine.cache(vector.Height)
			datasetBytes := datasetSize(vector.Height)
			digest, pow := kawpowLight(datasetBytes, cache.cache, headerHash.Bytes(), nonce, vector.Height, cache.cDag)

			mixHex := common.BytesToHash(digest).Hex()
			powHex := common.BytesToHash(pow).Hex()

			require.Equal(t, normalizeHex(vector.ExpectedMixHex), normalizeHex(mixHex), "mix hash mismatch")
			require.Equal(t, normalizeHex(vector.ExpectedPowHex), normalizeHex(powHex), "pow hash mismatch")

			powInt := new(big.Int).SetBytes(pow)
			target := bitsToTarget(bits)
			meets := powInt.Cmp(target) <= 0
			require.Equal(t, vector.MeetsTarget, meets, "difficulty comparison mismatch")
		})
	}
}

func mustParseUint64(t *testing.T, hexStr string) uint64 {
	t.Helper()
	val, err := parseUintFromHex(hexStr, 64)
	require.NoError(t, err)
	return val
}

func mustParseUint32(t *testing.T, hexStr string) uint32 {
	t.Helper()
	val, err := parseUintFromHex(hexStr, 32)
	require.NoError(t, err)
	return uint32(val)
}

func parseUintFromHex(hexStr string, bitSize int) (uint64, error) {
	s := strings.TrimPrefix(strings.ToLower(hexStr), "0x")
	if s == "" {
		return 0, nil
	}
	value, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return 0, fmt.Errorf("invalid hex value %q", hexStr)
	}
	if value.BitLen() > bitSize {
		return 0, fmt.Errorf("value %q exceeds %d bits", hexStr, bitSize)
	}
	return value.Uint64(), nil
}

func normalizeHex(s string) string {
	return strings.ToLower(strings.TrimPrefix(s, "0x"))
}

func bitsToTarget(bits uint32) *big.Int {
	exponent := (bits >> 24) & 0xff
	mantissa := bits & 0x00ffffff

	target := new(big.Int).SetUint64(uint64(mantissa))
	shift := int(exponent) - 3
	if shift < 0 {
		target.Rsh(target, uint(-shift*8))
	} else {
		target.Lsh(target, uint(shift*8))
	}
	return target
}
