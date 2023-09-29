// Copyright 2015 The go-ethereum Authors
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

package core

import "github.com/dominant-strategies/go-quai/common"

type HeirarchyBadHashes struct {
	PrimeContext  common.Hash
	RegionContext []common.Hash
	ZoneContext   [][]common.Hash
}

var BadHashes = []HeirarchyBadHashes{
	HeirarchyBadHashes{
		PrimeContext: common.HexToHash("0x0813eb5605424054121ad7160a55af45efc3bf1c8a49fcb3f538371ff439e6e8"),
		RegionContext: []common.Hash{
			common.HexToHash("0x9ca7505c1604821b1c0bc197422c67dd917e51a9fa8d6d66cecd376b0f24d784"),
			common.HexToHash("0x6331b1378c6638e645d38fd3553a8de8a518e836d28e42dbaba0552d52060210"),
			common.HexToHash("0xcb36c9fe3bd7f680667a719228d745d96da8e2b1ca41687267967b998e59945f"),
		},
		ZoneContext: [][]common.Hash{
			[]common.Hash{
				common.HexToHash("0x10b1427aaaf763b7b46f2976b389eabdb841fb78381792b8512bceac9b293d70"),
				common.HexToHash("0x24a2f495cfbcde0059a1e186ea4cc64e836dbeaf8ce94e593ee8f369e926b15c"),
				common.HexToHash("0x3a707834256f10617c2dc90f8b1d2fdbf85967f92b2155d75001125ec5ab140c"),
			},
			[]common.Hash{
				common.HexToHash("0xa1f4017433e9397bc12fa55185261ef371a60c1426c09246b530851ee45b6dd1"),
				common.HexToHash("0x3890ee2e8a2b2114e4cf05d6220831fe4a8179ef08ba7f2ca06d2715adea6c81"),
				common.HexToHash("0x9e824c19e8223f0d72593ecbe17516e85c9b6f1631da65dc1a3f4a8fdf91ae66"),
			},
			[]common.Hash{
				common.HexToHash("0xc5144226a339dccbbbd4da4e1752519bcfe305b78e14edd564d9811f0b66549e"),
				common.HexToHash("0x6cd0b54f97badc078400e016ab1c47359130e48949473b4756e6ee3778f1c421"),
				common.HexToHash("0x5af17dc6a19d404f8846b6578d61288cc7ae6a72e84abe25b6c840597a9ed7d1"),
			},
		},
	},
}
