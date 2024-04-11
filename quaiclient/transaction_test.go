package quaiclient

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	interfaces "github.com/dominant-strategies/go-quai"
	quai "github.com/dominant-strategies/go-quai"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/crypto"
	goCrypto "github.com/dominant-strategies/go-quai/crypto"
	"google.golang.org/protobuf/proto"

	"github.com/dominant-strategies/go-quai/params"
	"github.com/dominant-strategies/go-quai/quaiclient/ethclient"
)

var (
	location = common.Location{0, 0}
	PARAMS   = params.ChainConfig{ChainID: big.NewInt(1337), Location: location}
	MINERTIP = big.NewInt(1 * params.GWei)
	BASEFEE  = big.NewInt(1 * params.GWei)
	GAS      = uint64(420000)
	VALUE    = big.NewInt(10)
)

func TestTX(t *testing.T) {

	numTests := 1
	fromAddress := make([]common.Address, numTests)
	privKey := make([]*ecdsa.PrivateKey, numTests)
	toAddress := make([]common.Address, numTests)
	// toPrivKey := make([]*ecdsa.PrivateKey, numTests)
	wsUrl := make([]string, numTests)
	err := error(nil)
	fromLocation := make([]common.Location, numTests)
	toLocation := make([]common.Location, numTests)

	//cyprus 1 -> cyprus 1
	fromLocation[0] = common.Location{0, 0}
	toLocation[0] = common.Location{0, 0}
	fromAddress[0] = common.HexToAddress("0x0021358CeaC22936858C3eDa6EB86e0559915550", fromLocation[0])
	privKey[0], err = goCrypto.ToECDSA(common.FromHex("0x7e99ffbdf4b3dda10174f18a0991114bb4a7a684b5972c6901fbe8a4a4bfc325"))
	if err != nil {
		t.Fatalf("Failed to convert private key to ECDSA: %v", err)
	}
	toAddress[0] = common.HexToAddress("0x0147f9CEa7662C567188D58640ffC48901cde02a", toLocation[0])
	// toPrivKey[0], err = goCrypto.ToECDSA(common.FromHex("0x86f3731e698525a27530d4da6d1ae826303bb9b813ee718762b4c3524abddac5"))
	// if err != nil {
	// 	t.Fatalf("Failed to convert private key to ECDSA: %v", err)
	// }
	wsUrl[0] = "ws://localhost:8100"
	to := toAddress[0]

	for i := 0; i < numTests; i++ {
		from := goCrypto.PubkeyToAddress(privKey[i].PublicKey, fromLocation[i])
		if !from.Equal(fromAddress[i]) {
			t.Fatalf("Failed to convert public key to address: %v", err)
		}

		// to := goCrypto.PubkeyToAddress(toPrivKey[i].PublicKey, toLocation[i])
		// if !to.Equal(toAddress[i]) {
		// 	t.Fatalf("Failed to convert public key to address: %v", err)
		// }

		signer := types.LatestSigner(PARAMS)

		wsClient, err := ethclient.Dial(wsUrl[i])
		if err != nil {
			t.Fatalf("Failed to connect to the Ethereum WebSocket client: %v", err)
		}
		defer wsClient.Close()

		nonce, err := wsClient.NonceAt(context.Background(), from, nil)

		if err != nil {
			t.Error(err.Error())
			t.Fail()
		}

		inner_tx := types.QuaiTx{ChainID: PARAMS.ChainID, Nonce: nonce, GasTipCap: MINERTIP, GasFeeCap: BASEFEE, Gas: GAS * 3, To: &to, Value: VALUE, Data: nil, AccessList: types.AccessList{}}
		tx := types.NewTx(&inner_tx)

		tx, err = types.SignTx(tx, signer, privKey[i])
		if err != nil {
			t.Error(err.Error())
			t.Fail()
		}

		t.Log(tx.Hash().String())

		err = wsClient.SendTransaction(context.Background(), tx)
		if err != nil {
			t.Error(err.Error())
			t.Fail()
		}

	}
}

func TestGetBalance(t *testing.T) {
	wsUrl := "ws://localhost:8100"
	wsUrlCyprus2 := "ws://localhost:8101"
	wsClientCyprus1, err := ethclient.Dial(wsUrl)
	if err != nil {
		t.Fatalf("Failed to connect to the Ethereum WebSocket client: %v", err)
	}
	defer wsClientCyprus1.Close()

	balance, err := wsClientCyprus1.BalanceAt(context.Background(), common.HexToAddress("0x0047f9CEa7662C567188D58640ffC48901cde02a", common.Location{0, 0}), nil)
	if err != nil {
		t.Error(err.Error())
		t.Fail()
	}
	t.Log(balance)

	wsClientCyprus2, err := ethclient.Dial(wsUrlCyprus2)
	if err != nil {
		t.Fatalf("Failed to connect to the Ethereum WebSocket client: %v", err)
	}
	defer wsClientCyprus2.Close()

	balance, err = wsClientCyprus2.BalanceAt(context.Background(), common.HexToAddress("0x01736f9273a0dF59619Ea4e17c284b422561819e", common.Location{0, 1}), nil)
	if err != nil {
		t.Error(err.Error())
		t.Fail()
	}
	t.Log(balance)
}

func TestSmartContract(t *testing.T) {
	client, err := ethclient.Dial("ws://127.0.0.1:8100")
	if err != nil {
		t.Fatalf("Failed to connect to the Ethereum WebSocket client: %v", err)
	}
	defer client.Close()

	fromAddress := common.HexToAddress("0x000D8BfADBF40241101c430D25151D893c6b16D8", location)
	privKey, err := crypto.ToECDSA(common.FromHex("0x383bd2269958a23e0391be01d255316363e2fa22269cbdc48052343346a4dcd8"))
	if err != nil {
		t.Fatalf("Failed to convert private key to ECDSA: %v", err)
	}

	// Check balance
	balance, err := client.BalanceAt(context.Background(), fromAddress, nil)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("Balance of %s: %s nonce: %d\n", fromAddress.String(), balance.String(), nonce)

	// Deploy QXC contract with the proper address that gives me tokens in zone 0-0
	contract, err := hex.DecodeString(sha)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	i := uint8(0)
	contract = append(contract, i)
	var contractAddr common.Address
	// Grind contract address
	for {
		contract[len(contract)-1] = i
		contractAddr = crypto.CreateAddress(fromAddress, nonce, contract, location)
		if common.IsInChainScope(contractAddr.Bytes(), location) {
			break
		}
		i++
	}
	fmt.Println("Contract address: ", contractAddr.String())
	fmt.Println("Took ", i, " iterations to find contract address")

	signer := types.LatestSigner(PARAMS)

	// Construct deployment tx
	inner_tx := types.QuaiTx{ChainID: PARAMS.ChainID, Nonce: nonce, GasTipCap: MINERTIP, GasFeeCap: big.NewInt(50000), Gas: 5000000, To: nil, Value: common.Big0, Data: contract}
	tx, err := types.SignTx(types.NewTx(&inner_tx), signer, privKey)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	gas, err := client.EstimateGas(context.Background(), quai.CallMsg{From: fromAddress /*To: nil, Gas: 0, GasPrice: MAXFEE, GasFeeCap: MAXFEE, GasTipCap: MINERTIP, Value: common.Big0, */, Data: contract, AccessList: inner_tx.AccessList})
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("gas: ", gas)
	protoTx, err := tx.ProtoEncode()
	if err != nil {
		return
	}
	data, err := proto.Marshal(protoTx)
	if err != nil {
		return
	}
	fmt.Printf("%+v\n", data)
	err = client.SendTransaction(context.Background(), tx)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("tx: ", tx.Hash().String())
	fmt.Println(crypto.Keccak256(data))
	fmt.Println("tx value: ", tx.Value().String())
	//time.Sleep(5 * time.Second) // Wait for it to be mined
	newtx, isPending, err := client.TransactionByHash(context.Background(), tx.Hash())
	fmt.Println("newtx value: ", newtx.Value().String())
	newProtoTx, err := newtx.ProtoEncode()
	if err != nil {
		return
	}
	data_, err := proto.Marshal(newProtoTx)
	if err != nil {
		return
	}
	fmt.Printf("%+v\n", data_)
	fmt.Println("tx: ", newtx.Hash().String())
	fmt.Printf("tx: %+v isPending: %v err: %v\n", tx, isPending, err)
	receipt, err := client.TransactionReceipt(context.Background(), tx.Hash())
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("Receipt: %+v\n", receipt)
	contractAddr = receipt.ContractAddress

	// Check balance in zone 0-0
	sig := crypto.Keccak256([]byte("testSha()"))[:4]
	data = make([]byte, 0, 0)
	data = append(data, sig...)
	/*from_, err := uint256.FromHex(fromAddress.Hex())
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	temp := from_.Bytes32()
	data = append(data, temp[:]...)*/

	data, err = client.CallContract(context.Background(), interfaces.CallMsg{To: &contractAddr, Data: data}, nil)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("Balance of %s: %s\n", fromAddress.String(), new(big.Int).SetBytes(data).String())

}
