package datastruc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log"
	"math/rand"
	"fmt"
)

const KeyNumber = 10

type KeyPair struct {
	publicKey  *ecdsa.PublicKey
	privateKey *ecdsa.PrivateKey
}

type Wallet struct {

	WalletKeyList			[]KeyPair
	MainPubKey string
	MainPriKey string

	pubKeyToPriKey map[string]string
	priKeyToPubKey map[string]string
	Utxos UTXOSet
	UsedUtxo map[UtxoId]int
}

func (wallet *Wallet) Initialize() {
	wallet.WalletKeyList = []KeyPair{}
	wallet.pubKeyToPriKey = make(map[string]string)
	wallet.priKeyToPubKey = make(map[string]string)
	wallet.Utxos = UTXOSet{}
	wallet.UsedUtxo = make(map[UtxoId]int)

	wallet.GenerateKeys()
}

func (wallet *Wallet) GenerateKeys() {
	accountKeyList := []KeyPair{}
	for i:=0; i<KeyNumber; i++ {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
		if err != nil {
			log.Fatalln(err)
		}
		publicKey := &privateKey.PublicKey
		keypair := KeyPair{publicKey,privateKey }
		accountKeyList = append(accountKeyList, keypair)
		privateString := EncodePrivate(keypair.privateKey)
		publicString := EncodePublic(keypair.publicKey)
		wallet.pubKeyToPriKey[publicString] = privateString
		wallet.priKeyToPubKey[privateString] = publicString
	}
	wallet.WalletKeyList = accountKeyList
	wallet.MainPubKey = EncodePublic(wallet.WalletKeyList[0].publicKey)
	wallet.MainPriKey = EncodePrivate(wallet.WalletKeyList[0].privateKey)
}


func (wallet *Wallet) GetRandomPubkey() string {
	x := rand.Intn(len(wallet.WalletKeyList))
	return EncodePublic(wallet.WalletKeyList[x].publicKey)
}

func (wallet *Wallet) FindSpendableOutputs(target int) (int, []UTXO) {
	amount := 0
	spendableUtxo := []UTXO{}

	for _, utxo := range wallet.Utxos.Set {
		//fmt.Println("check if the first utxo is used")
		tmpkey := UtxoId{utxo.Tx.ID, utxo.Pubkey}
		if _, ok := wallet.UsedUtxo[tmpkey]; !ok {
			if wallet.PubkeyBelongsWallet(utxo.Pubkey) {
				spendableUtxo = append(spendableUtxo, utxo)
				amount += utxo.Value
				if amount>target {
					break
				}
			}
		}
	}
	return amount, spendableUtxo
}

func (wallet *Wallet) UpdateWallet(pendingUTXOSet *UTXOSet) {
	utxolist := []UTXO{}
	for _, utxo := range pendingUTXOSet.Set {
		if wallet.OwntheUtxo(&utxo) {
			utxolist = append(utxolist, utxo)
		}
	}
	wallet.Utxos.Set = utxolist
}

func (wallet *Wallet) OwntheUtxo(theutxo *UTXO) bool {
	if wallet.PubkeyBelongsWallet(theutxo.Pubkey) {
		return true
	}
	return false
}


func (wallet *Wallet) PubkeyBelongsWallet(thepubkey string) bool {
	for _, key := range wallet.WalletKeyList {
		if thepubkey == EncodePublic(key.publicKey) {
			return true
		}
	}
	return false
}


func (wallet *Wallet) NewTransaction(topubk string, target int) (bool, Transaction) {
	var inputs []TXInput
	var outputs []TXOutput
	var validOutputs []UTXO
	var acc int

	acc, validOutputs = wallet.FindSpendableOutputs(target)
	if len(validOutputs) == 0 {
		//fmt.Println("has no valid utxo")
		return false, Transaction{}
	}
	if acc<target {
		fmt.Println("not enough balance")
		return false, Transaction{}
	}

	for _, utxo := range validOutputs {
		tmpkey := UtxoId{utxo.Tx.ID, string(utxo.Pubkey)}
		if _, ok := wallet.UsedUtxo[tmpkey]; !ok {
			txID := utxo.Tx.ID
			public := utxo.Pubkey
			input := TXInput{txID, PariSign{}, public}
			inputs = append(inputs, input)
			wallet.UsedUtxo[tmpkey] = 1
		}
	}

	outputs = append(outputs, TXOutput{target, topubk})
	if acc>target {
		// TODO, use random number additional address to receive
		outputs = append(outputs, TXOutput{acc-target, wallet.GetRandomPubkey()})
	}

	tx := Transaction{"normal",[32]byte{}, inputs, outputs}
	tx.ID = tx.GetHash()
	wallet.SignTransaction(&tx)
	return true, tx

}

func (wallet *Wallet) SignTransaction(tx *Transaction) {
	for i, txinput := range tx.Vin {
		publickey := txinput.PubKey
		privatekey := DecodePrivate(wallet.pubKeyToPriKey[publickey])
		datatosign := txinput.Txid[:]
		tx.Vin[i].Sig.Sign(datatosign, privatekey)
	}
}

func EncodePrivate(privateKey *ecdsa.PrivateKey) string {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	return string(pemEncoded)
}


func EncodePublic(publicKey *ecdsa.PublicKey) string {
	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
	return string(pemEncodedPub)
}



func DecodePrivate(pemEncoded string) *ecdsa.PrivateKey {
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)
	return privateKey
}

func DecodePublic(pemEncodedPub string) *ecdsa.PublicKey {
	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)
	return publicKey
}