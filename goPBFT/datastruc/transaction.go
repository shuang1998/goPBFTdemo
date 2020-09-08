package datastruc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"log"
	"math/big"
)

type PariSign struct {
	R *big.Int
	S *big.Int
}

func (a *PariSign) Sign(b []byte, prk *ecdsa.PrivateKey) {
	a.R = new(big.Int)
	a.S = new(big.Int)
	a.R, a.S, _ = ecdsa.Sign(rand.Reader, prk, b)
}

func (a *PariSign) Verify(b []byte, puk *ecdsa.PublicKey) bool {
	return ecdsa.Verify(puk, b, a.R, a.S)
}

type Transaction struct {
	Kind string
	ID   [32]byte
	Vin  []TXInput
	Vout []TXOutput
}

type TXInput struct {
	Txid      [32]byte
	Sig PariSign
	PubKey    string
}

type TXOutput struct {
	Value      int
	PubKey string
}

type TXSet struct {
	Txs []Transaction
}

func (tx *Transaction) GetHash() [32]byte {
	var hash [32]byte
	txCopy := *tx
	txCopy.ID = [32]byte{}

	hash = sha256.Sum256(txCopy.Serialize())
	return hash
}

func (tx Transaction) Serialize() []byte {
	var encoded bytes.Buffer

	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(tx)
	if err != nil {
		log.Panic(err)
	}

	return encoded.Bytes()
}

func NewCoinbaseTransaction(topubkey string) Transaction {
	tx := Transaction{}
	tx.Kind = "coinbase"
	tx.Vin = []TXInput{}
	tx.Vout = []TXOutput{TXOutput{100, topubkey}}
	tx.ID = tx.GetHash()
	return tx
}

func (tx Transaction) IsCoinbase() bool {
	res := tx.Kind=="coinbase"
	return res
}

func SortTxs(txlist []Transaction) []Transaction {
	res := []Transaction{}
	for i:=0; i<len(txlist); i++ {
		if len(res)==0 {
			res = append(res, txlist[i])
		} else {
			thetx := txlist[i]
			lenn := len(res)
			var pos int
			var j int
			for j=0; j<lenn; j++ {
				if thetx.Lessthan(res[j]) {
					pos = j
					break
				}
			}
			if j<lenn {
				rear := append([]Transaction{}, res[pos:]...)
				head := append(res[:pos], thetx)
				res = append(head, rear...)
			} else {
				res = append(res, thetx)
			}
		}
	}
	return res
}

func (tx *Transaction) Verify() bool {
	if tx.IsCoinbase() {
		return true
	}
	for _, txinput := range tx.Vin {
		publickey := DecodePublic(txinput.PubKey)
		datatoverify := txinput.Txid[:]
		if !txinput.Sig.Verify(datatoverify, publickey) {
			return false
		}
	}
	return true
}


func (tx1 Transaction) Lessthan (tx2 Transaction) bool {

	p1hash := tx1.ID
	p2hash := tx2.ID

	i:=0
	for i<32 {
		if p1hash[i]<p2hash[i] {
			return true
		} else if p1hash[i]>p2hash[i] {
			return false
		} else {
			i++
		}
	}
	return false
}