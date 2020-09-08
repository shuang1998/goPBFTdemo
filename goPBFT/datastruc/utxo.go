package datastruc

import (
	"bytes"
	"crypto/elliptic"
	"encoding/gob"
	"log"
	"fmt"
)

type UTXOSet struct {
	Set []UTXO
}

type UTXO struct {
	Tx Transaction
	Pubkey string
	Value int
}

// utxo id is the transaction and the pubkey
type UtxoId struct {
	id [32]byte
	pubkey string
}

func (utoxset *UTXOSet) UpdateUtxoSetFromBlock(block *Block) {
	// delete used utxo, add new utxo according to the block information
	newUtxos1 := []UTXO{}
	for _, utxo := range utoxset.Set {
		res := utxoIsUsed(&utxo, &block.TransactionList)
		if !res {
			newUtxos1 = append(newUtxos1, utxo)
		}
	}

	newUtxos2 := []UTXO{}
	for _, tx := range block.TransactionList {
		for _, out := range tx.Vout {
			newUtxos2 = append(newUtxos2, UTXO{tx, out.PubKey, out.Value})
		}
	}
	newUtxos := append(newUtxos1, newUtxos2...)
	utoxset.Set = newUtxos
}

func (utxoset *UTXOSet) UpdateUtxoSetFromCoinbaseTxs(txs *[]Transaction) {
	res := []UTXO{}
	for _, tx := range *txs {
		if tx.Kind == "coinbase" {
			pub := tx.Vout[0].PubKey
			value := tx.Vout[0].Value
			res = append(res, UTXO{tx, pub, value})
		}
	}
	utxoset.Set = res
}

func utxoIsUsed(utxo *UTXO, txList *[]Transaction) bool {
	for _, tx := range *txList {
		for _, input := range tx.Vin {
			if twoHashEqual(input.Txid, utxo.Tx.ID) {
				if utxo.Pubkey == input.PubKey {
					return true
				}
			}
		}
	}
	return false
}

func (utxo UTXO) Serialize() []byte {
	var encoded bytes.Buffer

	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(utxo)
	if err != nil {
		log.Panic(err)
	}

	return encoded.Bytes()
}

func (utxo *UTXO) Deserialize(conten []byte) {
	var buff bytes.Buffer
	buff.Write(conten)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(utxo)
	if err!=nil {
		fmt.Println("decoding error")
	}
}

func (utxoset *UTXOSet) IncludeTheUtxo(theutxo UTXO) bool {
	for _, utxo := range utxoset.Set {
		if twoHashEqual(utxo.Tx.GetHash(), theutxo.Tx.GetHash()) {
			if utxo.Pubkey==theutxo.Pubkey {
				return true
			}
		}
	}
	return false
}

func twoHashEqual(a [32]byte, b [32]byte) bool {
	for i:=0; i<32; i++ {
		if a[i]!=b[i] {
			return false
		}
	}
	return true
}