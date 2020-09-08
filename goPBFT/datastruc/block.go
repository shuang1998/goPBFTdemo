package datastruc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/gob"
	"log"
	"strconv"
	"fmt"
)

const BlockVolume = 20

type Block struct {
	Kind string
	View int
	Height int

	PrevHash [32]byte
	MerkleTreeHash [32]byte

	TransactionList []Transaction
	Configure []PeerIdentity

	Hash [32]byte
	PubKey string
	Sig PariSign
}

func NewBlock(pubkeystr string, prvkey *ecdsa.PrivateKey, txlist *TXSet, height int, view int, prevhash [32]byte) Block {
	bloc := Block{}
	bloc.Kind = "txblock"
	bloc.Height = height
	bloc.PrevHash = prevhash

	bloc.TransactionList = []Transaction{}
	txpool := &(txlist.Txs)
	bloc.fetchTransactionForBlock(txpool)

	err := GenMerkTree(&bloc.TransactionList, &bloc.MerkleTreeHash)
	if err != nil {
		fmt.Println("error in generating merkle tree")
	}
	bloc.Configure = []PeerIdentity{}

	datatosign := []byte(bloc.Kind + "," + strconv.Itoa(bloc.View) + "," + strconv.Itoa(bloc.Height) + "," + string(bloc.PrevHash[:]) + ","  + string(bloc.MerkleTreeHash[:]))
	var hashtosign [32]byte
	SingleHash256(&datatosign, &hashtosign)
	bloc.Hash = hashtosign
	bloc.Sig.Sign(hashtosign[:], prvkey)
	bloc.PubKey = pubkeystr

	return bloc
}

func ConstructGenesisBlock(coinbtxs *[]Transaction, config []PeerIdentity) Block {
	geneb := Block{}
	geneb.Kind = "geblock"
	geneb.View = 0
	geneb.Height = 0
	geneb.PrevHash = [32]byte{}
	geneb.TransactionList = *coinbtxs
	err := GenMerkTree(&geneb.TransactionList, &geneb.MerkleTreeHash)
	if err != nil {
		fmt.Println("error in generating merkle tree")
	}
	geneb.Configure = config

	geneb.Sig = PariSign{} // genesis block has no creator, thus no signature
	geneb.PubKey = "" // genesis block has no creator, thus no public key
	return geneb
}

func (block *Block) fetchTransactionForBlock(txpool *[]Transaction) {
	res := []Transaction{}
	for i:=0; i<takemin(BlockVolume, len(*txpool)); i++ {
		if i<len(*txpool) {
			res = append(res, (*txpool)[i])
		} else {
			break
		}
	}
	block.TransactionList = res
}

func (block *Block) IncludeTheTx(thetx *Transaction) bool {
	for _, tx := range block.TransactionList {
		if twoHashEqual(thetx.GetHash(), tx.GetHash()) {
			return true
		}
	}
	return false
}

func (block *Block) GetSerialize() []byte {
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(block)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	return content

}

func GenMerkTree(d *[]Transaction, out *[32]byte) error {
	if len(*d) == 0 {
		return nil
	}
	if len(*d) == 1 {
		tmp := (*d)[0].ID[:]
		SingleHash256(&tmp, out)
	} else {
		l := len(*d)
		d1 := (*d)[:l/2]
		d2 := (*d)[l/2:]
		var out1, out2 [32]byte
		GenMerkTree(&d1, &out1)
		GenMerkTree(&d2, &out2)
		tmp := append(out1[:], out2[:]...)
		SingleHash256(&tmp, out)
	}
	return nil
}

func (bloc *Block) GetHash() [32]byte {
	var hash [32]byte
	data := []byte(bloc.Kind + "," + strconv.Itoa(bloc.View) + "," + strconv.Itoa(bloc.Height) + "," + string(bloc.PrevHash[:]) + ","  + string(bloc.MerkleTreeHash[:]))
	hash = sha256.Sum256(data)
	return hash
}

func SingleHash256(a *[]byte, b *[32]byte) {
	*b = sha256.Sum256(*a)
	//*b = sha256.Sum256(tmp[:])
}

func takemin(a, b int) int {
	res := a
	if b<a {
		res = b
	}
	return res
}