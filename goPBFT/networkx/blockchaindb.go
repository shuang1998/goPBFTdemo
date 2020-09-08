package networkx

import (
	"../datastruc"
	"log"
	"os"
	"github.com/boltdb/bolt"
	"fmt"
	"strconv"
)

const BucketHeightToHash = "BucketHeightToHash"
const BucketHashToBlock = "BucketHashToBlock"
const BucketNumToConfig = "BucketNumToConfig"
const BucketCurUTXO = "BucketCurUTXO"
const BucketMarginalInfo = "BucketMarginalInfo"
const BucketPrepareQC = "BucketPrepareQC"
const BucketCommitQC = "BucketCommiQC"

type BlockChainDB struct {
	FileName string
	LastBHash [32]byte
	Height int
	CommitQC []byte

	PreparedHeight int
	PreparedHash [32]byte
	PreparedQC []byte
}

func CreateBlockchainDB(filename string, genesis datastruc.Block) {
	if dbExists(filename) {
		fmt.Println("Blockchain ", filename, " already exists.")
		os.Exit(1)
	}
	db, err := bolt.Open(filename, 0600, nil)
	if err!=nil {
		log.Panic(err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		// bucket, height to block's hash

		// bucket, marginal information
		b, err := tx.CreateBucket([]byte(BucketMarginalInfo))
		b.Put([]byte("commitHeight"), []byte(strconv.Itoa(0)))
		b.Put([]byte("recentConfigVer"), []byte(strconv.Itoa(0)))
		if err != nil {
			log.Panic(err)
		}

		// bucket, height to blockhash
		b, err = tx.CreateBucket([]byte(BucketHeightToHash))
		hashvalue := genesis.Hash
		b.Put([]byte("0"), hashvalue[:])

		// bucket, hash to block
		b, err = tx.CreateBucket([]byte(BucketHashToBlock))
		b.Put(hashvalue[:], genesis.GetSerialize())


		// bucket, number to config
		b, err = tx.CreateBucket([]byte(BucketNumToConfig))
		b.Put([]byte("0"), datastruc.ConfigSerialize(genesis.Configure))

		// bucket, hash to tx, including unspent and spent
		b, err = tx.CreateBucket([]byte(BucketCurUTXO))
		for _, tx := range genesis.TransactionList {
			pub := tx.Vout[0].PubKey
			value := tx.Vout[0].Value
			theutxo :=  datastruc.UTXO{tx, pub, value}
			b.Put(theutxo.Serialize(), []byte("true"))
		}

		b, err = tx.CreateBucket([]byte(BucketPrepareQC))
		b, err = tx.CreateBucket([]byte(BucketCommitQC))

		return nil
	})

	if err := db.Close(); err != nil {
		log.Fatal(err)
	}
}

func UpdateBlockchainDBAfterPrepare(filename string, heigh int, ver int, blockhash [32]byte, prepareqc PrepareQC) {
	db, err := bolt.Open(filename, 0600, nil)
	if err!=nil {
		log.Panic(err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketMarginalInfo))
		b.Put([]byte("preparedHeight"), []byte(strconv.Itoa(heigh)))

		b = tx.Bucket([]byte(BucketPrepareQC))
		b.Put(blockhash[:], prepareqc.Serialize())
		return nil
	})

	if err := db.Close(); err != nil {
		log.Fatal(err)
	}
}


func UpdateBlockchainDBAfterCommit(filename string, heigh int, ver int, block *datastruc.Block, curUtxo *datastruc.UTXOSet, commitqc CommitQC) {
	db, err := bolt.Open(filename, 0600, nil)
	if err!=nil {
		log.Panic(err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketMarginalInfo))
		b.Put([]byte("commitHeight"), []byte(strconv.Itoa(heigh)))

		b = tx.Bucket([]byte(BucketHeightToHash))
		b.Put([]byte(strconv.Itoa(heigh)), block.Hash[:])

		b = tx.Bucket([]byte(BucketHashToBlock))
		b.Put(block.Hash[:], block.GetSerialize())

		// TODO, config

		err = tx.DeleteBucket([]byte(BucketCurUTXO))
		b, err = tx.CreateBucket([]byte(BucketCurUTXO))
		if err!=nil {
			log.Panic(err)
		}
		for _, utxo := range curUtxo.Set {
			b.Put(utxo.Serialize(), []byte("true"))
		}

		b = tx.Bucket([]byte(BucketCommitQC))
		b.Put(block.Hash[:], commitqc.Serialize())

		return nil
	})

	if err := db.Close(); err != nil {
		log.Fatal(err)
	}
}


func dbExists(dbFile string) bool {
	if _, err := os.Stat(dbFile); os.IsNotExist(err) {
		return false
	}

	return true
}