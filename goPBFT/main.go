package main

import (
	"github.com/boltdb/bolt"
	"log"
	"os"
	"strconv"
	"fmt"
	"time"
	"./networkx"
)


func main() {
	member := []string{"127.0.0.1:8000", "127.0.0.1:8001", "127.0.0.1:8002", "127.0.0.1:8003"}
	for i:=0; i<len(member); i++ {
		pbftinstance := networkx.MakePeer(member[i], member)
		go pbftinstance.Initialize()
	}

	time.Sleep(40*time.Second)
	fmt.Println("main finished")

	start := 0
	end := 4
	for i:=start; i<end; i++ {

		dbFile := fmt.Sprintf("blockchain_%s.db", strconv.Itoa(i))
		db, err := bolt.Open(dbFile, 0666, nil)
		defer os.Remove(db.Path())
		if err != nil {
			log.Fatal(err)
		}
		db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("BucketMarginalInfo"))
			b.ForEach(func(k, v []byte) error {
				//fmt.Printf("key=%s, value=%s\n", k, v)
				vv, _ := strconv.Atoi(string(v))
				fmt.Println("key = ", string(k), " value = ", vv)
				return nil
			})
			//v := b.Get([]byte("recentHeight"))
			//x, _ := strconv.Atoi(string(v))
			//fmt.Println(x)
			return nil
		})
		fmt.Println(db)

		if err := db.Close(); err != nil {
			log.Fatal(err)
		}
		fmt.Println("\n")
	}
}