package main

import (
	"time"
)
import "fmt"
import "./networkx"

func main() {
	member := []string{"127.0.0.1:8000", "127.0.0.1:8001", "127.0.0.1:8002", "127.0.0.1:8003"}
	for i:=0; i<len(member); i++ {
		pbftinstance := networkx.MakePeer(member[i], member)
		go pbftinstance.Initialize()
	}

	time.Sleep(300*time.Second)
	fmt.Println("main finished")
}