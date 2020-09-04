package networkx

import (
	"bytes"
	"encoding/gob"
	"log"
	"../datastruc"
)

type QueryForBlockMsg struct {
	Localheight int
	Pubkey string
}

type ReplyForQueryMsg struct {
	Height int
	RequestNum int
	ViewList []int
	RequestList []int
	Pubkey string
}

func NewQueryLostDataMsg(pubkey string, localheigh int) QueryForBlockMsg {
	qforb := QueryForBlockMsg{}
	qforb.Localheight = localheigh
	qforb.Pubkey = pubkey
	return qforb
}



func ReplyLost(pubkey string, localheight int, queryheigh int, remoteaddr string, viewlist []int, requestlist []int) {

	newrfq := NewReplyForQuery(pubkey, localheight, queryheigh, viewlist, requestlist)
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(newrfq)
	if err!=nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	comman := commandToBytes("replylost")
	content = append(comman, content...)
	go sendData(content, remoteaddr)
	//fmt.Println(extractNodeID(pbft.nodeIPAddress), "has finished reply msg sending to", remoteaddr)
}

func NewReplyForQuery(pubkey string, localheight int, queryheigh int, viewlist []int, requestlist []int) ReplyForQueryMsg {
	rforq := ReplyForQueryMsg{}
	rforq.Height = queryheigh
	rforq.RequestNum = localheight - queryheigh
	rforq.ViewList = viewlist
	rforq.RequestList = requestlist
	rforq.Pubkey = pubkey
	return rforq
}



func ExtractSenderIp(curConfigure []datastruc.PeerIdentity, sendAccount string) string {
	var senderip string
	for _, peer := range curConfigure {
		if peer.PubKey==sendAccount {
			senderip = peer.IpAddr
		}
	}
	return senderip
}