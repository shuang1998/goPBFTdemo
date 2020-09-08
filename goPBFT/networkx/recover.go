package networkx

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/gob"
	"log"
	"../datastruc"
)

type QueryForBlockMsg struct {
	Localheight int
	Pubkey string
	Sig PariSign
}

type ReplyForQueryMsg struct {
	Height int
	RequestNum int
	ViewList []int
	BlockHashList [][32]byte
	Pubkey string
	Sig PariSign
}

func NewQueryLostDataMsg(pubkey string, localheigh int, prvkey *ecdsa.PrivateKey) QueryForBlockMsg {
	qforb := QueryForBlockMsg{}
	qforb.Localheight = localheigh
	qforb.Pubkey = pubkey
	datatosign := string(qforb.Localheight)
	qforb.Sig.Sign([]byte(datatosign), prvkey)
	return qforb
}

func ReplyLost(pubkey string, localheight int, queryheigh int, remoteaddr string, viewlist []int, BlockHashList [][32]byte, prvkey *ecdsa.PrivateKey) {

	newrfq := NewReplyForQuery(pubkey, localheight, queryheigh, viewlist, BlockHashList, prvkey)
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

func NewReplyForQuery(pubkey string, localheight int, queryheigh int, viewlist []int, BlockHashList [][32]byte, prvkey *ecdsa.PrivateKey) ReplyForQueryMsg {
	rforq := ReplyForQueryMsg{}
	rforq.Height = queryheigh
	rforq.RequestNum = localheight - queryheigh
	rforq.ViewList = viewlist
	rforq.BlockHashList = BlockHashList

	datatosign := rforq.Serialize()
	rforq.Sig.Sign([]byte(datatosign), prvkey)
	rforq.Pubkey = pubkey
	return rforq
}

func (rforq ReplyForQueryMsg) Serialize() []byte {
	var encoded bytes.Buffer

	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(rforq)
	if err != nil {
		log.Panic(err)
	}

	return encoded.Bytes()
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