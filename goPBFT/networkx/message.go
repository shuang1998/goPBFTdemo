package networkx

import (
	"bytes"
	"crypto/elliptic"
	"encoding/gob"
	"fmt"
	"log"
	"math/rand"
)

type PrePrepareMsg struct {
	View int
	Order int
	Request int
	Pubkey string
}

type PrepareMsg struct {
	View int
	Order int
	Pubkey string
}

type CommitMsg struct {
	View int
	Order int
	Pubkey string
}

type ViewChangeMsg struct {
	View int
	Pubkey string

	LastBHeight int // checkpoint
	LockedHeight int
}


type NewViewMsg struct {
	View int
	Pubkey string

	CKpoint int
	VCMsgSet []ViewChangeMsg
	PPMsgSet []PrePrepareMsg
}



type PrepareQC struct {
	PrepareMsgSet []PrepareMsg
}

type CommitQC struct {
	CommitMsgSet []CommitMsg
}

func NewPreprepareMsg(view int, order int, pubkey string) PrePrepareMsg {
	prepreparemsg := PrePrepareMsg{}
	prepreparemsg.View = view
	prepreparemsg.Order = order
	prepreparemsg.Request = rand.Intn(1000)
	prepreparemsg.Pubkey = pubkey
	return prepreparemsg
}

func NewPrepareMsg(view int, order int, pubkey string) PrepareMsg {
	preparemsg := PrepareMsg{}
	preparemsg.View = view
	preparemsg.Order = order
	preparemsg.Pubkey = pubkey
	return preparemsg
}

func NewCommitMsg(view int, order int, pubkey string) CommitMsg {
	commitmsg := CommitMsg{}
	commitmsg.View = view
	commitmsg.Order = order
	commitmsg.Pubkey = pubkey
	return commitmsg
}

func NewViewChangeMsg(view int, pubkey string, ckpheigh int, lockheigh int) ViewChangeMsg {
	vcmsg := ViewChangeMsg{}
	vcmsg.View = view
	vcmsg.Pubkey = pubkey
	vcmsg.LastBHeight = ckpheigh
	vcmsg.LockedHeight = lockheigh
	return vcmsg
}

func NewNewViewMsg(view int, pubkey string, vcset []ViewChangeMsg) NewViewMsg {
	nvmsg := NewViewMsg{}
	nvmsg.View = view
	nvmsg.Pubkey = pubkey
	nvmsg.VCMsgSet = vcset

	// calculate nvmsg.PPMsgSet
	nvmsg.PPMsgSet = []PrePrepareMsg{}
	// first, find the maximum block height
	// then, get the locked hash
	max_s := 0 // the latest checkpoint
	lockedheigh := 0 // height for the locked(prepared) block
	for _, vcmsg := range vcset {
		max_s = takemax(max_s, vcmsg.LastBHeight)
	}
	nvmsg.CKpoint = max_s
	for _, vcmsg := range nvmsg.VCMsgSet {
		if max_s == vcmsg.LastBHeight {
			if vcmsg.LockedHeight>max_s {
				lockedheigh = vcmsg.LockedHeight
			}
		}
	}

	// construct the new pre-prepare msg for the locked hash(block)
	if lockedheigh>0 {
		prepremsg := PrePrepareMsg{}
		prepremsg.View = view
		prepremsg.Order = lockedheigh
		prepremsg.Pubkey = pubkey

		nvmsg.PPMsgSet = append(nvmsg.PPMsgSet, prepremsg)
	}

	return nvmsg
}



func (prepreparemsg PrePrepareMsg) Serialize() []byte {
	var encoded bytes.Buffer

	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(prepreparemsg)
	if err != nil {
		log.Panic(err)
	}

	return encoded.Bytes()
}

func (preparemsg PrepareMsg) Serialize() []byte {
	var encoded bytes.Buffer

	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(preparemsg)
	if err != nil {
		log.Panic(err)
	}

	return encoded.Bytes()
}

func (commitmsg CommitMsg) Serialize() []byte {
	var encoded bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(commitmsg)
	if err != nil {
		log.Panic(err)
	}

	return encoded.Bytes()
}


func (prepareqc *PrepareQC) Serialize() []byte {
	var encoded bytes.Buffer
	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(*prepareqc)
	if err != nil {
		log.Panic(err)
	}
	return encoded.Bytes()
}

func (prepareqc *PrepareQC) Deserialize(conten []byte) {
	var buff bytes.Buffer
	var theqc PrepareQC
	buff.Write(conten)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&theqc)
	if err != nil {
		log.Panic(err)
	}
	prepareqc.PrepareMsgSet = theqc.PrepareMsgSet
}

func (commitqc *CommitQC) Serialize() []byte {
	var encoded bytes.Buffer
	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(*commitqc)
	if err != nil {
		log.Panic(err)
	}
	return encoded.Bytes()
}

func (commitqc *CommitQC) Deserialize(conten []byte) {
	var buff bytes.Buffer
	buff.Write(conten)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&commitqc)
	if err != nil {
		fmt.Println("decoding error")
		log.Panic(err)
	}
}

func takemax(a, b int) int {
	res := a
	if b>a {
		res = b
	}
	return res
}