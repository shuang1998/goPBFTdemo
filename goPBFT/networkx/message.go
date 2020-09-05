package networkx

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"log"
	"math/big"
	mrand "math/rand"
)

type PariSign struct {
	R *big.Int
	S *big.Int
}

type PrePrepareMsg struct {
	View int
	Order int
	Digest int
	Pubkey string
	Sig PariSign
}

type PrepareMsg struct {
	View int
	Order int
	Digest int
	Pubkey string
	Sig PariSign
}

type CommitMsg struct {
	View int
	Order int
	Digest int
	Pubkey string
	Sig PariSign
}

type ViewChangeMsg struct {
	View int
	Pubkey string

	LastBHeight int // checkpoint
	LockedHeight int

	Sig PariSign
}


type NewViewMsg struct {
	View int
	Pubkey string

	CKpoint int
	VCMsgSet []ViewChangeMsg
	PPMsgSet []PrePrepareMsg
	Sig PariSign
}



type PrepareQC struct {
	PrepareMsgSet []PrepareMsg
}

type CommitQC struct {
	CommitMsgSet []CommitMsg
}

func NewPreprepareMsg(view int, order int, pubkeystr string, prvkey *ecdsa.PrivateKey) PrePrepareMsg {
	prepreparemsg := PrePrepareMsg{}
	prepreparemsg.View = view
	prepreparemsg.Order = order
	prepreparemsg.Digest = mrand.Intn(1000)

	datatosign := string(prepreparemsg.View) + "," + string(prepreparemsg.Order) + "," + string(prepreparemsg.Digest)
	prepreparemsg.Sig.Sign([]byte(datatosign), prvkey)
	prepreparemsg.Pubkey = pubkeystr
	return prepreparemsg
}

func NewPrepareMsg(view int, order int, digest int, pubkeystr string, prvkey *ecdsa.PrivateKey) PrepareMsg {
	preparemsg := PrepareMsg{}
	preparemsg.View = view
	preparemsg.Order = order
	preparemsg.Digest = digest

	datatosign := string(preparemsg.View) + "," + string(preparemsg.Order) + "," + string(preparemsg.Digest)
	preparemsg.Sig.Sign([]byte(datatosign), prvkey)
	preparemsg.Pubkey = pubkeystr
	return preparemsg
}

func NewCommitMsg(view int, order int, digest int, pubkeystr string, prvkey *ecdsa.PrivateKey) CommitMsg {
	commitmsg := CommitMsg{}
	commitmsg.View = view
	commitmsg.Order = order
	commitmsg.Digest = digest

	datatosign := string(commitmsg.View) + "," + string(commitmsg.Order) + "," + string(commitmsg.Digest)
	commitmsg.Sig.Sign([]byte(datatosign), prvkey)
	commitmsg.Pubkey = pubkeystr
	return commitmsg
}

func NewViewChangeMsg(view int, pubkey string, ckpheigh int, lockheigh int, prvkey *ecdsa.PrivateKey) ViewChangeMsg {
	vcmsg := ViewChangeMsg{}
	vcmsg.View = view
	vcmsg.Pubkey = pubkey
	vcmsg.LastBHeight = ckpheigh
	vcmsg.LockedHeight = lockheigh

	datatosign := string(vcmsg.View) + "," + vcmsg.Pubkey + "," + string(vcmsg.LastBHeight) + "," + string(vcmsg.LockedHeight)
	vcmsg.Sig.Sign([]byte(datatosign), prvkey)
	return vcmsg
}

func NewNewViewMsg(view int, pubkey string, vcset []ViewChangeMsg, prvkey *ecdsa.PrivateKey) NewViewMsg {
	nvmsg := NewViewMsg{}
	nvmsg.View = view
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

	datatosign := sha256.Sum256(nvmsg.Serialize())
	nvmsg.Sig.Sign(datatosign[:], prvkey)
	nvmsg.Pubkey = pubkey
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

func (nvmsg NewViewMsg) Serialize() []byte {
	var encoded bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(nvmsg)
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

func (a *PariSign) Sign(b []byte, prk *ecdsa.PrivateKey) {
	a.R = new(big.Int)
	a.S = new(big.Int)
	a.R, a.S, _ = ecdsa.Sign(rand.Reader, prk, b)
}

func (a *PariSign) Verify(b []byte, puk *ecdsa.PublicKey) bool {
	return ecdsa.Verify(puk, b, a.R, a.S)
}

func takemax(a, b int) int {
	res := a
	if b>a {
		res = b
	}
	return res
}