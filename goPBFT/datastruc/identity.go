package datastruc

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"log"
)

type PeerIdentity struct {
	PubKey string
	IpAddr string
}

func ConfigSerialize(config []PeerIdentity) []byte {
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(config)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	return content
}

func ConfigDeSerialize(content []byte) []PeerIdentity {
	var config []PeerIdentity
	var buff bytes.Buffer
	buff.Write(content)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(config)
	if err != nil {
		log.Panic(err)
	}
	return config

}

func (peerid PeerIdentity) Lessthan (peerid2 PeerIdentity) bool {
	var p1hash [32]byte
	var p2hash [32]byte
	p1hash = sha256.Sum256(peerid.Serialize())
	p2hash = sha256.Sum256(peerid2.Serialize())

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

func (peerid PeerIdentity) Serialize() []byte {
	var encoded bytes.Buffer

	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(peerid)
	if err != nil {
		log.Panic(err)
	}

	return encoded.Bytes()
}