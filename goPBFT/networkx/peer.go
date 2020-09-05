package networkx

import (
	"../datastruc"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/gob"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"sync"
	"time"
)

const protocol = "tcp"
const commandLength = 16
const TotalNumber = 4
const QuorumSize = 3
const ConsensusTimer = 5
const InauguratTimer = 60
const ScanInterval = 100
const ThreadExit = 5000

const (
	stat_consensus = iota
	stat_inaugurate
	stat_viewchange
	Unstarted
	Preprepared
	Prepared
	Commited
)

type persister struct {
	requestlist map[int]int
	logview map[int]int // height -> view
	commitedheight int
	preparedheight int

}

type progres struct {
	view int
	height int
}

type PBFT struct {
	mu sync.Mutex

	nodeIPAddress       string
	nodePubKey *ecdsa.PublicKey
	nodePrvKey *ecdsa.PrivateKey
	nodePubkeystr string
	nodePrvkeystr string
	minerIPAddress      []string
	minerPubKey         []string

	status int
	consenstatus int
	curleaderPubKeystr string
	curleaderIpAddr string

	prepreparedCh chan progres
	preparedCh chan progres
	committedCh chan progres
	vcmsgcollectedCh chan int
	inauguratedCh chan int

	recoverstate chan bool

	viewnumber 		int
	currentHeight 	int
	currequest int

	pre_preparelog map[int]PrePrepareMsg
	newviewlog map[int]NewViewMsg
	prepareVote map[int][]PrepareMsg
	commitVote map[int][]CommitMsg
	vcmsgset map[int][]ViewChangeMsg

	sentnewviewmsg map[int]bool
	hasRemainBInNVMsg bool
	preprepareMsgInNVMsg PrePrepareMsg



	curConfigure []datastruc.PeerIdentity
	succLine *datastruc.SuccLine

	recovStartView int
	recovStartHeight int

	persis persister
	recoverflag bool
}

func commandToBytes(command string) []byte {
	//command -> byte
	var bytees [commandLength]byte

	for i, c := range command {
		bytees[i] = byte(c)
	}

	return bytees[:]
}

func bytesToCommand(bytees []byte) string {
	//byte -> command
	var command []byte

	for _, b := range bytees {
		if b != 0x0 {
			command = append(command, b)
		}
	}

	return fmt.Sprintf("%s", command)
}

func MakePeer(addr string, memb []string) *PBFT {
	pbft := &PBFT{}
	pbft.nodeIPAddress = addr
	pbft.minerIPAddress = memb
	pbft.minerPubKey = []string{}

	pbft.status = stat_consensus
	pbft.consenstatus = Unstarted
	pbft.curleaderPubKeystr = ""

	pbft.viewnumber = 0
	pbft.currentHeight = 0

	pbft.pre_preparelog = map[int]PrePrepareMsg{}
	pbft.newviewlog = map[int]NewViewMsg{}
	pbft.prepareVote = map[int][]PrepareMsg{}
	pbft.commitVote = map[int][]CommitMsg{}
	pbft.vcmsgset = map[int][]ViewChangeMsg{}

	pbft.prepreparedCh = make(chan progres)
	pbft.preparedCh = make(chan progres)
	pbft.committedCh = make(chan progres)
	pbft.inauguratedCh = make(chan int)
	pbft.vcmsgcollectedCh = make(chan int)

	pbft.recoverstate = make(chan bool)

	pbft.sentnewviewmsg = map[int]bool{}
	pbft.hasRemainBInNVMsg = false
	pbft.preprepareMsgInNVMsg = PrePrepareMsg{}

	pbft.curConfigure = []datastruc.PeerIdentity{}
	pbft.recovStartView = 0
	pbft.recovStartHeight = 0
	pbft.persis = persister{}
	pbft.persis.logview = make(map[int]int)
	pbft.persis.requestlist = make(map[int]int)

	pbft.generatePubKeys()
	constructConfigure(&pbft.curConfigure, datastruc.PeerIdentity{pbft.nodePubkeystr, pbft.nodeIPAddress})

	return pbft
}

func (pbft *PBFT) Initialize() {
	go pbft.runServer()
	time.Sleep(time.Second*2)

	// initialization stage, find peer address and pubkey, build genesis block
	pbft.broadcastAddrPubKeyIp()
	time.Sleep(time.Second*2)

	time.Sleep(time.Second*2)
	pbft.currentHeight += 1
	pbft.consenstatus = Unstarted
	go pbft.run()
}

func (pbft *PBFT) run() {
RECOVERSTART:
	for {
		switch pbft.status {
		case stat_consensus:
			fmt.Print("node ", extractNodeID(pbft.nodeIPAddress)," now enters consensus stage in view ",pbft.viewnumber," in height ", pbft.currentHeight, "\n")
			if pbft.nodePubkeystr==pbft.curleaderPubKeystr {
				time.Sleep(2000*time.Millisecond)
				if pbft.hasRemainBInNVMsg==false {
					condi := pbft.currentHeight>=1116 && pbft.currentHeight%8==0 && (pbft.currentHeight/(pbft.viewnumber+1))==8
					if condi==false {
						fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "is leader, now broadcasts pre-prepare msg")
						go pbft.broadcastPreprepare(pbft.viewnumber, pbft.currentHeight, pbft.nodePrvKey)
					} else {
						fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "is leader, launches silence attack, does not broadcast pre-prepare msg")
					}
				} else {
					fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "is leader, dealing with pre-prepare msg in new-view msg")
					pbft.hasRemainBInNVMsg = false
				}
			}
			thetimer := time.NewTimer(time.Second*ConsensusTimer)
		consensus_loop:
			for {
				if pbft.consenstatus==Unstarted {
					go pbft.scanPreprepare(pbft.viewnumber, pbft.currentHeight, pbft.curleaderPubKeystr)
					condi := extractNodeID(pbft.nodeIPAddress)==13 && pbft.viewnumber==0 && pbft.currentHeight==5
					if condi {
						fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "scan Pre-prepare in view ",pbft.viewnumber," height ", pbft.currentHeight)
					}
				}
				select {
				case <- pbft.recoverstate:
					pbft.mu.Lock()
					view := pbft.viewnumber
					heigh := pbft.currentHeight
					pbft.mu.Unlock()
					fmt.Println("node", extractNodeID(pbft.nodeIPAddress), " goto RECOVERSTART in view ", view, " height ", heigh)
					goto RECOVERSTART
				case <- thetimer.C:
					fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "view-change timer expires in view ",pbft.viewnumber," height ", pbft.currentHeight)
					pbft.resetVariForViewChange()
					pbft.mu.Lock()
					view := pbft.viewnumber
					ckpheigh := pbft.persis.commitedheight
					lockheigh := pbft.persis.preparedheight
					pbft.mu.Unlock()
					fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "now broadcasts view-change msg, checkpoint height: ", ckpheigh, " prepare-locked height: ", lockheigh)
					go pbft.broadcastViewChange(view, ckpheigh, lockheigh)
					break consensus_loop
				case prog :=<- pbft.prepreparedCh:
					//fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "got pre-prepared signal in view ", prog.view, " height ", prog.height)
					pbft.mu.Lock()
					condi := extractNodeID(pbft.nodeIPAddress)==13 && pbft.viewnumber==0 && pbft.currentHeight==5
					if condi {
						fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "got the lock in height ", pbft.currentHeight, " and change consensus state to ", Prepared)
					}
					if prog.view==pbft.viewnumber && prog.height==pbft.currentHeight && pbft.consenstatus==Unstarted {
						pbft.consenstatus = Preprepared
						//fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "is pre-prepared in view ", pbft.viewnumber, " height ", pbft.currentHeight)
						go pbft.broadcastPrepare(pbft.viewnumber, pbft.currentHeight, pbft.currequest)
						go pbft.scanPrepare(pbft.viewnumber, pbft.currentHeight, pbft.currequest)
					}
					pbft.mu.Unlock()
				case prog :=<- pbft.preparedCh:
					pbft.mu.Lock()
					if prog.view==pbft.viewnumber && prog.height==pbft.currentHeight && pbft.consenstatus==Preprepared {
						pbft.consenstatus = Prepared
						pbft.persis.preparedheight = pbft.currentHeight
						fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "is prepared in view ", pbft.viewnumber, " height ", pbft.currentHeight)
						go pbft.broadcastCommit(pbft.viewnumber, pbft.currentHeight, pbft.currequest)
						go pbft.scanCommit(pbft.viewnumber, pbft.currentHeight, pbft.currequest)
					}
					pbft.mu.Unlock()
				case prog :=<- pbft.committedCh:
					condi := extractNodeID(pbft.nodeIPAddress)==13 && pbft.currentHeight==7 && pbft.nodePubkeystr!=pbft.curleaderPubKeystr
					if condi {
						fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "sleeps when committing in height", pbft.currentHeight)
						time.Sleep(time.Second*ConsensusTimer)
						goto consensus_loop
					}
					pbft.mu.Lock()
					if prog.view==pbft.viewnumber && prog.height==pbft.currentHeight && pbft.consenstatus==Prepared {
						pbft.consenstatus = Commited
						pbft.persis.commitedheight = pbft.currentHeight
						fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "is commited in view ", pbft.viewnumber, " height ", pbft.currentHeight)
						// todo, commit the request
						pbft.CommitCurConsensOb()
					}
					pbft.mu.Unlock()
					break consensus_loop
				}
			}
		case stat_viewchange:
			fmt.Print("node ", extractNodeID(pbft.nodeIPAddress), " now enters view-change in view ",pbft.viewnumber," in height ", pbft.currentHeight, " waiting for vcmsg!\n")
			go pbft.scanViewChange(pbft.viewnumber)
			select {
			case <- pbft.recoverstate:
				pbft.mu.Lock()
				view := pbft.viewnumber
				heigh := pbft.currentHeight
				pbft.mu.Unlock()
				fmt.Println("node", extractNodeID(pbft.nodeIPAddress), " goto RECOVERSTART in view ", view, " height ", heigh)
				goto RECOVERSTART
			case theview :=<- pbft.vcmsgcollectedCh:
				if theview==pbft.viewnumber {
					fmt.Println("node", extractNodeID(pbft.nodeIPAddress), " has collected enough view change msg in view ", theview)
					pbft.status = stat_inaugurate
				}
			}
		case stat_inaugurate:
			fmt.Print("node ", extractNodeID(pbft.nodeIPAddress)," now enters inauguration stage in view ", pbft.viewnumber," in height ", pbft.currentHeight, "\n")
			if pbft.nodePubkeystr==pbft.curleaderPubKeystr && pbft.sentnewviewmsg[pbft.viewnumber]==false {
				pbft.sentnewviewmsg[pbft.viewnumber] = true
				pbft.mu.Lock()
				view := pbft.viewnumber
				vcset := pbft.vcmsgset[view][0:QuorumSize]
				pbft.mu.Unlock()
				go pbft.broadcastNewView(view, vcset)
			}
			pbft.mu.Lock()
			ckp := pbft.persis.commitedheight
			leaderpubkey := pbft.curleaderPubKeystr
			pbft.mu.Unlock()
			go pbft.scanNewView(pbft.viewnumber, ckp, leaderpubkey)
			thetimer := time.NewTimer(time.Second*InauguratTimer)
		inaugurate_loop:
			for {
				select {
				case <- pbft.recoverstate:
					pbft.mu.Lock()
					view := pbft.viewnumber
					heigh := pbft.currentHeight
					pbft.mu.Unlock()
					fmt.Println("node", extractNodeID(pbft.nodeIPAddress), " goto RECOVERSTART in view ", view, " height ", heigh)
					goto RECOVERSTART
				case <-thetimer.C:
					pbft.resetVariForViewChange()
					pbft.mu.Lock()
					view := pbft.viewnumber
					ckpheigh := pbft.persis.commitedheight
					lockheigh := pbft.persis.preparedheight
					pbft.mu.Unlock()
					fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "view-change timer expires in view ",pbft.viewnumber," height ", pbft.currentHeight)
					fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "now broadcasts view-change msg, checkpoint height: ", ckpheigh, " prepare-locked height: ", lockheigh)
					go pbft.broadcastViewChange(view, ckpheigh, lockheigh)
				case theview:=<- pbft.inauguratedCh:
					if theview==pbft.viewnumber {
						pbft.mu.Lock()
						pbft.consenstatus = Unstarted
						pbft.status = stat_consensus
						if pbft.hasRemainBInNVMsg {
							pbft.prepareVote[pbft.preprepareMsgInNVMsg.Order] = []PrepareMsg{}
							pbft.commitVote[pbft.preprepareMsgInNVMsg.Order] = []CommitMsg{}
							pbft.currentHeight = pbft.preprepareMsgInNVMsg.Order
							go pbft.handlePreprepareMsgAfterVC(pbft.preprepareMsgInNVMsg)
						}
						pbft.mu.Unlock()
						fmt.Println("node", extractNodeID(pbft.nodeIPAddress), " received a new-view msg in view ", theview)
						break inaugurate_loop
					}
				}
			}
		}
	}
}

func (pbft *PBFT) scanViewChange(view int) {
	timeouter := time.NewTimer(time.Millisecond*ThreadExit)
	for {
		select {
		case <- timeouter.C:
			return
		default:
			// need mutex lock? no, this is the only place that calls len() func
			pbft.mu.Lock()
			le := len(pbft.vcmsgset[view])
			pbft.mu.Unlock()
			if le>=QuorumSize {
				pbft.vcmsgcollectedCh<-view
				return
			} else {
				time.Sleep(time.Millisecond*ScanInterval)
			}
		}
	}
}

func (pbft *PBFT) CommitCurConsensOb() {
	// do not re-execute requests
	condi := extractNodeID(pbft.nodeIPAddress)==13 && pbft.currentHeight>=5 && pbft.currentHeight<=5 && pbft.nodePubkeystr!=pbft.curleaderPubKeystr
	if condi==false {
		// reset consensus variables and channels
		pbft.persis.requestlist[pbft.currentHeight] = pbft.currequest
		pbft.persis.logview[pbft.currentHeight] = pbft.viewnumber
		pbft.recovStartView = pbft.viewnumber
		pbft.recovStartHeight = pbft.currentHeight
		pbft.consenstatus = Unstarted
		pbft.currentHeight += 1
		pbft.currequest = 0
	} else {
		fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "gives up committing in height", pbft.currentHeight)
	}
	if pbft.currentHeight%20==0 {
		var requestlist []int
		for i:=0; i<pbft.currentHeight; i++ {
			requestlist = append(requestlist, pbft.persis.requestlist[i])
		}
		fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "requests history: ", requestlist)
	}
}

func (pbft *PBFT) resetVariForViewChange() {

	pbft.status = stat_viewchange
	pbft.viewnumber += 1
	// consensus status change?
	pbft.succLine.RotateLeader()
	pbft.curleaderPubKeystr = pbft.succLine.CurLeader.Member.PubKey
	pbft.curleaderIpAddr = pbft.succLine.CurLeader.Member.IpAddr
	pbft.hasRemainBInNVMsg = false
}

func (pbft *PBFT) scanPreprepare(view, heigh int, leaderpubkey string) {
	timeouter := time.NewTimer(time.Millisecond*ThreadExit)
	for {
		select {
		case <- timeouter.C:
			return
		default:
			pbft.mu.Lock()
			_, ok := pbft.pre_preparelog[heigh]
			pbft.mu.Unlock()
			if ok {
				pbft.mu.Lock()
				thepreprepare := pbft.pre_preparelog[heigh]
				pbft.mu.Unlock()
				theview := thepreprepare.View
				if view==theview && thepreprepare.Pubkey==leaderpubkey {
					pbft.currequest = thepreprepare.Digest
					prog := progres{view, heigh}
					pbft.prepreparedCh<-prog
					return
				}
			} else {
				time.Sleep(time.Millisecond*ScanInterval)
			}
		}
	}
}

func (pbft *PBFT) scanPrepare(view, heigh int, digest int) {
	timeouter := time.NewTimer(time.Millisecond*ThreadExit)
	for {
		select {
		case <- timeouter.C:
			return
		default:
			pbft.mu.Lock()
			acc := 0
			for _, vote := range pbft.prepareVote[heigh] {
				if digest==vote.Digest {
					acc += 1
				}
			}
			pbft.mu.Unlock()
			if acc>=QuorumSize {
				prog := progres{view, heigh}
				pbft.preparedCh<-prog
				return
			} else {
				time.Sleep(time.Millisecond*ScanInterval)
			}
		}
	}
}

func (pbft *PBFT) scanCommit(view, heigh int, digest int) {
	timeouter := time.NewTimer(time.Millisecond*ThreadExit)
	for {
		select {
		case <- timeouter.C:
			return
		default:
			pbft.mu.Lock()
			acc := 0
			for _, vote := range pbft.commitVote[heigh] {
				if digest==vote.Digest {
					acc += 1
				}
			}
			pbft.mu.Unlock()
			if acc>=QuorumSize {
				prog := progres{view, heigh}
				pbft.committedCh<-prog
				return
			} else {
				time.Sleep(time.Millisecond*ScanInterval)
			}
		}
	}
}

func (pbft *PBFT) broadcastPrepare(v, n , digest int) {
	preparemsg := NewPrepareMsg(v, n, digest, pbft.nodePubkeystr, pbft.nodePrvKey)
	for _, dest := range pbft.minerIPAddress {
		if dest == pbft.nodeIPAddress {
			pbft.mu.Lock()
			pbft.prepareVote[n] = append(pbft.prepareVote[n], preparemsg)
			pbft.mu.Unlock()
		} else {
			var buff bytes.Buffer
			enc := gob.NewEncoder(&buff)
			err := enc.Encode(preparemsg)
			if err != nil {
				log.Panic(err)
			}
			content := buff.Bytes()
			comman := commandToBytes("preparemsg")
			content = append(comman, content...)
			go sendData(content, dest)
		}
	}
}

func (pbft *PBFT) handlePreprepareMsgAfterVC(pppmsg PrePrepareMsg) {
	prog := progres{pppmsg.View, pppmsg.Order}
	pbft.prepreparedCh <- prog
}

func (pbft *PBFT) runServer() {
	fmt.Println("node", extractNodeID(pbft.nodeIPAddress), " starts ")
	listener, err := net.Listen(protocol, pbft.nodeIPAddress)
	if err != nil {
		fmt.Printf("net.Listen() runs wrongly :%v\n", err)
		return
	}
	defer listener.Close()

	for true {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("listener.Accept() runs wrongly :%v\n", err)
			return
		}
		defer conn.Close()


		request, err := ioutil.ReadAll(conn)
		commanType := bytesToCommand(request[:commandLength])
		//fmt.Println("the message type is ", commanType)
		if err != nil {
			log.Panic(err)
		}
		switch commanType {
		case "addrpubkey":
			go pbft.handleAddrPubKey(request[commandLength:])
		case "prepreparemsg":
			go pbft.handlePreprepareMsg(request[commandLength:])
		case "preparemsg":
			go pbft.handlePrepareMsg(request[commandLength:])
		case "commitmsg":
			go pbft.handleCommitMsg(request[commandLength:])
		case "viewchangemsg":
			//fmt.Println("node", extractNodeID(pbft.nodeIPAddress), " received a view-change msg")
			go pbft.handleViewChangeMsg(request[commandLength:])
		case "newviewmsg":
			//fmt.Println("node", extractNodeID(pbft.nodeIPAddress), " received a new-view msg")
			go pbft.handleNewViewMsg(request[commandLength:])
		case "querylost":
			fmt.Println("node", extractNodeID(pbft.nodeIPAddress), " received a querylost")
			go pbft.handleQueryLost(request[commandLength:])
		case "replylost":
			go pbft.handleReplyLost(request[commandLength:])
		}
	}
}

func (pbft *PBFT) broadcastAddrPubKeyIp() {
	for _, dest := range pbft.minerIPAddress {
		if dest != pbft.nodeIPAddress {
			peerid := datastruc.PeerIdentity{pbft.nodePubkeystr, pbft.nodeIPAddress}
			go SendAddrPubKey(peerid, dest)
		}
	}
}

func SendAddrPubKey(peerid datastruc.PeerIdentity, toaddr string) {
	var buff bytes.Buffer

	enc := gob.NewEncoder(&buff)
	err := enc.Encode(peerid)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	comman := commandToBytes("addrpubkey")
	content = append(comman, content...)
	sendData(content, toaddr)
}

func (pbft *PBFT) handleAddrPubKey(conten []byte) {
	var buff bytes.Buffer
	var peerid datastruc.PeerIdentity
	buff.Write(conten)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&peerid)
	if err != nil {
		fmt.Println("decoding error")
	}
	pbft.mu.Lock()
	constructConfigure(&pbft.curConfigure, peerid)
	pbft.mu.Unlock()

	if len(pbft.curConfigure)==TotalNumber {
		pbft.succLine = datastruc.ConstructSuccessionLine(pbft.curConfigure)
		pbft.curleaderPubKeystr = pbft.succLine.CurLeader.Member.PubKey
		pbft.curleaderIpAddr = pbft.succLine.CurLeader.Member.IpAddr
		fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "thinks the current leader should be ", pbft.curleaderIpAddr)
	}
}

func (pbft *PBFT) broadcastPreprepare(v, n int, prk *ecdsa.PrivateKey) {
	prepreparemsg := NewPreprepareMsg(v, n, pbft.nodePubkeystr, prk)
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(prepreparemsg)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	comman := commandToBytes("prepreparemsg")
	//fmt.Println("node", pbft.nodeIPAddress, " sends pre-prepare to ", addr)
	content = append(comman, content...)

	for _, dest := range pbft.minerIPAddress {
		if dest != pbft.nodeIPAddress {
			go sendData(content, dest)
		} else {
			fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "received pre-preparemsg in height ", prepreparemsg.Order)
			pbft.mu.Lock()
			pbft.pre_preparelog[n] = prepreparemsg
			pbft.mu.Unlock()
		}
	}
}

func sendData(data []byte, addr string) {
	conn, err := net.Dial(protocol, addr)
	if err != nil {
		fmt.Printf("%s is not available\n", addr)
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err!=nil {
		fmt.Println("send error")
		log.Panic(err)
	}
}

func (pbft *PBFT) handlePreprepareMsg(content []byte) {
	//fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "received pre-preparemsg in height ", pbft.currentHeight)

	var buff bytes.Buffer
	var prepreparemsg PrePrepareMsg
	buff.Write(content)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&prepreparemsg)
	if err != nil {
		fmt.Println("decoding error")
	}

	// verify signature
	datatoverify := string(prepreparemsg.View) + "," + string(prepreparemsg.Order) + "," + string(prepreparemsg.Digest)
	pub := DecodePublic(prepreparemsg.Pubkey)
	if !prepreparemsg.Sig.Verify([]byte(datatoverify), pub) {
		fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "received pre-preparemsg in height ", prepreparemsg.Order, " but the sig is wrong!")
		return
	}

	//if prepreparemsg.Pubkey!=pbft.curleaderPubKeystr {
	//	fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "receives a pre-prepare msg, but it is not from leader")
	//}

	pbft.mu.Lock()
	localheigh := pbft.persis.commitedheight
	if localheigh+1<prepreparemsg.Order {
		fmt.Println("node", extractNodeID(pbft.nodeIPAddress), " realizes it has been left behind after receiving pre-prepare msg, query lost data, current height: ", localheigh, "system height: ", prepreparemsg.Order)
		go QueryLostData(pbft.nodePubkeystr, pbft.curleaderIpAddr, localheigh, pbft.nodePrvKey)
		//fmt.Println("node", extractNodeID(pbft.nodeIPAddress), " realizes it has been left behind after receiving pre-prepare msg, " +
		//	"but doesn't query lost data, current height: ", localheigh, " system height: ", prepreparemsg.Order)
	}
	pbft.pre_preparelog[prepreparemsg.Order] = prepreparemsg
	pbft.mu.Unlock()

	fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "received pre-preparemsg in height ", prepreparemsg.Order)
}

func QueryLostData(pubkey string, remoteaddr string, localheigh int, prvkey *ecdsa.PrivateKey) {
	querymsg := NewQueryLostDataMsg(pubkey, localheigh, prvkey)

	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(querymsg)
	if err!=nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	comman := commandToBytes("querylost")
	content = append(comman, content...)
	sendData(content, remoteaddr)
}

func (pbft *PBFT) handlePrepareMsg(content []byte) {
	//fmt.Print("node", extractNodeID(pbft.nodeIPAddress), " received a prepare msg\n")
	var buff bytes.Buffer
	var preparemsg PrepareMsg
	buff.Write(content)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&preparemsg)
	if err != nil {
		fmt.Println("decoding error")
		log.Panic(err)
	}

	datatoverify := string(preparemsg.View) + "," + string(preparemsg.Order) + "," + string(preparemsg.Digest)
	pub := DecodePublic(preparemsg.Pubkey)
	if !preparemsg.Sig.Verify([]byte(datatoverify), pub) {
		fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "received preparemsg in height ", preparemsg.Order, " but the sig is wrong!")
		return
	}

	pbft.mu.Lock()
	pbft.prepareVote[preparemsg.Order] = append(pbft.prepareVote[preparemsg.Order], preparemsg)
	pbft.mu.Unlock()
}

func (pbft *PBFT) broadcastCommit(v, n int, digest int) {
	commitmsg := NewCommitMsg(v, n, digest, pbft.nodePubkeystr, pbft.nodePrvKey)
	for _, dest := range pbft.minerIPAddress {
		if dest == pbft.nodeIPAddress {
			pbft.mu.Lock()
			pbft.commitVote[n] = append(pbft.commitVote[n], commitmsg)
			pbft.mu.Unlock()
		} else {
			var buff bytes.Buffer
			enc := gob.NewEncoder(&buff)
			err := enc.Encode(commitmsg)
			if err != nil {
				log.Panic(err)
			}
			content := buff.Bytes()
			comman := commandToBytes("commitmsg")
			content = append(comman, content...)
			//fmt.Println("node", extractNodeID(pbft.nodeIPAddress),
			//	"sends prepare msg to ", extractNodeID(addr))
			go sendData(content, dest)
		}
	}
}

func (pbft *PBFT) handleCommitMsg(content []byte) {
	var buff bytes.Buffer
	var commitmsg CommitMsg
	buff.Write(content)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&commitmsg)
	if err != nil {
		fmt.Println("decoding error")
	}

	datatoverify := string(commitmsg.View) + "," + string(commitmsg.Order) + "," + string(commitmsg.Digest)
	pub := DecodePublic(commitmsg.Pubkey)
	if !commitmsg.Sig.Verify([]byte(datatoverify), pub) {
		fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "received commitmsg in height ", commitmsg.Order, " but the sig is wrong!")
		return
	}

	pbft.mu.Lock()
	pbft.commitVote[commitmsg.Order] = append(pbft.commitVote[commitmsg.Order], commitmsg)
	pbft.mu.Unlock()
}

func (pbft *PBFT) broadcastViewChange(view, ckpheigh, lockheigh int) {
	vcmsg := NewViewChangeMsg(view, pbft.nodePubkeystr, ckpheigh, lockheigh, pbft.nodePrvKey)
	for _, dest := range pbft.minerIPAddress {
		if dest == pbft.nodeIPAddress {
			pbft.mu.Lock()
			pbft.vcmsgset[view] = append(pbft.vcmsgset[view], vcmsg)
			pbft.mu.Unlock()
		} else {
			var buff bytes.Buffer
			enc := gob.NewEncoder(&buff)
			err := enc.Encode(vcmsg)
			if err!=nil {
				log.Panic(err)
			}
			content := buff.Bytes()
			comman := commandToBytes("viewchangemsg")
			content = append(comman, content...)
			go sendData(content, dest)
		}
	}
}

func (pbft *PBFT) handleViewChangeMsg (conten []byte) {
	var buff bytes.Buffer
	var vcmsg ViewChangeMsg
	buff.Write(conten)

	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&vcmsg)
	if err!=nil {
		log.Panic(err)
	}

	datatoverify := string(vcmsg.View) + "," + vcmsg.Pubkey + "," + string(vcmsg.LastBHeight) + "," + string(vcmsg.LockedHeight)
	pub := DecodePublic(vcmsg.Pubkey)
	if !vcmsg.Sig.Verify([]byte(datatoverify), pub) {
		fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "received commitmsg in view ", vcmsg.View, " but the sig is wrong!")
		return
	}

	pbft.mu.Lock()
	localheigh := pbft.persis.commitedheight
	if localheigh<vcmsg.LastBHeight {
		remotepubkey := vcmsg.Pubkey
		remoteaddr := ExtractSenderIp(pbft.curConfigure, remotepubkey)
		fmt.Println("node", extractNodeID(pbft.nodeIPAddress), " realizes it has been left behind after receiving view change msg, query lost data," +
			" current height: ", localheigh, "system height: ", vcmsg.LastBHeight)
		go QueryLostData(pbft.nodePubkeystr, remoteaddr, localheigh, pbft.nodePrvKey)
	}
	pbft.vcmsgset[vcmsg.View] = append(pbft.vcmsgset[vcmsg.View], vcmsg)
	pbft.mu.Unlock()
	fmt.Println("node", extractNodeID(pbft.nodeIPAddress), " received a view-change msg of view ", vcmsg.View)
}

func (pbft *PBFT) broadcastNewView(view int, vcset []ViewChangeMsg) {
	nvmsg := NewNewViewMsg(view, pbft.nodePubkeystr, vcset, pbft.nodePrvKey)
	if len(nvmsg.PPMsgSet)>0 {
		order := nvmsg.PPMsgSet[0].Order
		fmt.Println("leader", extractNodeID(pbft.nodeIPAddress), "now broadcasts new-view msg, with a pre-prepare msg of height", order)
	} else {
		fmt.Println("leader", extractNodeID(pbft.nodeIPAddress), "now broadcasts new-view msg")
	}
	for _, dest := range pbft.minerIPAddress {
		if dest == pbft.nodeIPAddress {
			// TODO, how does the new leader itself deal with new-view msg?
			pbft.mu.Lock()
			pbft.newviewlog[view] = nvmsg
			pbft.mu.Unlock()
		} else {
			var buff bytes.Buffer
			enc := gob.NewEncoder(&buff)
			err := enc.Encode(nvmsg)
			if err!=nil {
				log.Panic(err)
			}
			content := buff.Bytes()
			comman := commandToBytes("newviewmsg")
			content = append(comman, content...)
			go sendData(content, dest)
		}
	}
}

func (pbft *PBFT) handleNewViewMsg(conten []byte) {
	var buff bytes.Buffer
	var nvmsg NewViewMsg
	buff.Write(conten)

	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&nvmsg)
	if err!=nil {
		log.Panic(err)
	}

	nvvmsg := nvmsg
	nvvmsg.Sig = PariSign{}
	nvvmsg.Pubkey = ""
	datatoverify := sha256.Sum256(nvvmsg.Serialize())
	pub := DecodePublic(nvmsg.Pubkey)
	if !nvmsg.Sig.Verify(datatoverify[:], pub) {
		fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "received new-view msg in view ", nvmsg.View, " but the sig is wrong!")
		return
	}

	// start consens the request prepared in the new-view msg
	pbft.mu.Lock()
	pbft.newviewlog[nvmsg.View] = nvmsg
	pbft.mu.Unlock()
}


func (pbft *PBFT) handleQueryLost(content []byte) {
	// this functions runs in a non-primary thread, and needs to read the database, may lead to confict??
	//fmt.Println("node", extractNodeID(pbft.nodeIPAddress)," reply query")
	var buff bytes.Buffer
	var qlmsg QueryForBlockMsg
	buff.Write(content)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&qlmsg)
	if err!=nil {
		log.Panic(err)
	}

	// verify signature
	datatosign := string(qlmsg.Localheight)
	pub := DecodePublic(qlmsg.Pubkey)
	if !qlmsg.Sig.Verify([]byte(datatosign), pub) {
		fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "received query for lost msg in height ", qlmsg.Localheight, " but the sig is wrong!")
		return
	}

	pbft.mu.Lock()
	localheigh := pbft.persis.commitedheight
	if qlmsg.Localheight<localheigh {
		fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "reply querier with requests from ", (qlmsg.Localheight+1), " to ", localheigh)
		remotepubkey := qlmsg.Pubkey
		remoteaddr := ExtractSenderIp(pbft.curConfigure, remotepubkey)
		viewlist := []int{}
		requestlist := []int{}
		for i:=qlmsg.Localheight+1; i<=localheigh; i++ {
			viewlist = append(viewlist, pbft.persis.logview[i])
			requestlist = append(requestlist, pbft.persis.requestlist[i])
		}
		fmt.Println("------", viewlist, "------")
		go ReplyLost(pbft.nodePubkeystr, localheigh, qlmsg.Localheight, remoteaddr, viewlist, requestlist, pbft.nodePrvKey)
	} else {
		fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "doesn't reply querier because it is also left behind")
	}
	pbft.mu.Unlock()
}

func (pbft *PBFT) handleReplyLost(content []byte) {

	var buff bytes.Buffer
	var rfqmsg ReplyForQueryMsg
	buff.Write(content)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&rfqmsg)
	if err != nil {
		fmt.Println("decoding error")
	}
	// verify signature
	rfqqmsg := rfqmsg
	rfqqmsg.Sig = PariSign{}
	rfqqmsg.Pubkey = ""
	datatoverify := rfqqmsg.Serialize()
	pub := DecodePublic(rfqmsg.Pubkey)
	if !rfqmsg.Sig.Verify(datatoverify, pub) {
		fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "received reply for query msg in height ", rfqmsg.Height, " but the sig is wrong!")
		return
	}

	fmt.Println("node", extractNodeID(pbft.nodeIPAddress), " received a replylost from height ", (rfqmsg.Height+1), " to ", (rfqmsg.Height + rfqmsg.RequestNum))
	// TODO, querier updates its state to the newest after receiving the lost data
	pbft.mu.Lock()
	if pbft.persis.commitedheight==rfqmsg.Height {
		// which means that the reply is exactly it needs
		// recover state
		fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "receives the reply! there are", rfqmsg.RequestNum, "requests in it")

		// change local state to last consensus
		if pbft.viewnumber > pbft.recovStartView {
			for j:=0; j<pbft.viewnumber - pbft.recovStartView; j++ {
				pbft.succLine.InverseRotateLeader()
				pbft.curleaderPubKeystr = pbft.succLine.CurLeader.Member.PubKey
				pbft.curleaderIpAddr = pbft.succLine.CurLeader.Member.IpAddr
			}
			pbft.viewnumber = pbft.recovStartView
		}
		fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "recovers its view to view ",pbft.viewnumber)
		// then recover requests one by one
		for i:=0; i<rfqmsg.RequestNum; i++ {
			if rfqmsg.ViewList[i] > pbft.viewnumber {
				for j:=0; j<(rfqmsg.ViewList[i]-pbft.viewnumber); j++ {
					pbft.succLine.RotateLeader()
					pbft.curleaderPubKeystr = pbft.succLine.CurLeader.Member.PubKey
					pbft.curleaderIpAddr = pbft.succLine.CurLeader.Member.IpAddr
				}
				pbft.viewnumber = rfqmsg.ViewList[i]
				pbft.recovStartView = rfqmsg.ViewList[i]
			}
			order := rfqmsg.Height + 1 + i
			pbft.persis.preparedheight = order
			pbft.persis.commitedheight = order
			pbft.persis.logview[order] = pbft.viewnumber
			pbft.persis.requestlist[order] = rfqmsg.RequestList[i]
			fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "recovers the request in height", order)
			pbft.recovStartHeight += 1
		}
		pbft.currentHeight = pbft.persis.commitedheight + 1
		pbft.consenstatus = Unstarted
		pbft.status = stat_consensus

		pbft.recoverstate<-true
	}
	pbft.mu.Unlock()
	fmt.Println("node", extractNodeID(pbft.nodeIPAddress), "thinks current leader is", extractNodeID(pbft.curleaderIpAddr))

}

func (pbft *PBFT) scanNewView(view int, ckp int, leaderpubkey string) {
	timeouter := time.NewTimer(time.Millisecond*ThreadExit)
	for {
		select {
		case <- timeouter.C:
			return
		default:
			pbft.mu.Lock()
			_, ok := pbft.newviewlog[view]
			if ok {
				nvmsg := pbft.newviewlog[view]
				if ckp==nvmsg.CKpoint && nvmsg.Pubkey==leaderpubkey {
					if len(nvmsg.PPMsgSet)>0 {
						pbft.hasRemainBInNVMsg = true
						pbft.preprepareMsgInNVMsg = nvmsg.PPMsgSet[0]
					}
					pbft.inauguratedCh <- view
					pbft.mu.Unlock()
					return
				}
			} else {
				pbft.mu.Unlock()
				time.Sleep(time.Millisecond*ScanInterval)
			}
		}
	}
}

func constructConfigure(config *[]datastruc.PeerIdentity, peerid datastruc.PeerIdentity) {
	var curconfig []datastruc.PeerIdentity
	curconfig = *config
	if len(curconfig)==0 {
		*config = append(curconfig, peerid)
	} else {
		// ensure the line is orded
		lenn := len(curconfig)
		var pos int
		var i int
		for i=0; i<lenn; i++ {
			if peerid.Lessthan(curconfig[i]) {
				pos = i
				break
			}
		}
		if i<lenn {
			rear := append([]datastruc.PeerIdentity{}, curconfig[pos:]...)
			*config = append(append(curconfig[:pos], peerid), rear...)
		} else {
			*config = append(curconfig, peerid)
		}
	}
}

func extractNodeID(s string) int {
	pos := len(s) - 1
	res := int([]byte(s)[pos]) - 48
	return res
}

func (pbft *PBFT) generatePubKeys() {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		log.Fatalln(err)
	}
	pbft.nodePrvKey = privateKey
	pbft.nodePubKey = &privateKey.PublicKey
	pbft.nodePrvkeystr = EncodePrivate(pbft.nodePrvKey)
	pbft.nodePubkeystr = EncodePublic(pbft.nodePubKey)
}

func EncodePublic(publicKey *ecdsa.PublicKey) string {
	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
	return string(pemEncodedPub)
}

func EncodePrivate(privateKey *ecdsa.PrivateKey) string {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	return string(pemEncoded)
}

func DecodePrivate(pemEncoded string) *ecdsa.PrivateKey {
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)
	return privateKey
}

func DecodePublic(pemEncodedPub string) *ecdsa.PublicKey {
	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)
	return publicKey
}