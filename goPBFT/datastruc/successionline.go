package datastruc

type SLNode struct {
	Member PeerIdentity
	Next *SLNode
}

type SuccLine struct {
	tail *SLNode
	CurLeader *SLNode
}

func ConstructSuccessionLine(curConfigure []PeerIdentity) *SuccLine {
	sl := new(SuccLine)
	tmp := []*SLNode{}
	for _, peer := range curConfigure {
		sln := new(SLNode)
		sln.Member = peer
		tmp = append(tmp, sln)
	}
	for i, sln := range tmp {
		if i==len(tmp)-1 {
			sln.Next = tmp[0]
		} else {
			sln.Next = tmp[i+1]
		}
	}
	sl.tail = tmp[0]
	sl.CurLeader = sl.tail
	return sl
}

func (sl *SuccLine) RotateLeader() {
	sl.CurLeader = sl.CurLeader.Next
}

func (sl *SuccLine) InverseRotateLeader() {
	res := FindPrevious(sl, sl.CurLeader)
	sl.CurLeader = res
}

func (sl *SuccLine) InsertNewSLNode(n1 *SLNode) {
	posNode := FindPrevious(sl, sl.CurLeader)
	posNode.Next = n1
	n1.Next = sl.CurLeader
}

func FindPrevious(sline *SuccLine, target *SLNode) *SLNode {
	var res *SLNode
	res = sline.tail
	for {
		if TwoSLNodesEqual(res.Next, target) {
			break
		} else {
			res = res.Next
		}
	}
	return res
}

func TwoSLNodesEqual(n1, n2 *SLNode) bool {
	if n1.Member.PubKey == n2.Member.PubKey {
		return true
	}
	return false
}


