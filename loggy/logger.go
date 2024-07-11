package loggy

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"
)

var EPOCH_DURATION int64
var LOGS_BASEPATH string

type MessageType int
type MessageDirection int

const (
	// Protocol messages belonging to eth/62
	StatusMsg                MessageType = 0x00
	NewBlockHashesMsg        MessageType = 0x01
	TxMsg                    MessageType = 0x02
	GetBlockHeadersMsg       MessageType = 0x03
	BlockHeadersMsg          MessageType = 0x04
	GetBlockBodiesMsg        MessageType = 0x05
	BlockBodiesMsg           MessageType = 0x06
	NewBlockMsg              MessageType = 0x07
	GetPooledTransactionsMsg MessageType = 0x09
	PooledTransactionsMsg    MessageType = 0x0a

	// Protocol messages belonging to eth/63
	GetNodeDataMsg MessageType = 0x0d
	NodeDataMsg    MessageType = 0x0e
	GetReceiptsMsg MessageType = 0x0f
	ReceiptsMsg    MessageType = 0x10
	Other          MessageType = 0xff
	RemovePeer     MessageType = 0x11 //Came up with these last two... any protocol?
	AddPeer        MessageType = 0x12
	PeerTableLog   MessageType = 0x13
)

const (
	Inbound  MessageDirection = 0
	Outbound MessageDirection = 1
)

var lastEpochStart int64

// updates epoch if needed and returns true if updated
func changeEpochIfNeeded() bool {
	//new epoch every EPOCH_DURATION
	if time.Now().Unix() >= (lastEpochStart + EPOCH_DURATION) {
		lastEpochStart = time.Now().Unix()
		return true
	}
	return false
}

// returns the path of file to log to and if the epoch just changed
func GET_LOG_FILE(msgtype MessageType, msgdir MessageDirection) string {
	changeEpochIfNeeded()
	epoch := strconv.FormatInt(lastEpochStart, 10)

	if msgtype == StatusMsg {
		if msgdir == Outbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("StatusMsg_out_%s.jsonl", epoch)
			return fname
		} else if msgdir == Inbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("StatusMsg_in_%s.jsonl", epoch)
			return fname
		}
	}

	if msgtype == NewBlockHashesMsg {
		if msgdir == Outbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("NewBlockHashesMsg_out_%s.jsonl", epoch)
			return fname
		} else if msgdir == Inbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("NewBlockHashesMsg_in_%s.jsonl", epoch)
			return fname
		}
	}

	if msgtype == TxMsg {
		if msgdir == Outbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("TxMsg_out_%s.jsonl", epoch)
			return fname
		} else if msgdir == Inbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("TxMsg_in_%s.jsonl", epoch)
			return fname
		}
	}

	if msgtype == GetBlockHeadersMsg {
		if msgdir == Outbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("GetBlockHeadersMsg_out_%s.jsonl", epoch)
			return fname
		} else if msgdir == Inbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("GetBlockHeadersMsg_in_%s.jsonl", epoch)
			return fname
		}
	}

	if msgtype == BlockHeadersMsg {
		if msgdir == Outbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("BlockHeadersMsg_out_%s.jsonl", epoch)
			return fname
		} else if msgdir == Inbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("BlockHeadersMsg_in_%s.jsonl", epoch)
			return fname
		}
	}

	if msgtype == GetBlockBodiesMsg {
		if msgdir == Outbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("GetBlockBodiesMsg_out_%s.jsonl", epoch)
			return fname
		} else if msgdir == Inbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("GetBlockBodiesMsg_in_%s.jsonl", epoch)
			return fname
		}
	}

	if msgtype == BlockBodiesMsg {
		if msgdir == Outbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("BlockBodiesMsg_out_%s.jsonl", epoch)
			return fname
		} else if msgdir == Inbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("BlockBodiesMsg_in_%s.jsonl", epoch)
			return fname
		}
	}

	if msgtype == NewBlockMsg {
		if msgdir == Outbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("NewBlockMsg_out_%s.jsonl", epoch)
			return fname
		} else if msgdir == Inbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("NewBlockMsg_in_%s.jsonl", epoch)
			return fname
		}
	}

	if msgtype == GetNodeDataMsg {
		if msgdir == Outbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("GetNodeDataMsg_out_%s.jsonl", epoch)
			return fname
		} else if msgdir == Inbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("GetNodeDataMsg_in_%s.jsonl", epoch)
			return fname
		}
	}

	if msgtype == NodeDataMsg {
		if msgdir == Outbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("NodeDataMsg_out_%s.jsonl", epoch)
			return fname
		} else if msgdir == Inbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("NodeDataMsg_in_%s.jsonl", epoch)
			return fname
		}
	}

	if msgtype == GetReceiptsMsg {
		if msgdir == Outbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("GetReceiptsMsg_out_%s.jsonl", epoch)
			return fname
		} else if msgdir == Inbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("GetReceiptsMsg_in_%s.jsonl", epoch)
			return fname
		}
	}

	if msgtype == ReceiptsMsg {
		if msgdir == Outbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("ReceiptsMsg_out_%s.jsonl", epoch)
			return fname
		} else if msgdir == Inbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("ReceiptsMsg_in_%s.jsonl", epoch)
			return fname
		}
	}

	if msgtype == AddPeer {
		fname := LOGS_BASEPATH + fmt.Sprintf("AddPeer_%s.jsonl", epoch)
		return fname
	}

	if msgtype == RemovePeer {
		fname := LOGS_BASEPATH + fmt.Sprintf("RemovePeer_%s.jsonl", epoch)
		return fname
	}

	if msgtype == PeerTableLog {
		fname := LOGS_BASEPATH + fmt.Sprintf("PeerTable_%s.jsonl", epoch)
		return fname
	}

	if msgtype == GetPooledTransactionsMsg {

		if msgdir == Outbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("GetPooledTransactionsMsg_out_%s.jsonl", epoch)
			return fname
		} else if msgdir == Inbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("GetPooledTransactionsMsg_in_%s.jsonl", epoch)
			return fname
		}
	}

	if msgtype == PooledTransactionsMsg {

		if msgdir == Outbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("PooledTransactionsMsg_out_%s.jsonl", epoch)
			return fname
		} else if msgdir == Inbound {
			fname := LOGS_BASEPATH + fmt.Sprintf("PooledTransactionsMsg_in_%s.jsonl", epoch)
			return fname
		}
	}

	return (LOGS_BASEPATH + fmt.Sprintf("other_%s.txt", epoch))
}

// var Loggymutex *sync.Mutex
var Loggymutex sync.Mutex

// assumes valid json is being passed to function as string
func Log(jsonstr string, msgtype MessageType, msgdir MessageDirection) {
	Loggymutex.Lock()
	defer Loggymutex.Unlock()

	EPOCH_DURATION = 14400
	// Change BASEPATH accordingly
	LOGS_BASEPATH = "/mnt/fscopy/home/ubuntu/ethereumlogs/"

	fname := GET_LOG_FILE(msgtype, msgdir)

	f, err := os.OpenFile(fname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		log.Fatal("Cannot create file", err)
	}
	f.WriteString(jsonstr)
	f.WriteString("\n")
	f.Close()
}
