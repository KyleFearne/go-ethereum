// Copyright 2021 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package eth

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/loggy"

	//"/home/ubuntu/ethereum/go-ethereum/loggy" //How do I import loggy

	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

type Tx struct {
	Type                 string `json:"type"`
	ChainId              string `json:"chainId"`
	Nonce                string `json:"nonce"`
	To                   string `json:"to"`
	Gas                  string `json:"gas"`
	GasPrice             string `json:"gasPrice"`
	MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas"`
	MaxFeePerGas         string `json:"maxFeePerGas"`
	Value                string `json:"value"`
	Input                string `json:"input"`
	V                    string `json:"v"`
	R                    string `json:"r"`
	S                    string `json:"s"`
	Hash                 string `json:"hash"`
}

// Adding this for json Marshalling in TxLogging
type Transaction struct {
	TxHash common.Hash `json:"TxHash"`
}

type Output struct {
	RequestId        uint64        `json:"RequestId"`
	TxHashes         []common.Hash `json:"TxHashes"`
	UncleHashes      []common.Hash `json:"UncleHashes"`
	WithdrawalHashes []common.Hash `json:"WithdrawalHashes"`
}

type ReceiptOutput struct {
	RequestId uint64        `json:"RequestId"`
	TxHashes  []common.Hash `json:"TxHashes"`
}

func handleGetBlockHeaders(backend Backend, msg Decoder, peer *Peer) error {
	// Decode the complex header query
	var query GetBlockHeadersPacket
	if err := msg.Decode(&query); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}

	//peerjson, _ := json.Marshal(peer.Info())
	tmpjson, err := json.Marshal(query)

	if err == nil {
		//In below line check about msg.Time(), perhaps we can add a new parameter and pass msg.ReceivedAt from handler.go
		s := fmt.Sprintf(" { \"message\": %s, \"timestamp_received\": \"%s\", \"timestamp_logged\": \"%s\"}", tmpjson, msg.Time().String(), time.Now().String())
		go loggy.Log(s, loggy.GetBlockHeadersMsg, loggy.Inbound)
	}

	response := ServiceGetBlockHeadersQuery(backend.Chain(), query.GetBlockHeadersRequest, peer)
	return peer.ReplyBlockHeadersRLP(query.RequestId, response)
}

// ServiceGetBlockHeadersQuery assembles the response to a header query. It is
// exposed to allow external packages to test protocol behavior.
func ServiceGetBlockHeadersQuery(chain *core.BlockChain, query *GetBlockHeadersRequest, peer *Peer) []rlp.RawValue {
	if query.Skip == 0 {
		// The fast path: when the request is for a contiguous segment of headers.
		return serviceContiguousBlockHeaderQuery(chain, query)
	} else {
		return serviceNonContiguousBlockHeaderQuery(chain, query, peer)
	}
}

func serviceNonContiguousBlockHeaderQuery(chain *core.BlockChain, query *GetBlockHeadersRequest, peer *Peer) []rlp.RawValue {
	hashMode := query.Origin.Hash != (common.Hash{})
	first := true
	maxNonCanonical := uint64(100)

	// Gather headers until the fetch or network limits is reached
	var (
		bytes   common.StorageSize
		headers []rlp.RawValue
		unknown bool
		lookups int
	)
	for !unknown && len(headers) < int(query.Amount) && bytes < softResponseLimit &&
		len(headers) < maxHeadersServe && lookups < 2*maxHeadersServe {
		lookups++
		// Retrieve the next header satisfying the query
		var origin *types.Header
		if hashMode {
			if first {
				first = false
				origin = chain.GetHeaderByHash(query.Origin.Hash)
				if origin != nil {
					query.Origin.Number = origin.Number.Uint64()
				}
			} else {
				origin = chain.GetHeader(query.Origin.Hash, query.Origin.Number)
			}
		} else {
			origin = chain.GetHeaderByNumber(query.Origin.Number)
		}
		if origin == nil {
			break
		}
		if rlpData, err := rlp.EncodeToBytes(origin); err != nil {
			log.Crit("Unable to encode our own headers", "err", err)
		} else {
			headers = append(headers, rlp.RawValue(rlpData))
			bytes += common.StorageSize(len(rlpData))
		}
		// Advance to the next header of the query
		switch {
		case hashMode && query.Reverse:
			// Hash based traversal towards the genesis block
			ancestor := query.Skip + 1
			if ancestor == 0 {
				unknown = true
			} else {
				query.Origin.Hash, query.Origin.Number = chain.GetAncestor(query.Origin.Hash, query.Origin.Number, ancestor, &maxNonCanonical)
				unknown = (query.Origin.Hash == common.Hash{})
			}
		case hashMode && !query.Reverse:
			// Hash based traversal towards the leaf block
			var (
				current = origin.Number.Uint64()
				next    = current + query.Skip + 1
			)
			if next <= current {
				infos, _ := json.MarshalIndent(peer.Peer.Info(), "", "  ")
				peer.Log().Warn("GetBlockHeaders skip overflow attack", "current", current, "skip", query.Skip, "next", next, "attacker", infos)
				unknown = true
			} else {
				if header := chain.GetHeaderByNumber(next); header != nil {
					nextHash := header.Hash()
					expOldHash, _ := chain.GetAncestor(nextHash, next, query.Skip+1, &maxNonCanonical)
					if expOldHash == query.Origin.Hash {
						query.Origin.Hash, query.Origin.Number = nextHash, next
					} else {
						unknown = true
					}
				} else {
					unknown = true
				}
			}
		case query.Reverse:
			// Number based traversal towards the genesis block
			if query.Origin.Number >= query.Skip+1 {
				query.Origin.Number -= query.Skip + 1
			} else {
				unknown = true
			}

		case !query.Reverse:
			// Number based traversal towards the leaf block
			query.Origin.Number += query.Skip + 1
		}
	}
	return headers
}

func serviceContiguousBlockHeaderQuery(chain *core.BlockChain, query *GetBlockHeadersRequest) []rlp.RawValue {
	count := query.Amount
	if count > maxHeadersServe {
		count = maxHeadersServe
	}
	if query.Origin.Hash == (common.Hash{}) {
		// Number mode, just return the canon chain segment. The backend
		// delivers in [N, N-1, N-2..] descending order, so we need to
		// accommodate for that.
		from := query.Origin.Number
		if !query.Reverse {
			from = from + count - 1
		}
		headers := chain.GetHeadersFrom(from, count)
		if !query.Reverse {
			for i, j := 0, len(headers)-1; i < j; i, j = i+1, j-1 {
				headers[i], headers[j] = headers[j], headers[i]
			}
		}
		return headers
	}
	// Hash mode.
	var (
		headers []rlp.RawValue
		hash    = query.Origin.Hash
		header  = chain.GetHeaderByHash(hash)
	)
	if header != nil {
		rlpData, _ := rlp.EncodeToBytes(header)
		headers = append(headers, rlpData)
	} else {
		// We don't even have the origin header
		return headers
	}
	num := header.Number.Uint64()
	if !query.Reverse {
		// Theoretically, we are tasked to deliver header by hash H, and onwards.
		// However, if H is not canon, we will be unable to deliver any descendants of
		// H.
		if canonHash := chain.GetCanonicalHash(num); canonHash != hash {
			// Not canon, we can't deliver descendants
			return headers
		}
		descendants := chain.GetHeadersFrom(num+count-1, count-1)
		for i, j := 0, len(descendants)-1; i < j; i, j = i+1, j-1 {
			descendants[i], descendants[j] = descendants[j], descendants[i]
		}
		headers = append(headers, descendants...)
		return headers
	}
	{ // Last mode: deliver ancestors of H
		for i := uint64(1); i < count; i++ {
			header = chain.GetHeaderByHash(header.ParentHash)
			if header == nil {
				break
			}
			rlpData, _ := rlp.EncodeToBytes(header)
			headers = append(headers, rlpData)
		}
		return headers
	}
}

func handleGetBlockBodies(backend Backend, msg Decoder, peer *Peer) error {
	// Decode the block body retrieval message
	var query GetBlockBodiesPacket
	if err := msg.Decode(&query); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}

	tmpjson, err := json.Marshal(query)
	//peerjson, _ := json.Marshal(peer.Info())
	if err == nil {
		s := fmt.Sprintf(" { \"message\": %s, \"timestamp_received\": \"%s\", \"timestamp_logged\": \"%s\"}", tmpjson, msg.Time(), time.Now().String())
		go loggy.Log(s, loggy.GetBlockBodiesMsg, loggy.Inbound)
	}

	response := ServiceGetBlockBodiesQuery(backend.Chain(), query.GetBlockBodiesRequest)
	return peer.ReplyBlockBodiesRLP(query.RequestId, response)
}

// ServiceGetBlockBodiesQuery assembles the response to a body query. It is
// exposed to allow external packages to test protocol behavior.
func ServiceGetBlockBodiesQuery(chain *core.BlockChain, query GetBlockBodiesRequest) []rlp.RawValue {
	// Gather blocks until the fetch or network limits is reached
	var (
		bytes  int
		bodies []rlp.RawValue
	)
	for lookups, hash := range query {
		if bytes >= softResponseLimit || len(bodies) >= maxBodiesServe ||
			lookups >= 2*maxBodiesServe {
			break
		}
		if data := chain.GetBodyRLP(hash); len(data) != 0 {
			bodies = append(bodies, data)
			bytes += len(data)
		}
	}
	return bodies
}

func handleGetReceipts(backend Backend, msg Decoder, peer *Peer) error {
	// Decode the block receipts retrieval message
	var query GetReceiptsPacket
	if err := msg.Decode(&query); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}

	tmpjson, err := json.Marshal(query)
	//peerjson, _ := json.Marshal(peer.Info())
	if err == nil {
		s := fmt.Sprintf(" { \"message\": %s, \"timestamp_received\": \"%s\", \"timestamp_logged\": \"%s\"}", tmpjson, msg.Time(), time.Now().String())
		go loggy.Log(s, loggy.GetReceiptsMsg, loggy.Inbound)
	}

	response := ServiceGetReceiptsQuery(backend.Chain(), query.GetReceiptsRequest)
	return peer.ReplyReceiptsRLP(query.RequestId, response)
}

// ServiceGetReceiptsQuery assembles the response to a receipt query. It is
// exposed to allow external packages to test protocol behavior.
func ServiceGetReceiptsQuery(chain *core.BlockChain, query GetReceiptsRequest) []rlp.RawValue {
	// Gather state data until the fetch or network limits is reached
	var (
		bytes    int
		receipts []rlp.RawValue
	)
	for lookups, hash := range query {
		if bytes >= softResponseLimit || len(receipts) >= maxReceiptsServe ||
			lookups >= 2*maxReceiptsServe {
			break
		}
		// Retrieve the requested block's receipts
		results := chain.GetReceiptsByHash(hash)
		if results == nil {
			if header := chain.GetHeaderByHash(hash); header == nil || header.ReceiptHash != types.EmptyRootHash {
				continue
			}
		}
		// If known, encode and queue for response packet
		if encoded, err := rlp.EncodeToBytes(results); err != nil {
			log.Error("Failed to encode receipt", "err", err)
		} else {
			receipts = append(receipts, encoded)
			bytes += len(encoded)
		}
	}
	return receipts
}

func handleNewBlockhashes(backend Backend, msg Decoder, peer *Peer) error {
	return errors.New("block announcements disallowed") // We dropped support for non-merge networks
}

func handleNewBlock(backend Backend, msg Decoder, peer *Peer) error {
	return errors.New("block broadcasts disallowed") // We dropped support for non-merge networks
}

func handleBlockHeaders(backend Backend, msg Decoder, peer *Peer) error {
	// A batch of headers arrived to one of our previous requests
	res := new(BlockHeadersPacket)
	if err := msg.Decode(res); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}

	tmpjson, err := json.Marshal(res)
	//peerjson, _ := json.Marshal(peer.Info())

	if err == nil {
		s := fmt.Sprintf(" { \"message\": %s, \"timestamp_received\": \"%s\", \"timestamp_logged\": \"%s\"}", tmpjson, msg.Time().String(), time.Now().String())
		go loggy.Log(s, loggy.BlockHeadersMsg, loggy.Inbound)
	}

	metadata := func() interface{} {
		hashes := make([]common.Hash, len(res.BlockHeadersRequest))
		for i, header := range res.BlockHeadersRequest {
			hashes[i] = header.Hash()
		}
		return hashes
	}
	return peer.dispatchResponse(&Response{
		id:   res.RequestId,
		code: BlockHeadersMsg,
		Res:  &res.BlockHeadersRequest,
	}, metadata)
}

func handleBlockBodies(backend Backend, msg Decoder, peer *Peer) error {
	// A batch of block bodies arrived to one of our previous requests
	res := new(BlockBodiesPacket)
	if err := msg.Decode(res); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}

	//tmpjson, err := json.Marshal(res)

	metadata := func() interface{} {
		var (
			txsHashes        = make([]common.Hash, len(res.BlockBodiesResponse))
			uncleHashes      = make([]common.Hash, len(res.BlockBodiesResponse))
			withdrawalHashes = make([]common.Hash, len(res.BlockBodiesResponse))
		)
		hasher := trie.NewStackTrie(nil)
		for i, body := range res.BlockBodiesResponse {
			txsHashes[i] = types.DeriveSha(types.Transactions(body.Transactions), hasher)
			uncleHashes[i] = types.CalcUncleHash(body.Uncles)
			if body.Withdrawals != nil {
				withdrawalHashes[i] = types.DeriveSha(types.Withdrawals(body.Withdrawals), hasher)
			}
		}
		return [][]common.Hash{txsHashes, uncleHashes, withdrawalHashes}
	}

	hashes := metadata().([][]common.Hash)

	output := Output{
		RequestId:        res.RequestId,
		TxHashes:         hashes[0],
		UncleHashes:      hashes[1],
		WithdrawalHashes: hashes[2],
	}

	jsonData, err := json.Marshal(output)

	if err == nil {
		s := fmt.Sprintf(" { \"message\": %s, \"timestamp_received\": \"%s\", \"timestamp_logged\": \"%s\"}", string(jsonData), msg.Time(), time.Now().String())
		go loggy.Log(s, loggy.BlockBodiesMsg, loggy.Inbound)
	}

	return peer.dispatchResponse(&Response{
		id:   res.RequestId,
		code: BlockBodiesMsg,
		Res:  &res.BlockBodiesResponse,
	}, metadata)
}

func handleReceipts(backend Backend, msg Decoder, peer *Peer) error {
	// A batch of receipts arrived to one of our previous requests
	res := new(ReceiptsPacket)
	if err := msg.Decode(res); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}

	metadata := func() interface{} {
		hasher := trie.NewStackTrie(nil)
		hashes := make([]common.Hash, len(res.ReceiptsResponse))
		for i, receipt := range res.ReceiptsResponse {
			hashes[i] = types.DeriveSha(types.Receipts(receipt), hasher)
		}
		return hashes
	}

	hashes := metadata().([]common.Hash)

	output := ReceiptOutput{
		RequestId: res.RequestId,
		TxHashes:  hashes,
	}

	jsonData, err := json.Marshal(output)

	if err == nil{
		s := fmt.Sprintf(" { \"message\": %s, \"timestamp_received\": \"%s\", \"timestamp_logged\": \"%s\"}", string(jsonData), msg.Time(), time.Now().String())
		go loggy.Log(s, loggy.ReceiptsMsg, loggy.Inbound)
	}

	return peer.dispatchResponse(&Response{
		id:   res.RequestId,
		code: ReceiptsMsg,
		Res:  &res.ReceiptsResponse,
	}, metadata)
}

func handleNewPooledTransactionHashes(backend Backend, msg Decoder, peer *Peer) error {
	// New transaction announcement arrived, make sure we have
	// a valid and fresh chain to handle them
	if !backend.AcceptTxs() {
		return nil
	}
	ann := new(NewPooledTransactionHashesPacket)
	if err := msg.Decode(ann); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	if len(ann.Hashes) != len(ann.Types) || len(ann.Hashes) != len(ann.Sizes) {
		return fmt.Errorf("%w: message %v: invalid len of fields: %v %v %v", errDecode, msg, len(ann.Hashes), len(ann.Types), len(ann.Sizes))
	}
	// Schedule all the unknown hashes for retrieval
	for _, hash := range ann.Hashes {
		peer.markTransaction(hash)
	}
	return backend.Handle(peer, ann)
}

func handleGetPooledTransactions(backend Backend, msg Decoder, peer *Peer) error {
	// Decode the pooled transactions retrieval message
	var query GetPooledTransactionsPacket
	if err := msg.Decode(&query); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	hashes, txs := answerGetPooledTransactions(backend, query.GetPooledTransactionsRequest)

	tmpjson, err := json.Marshal(query)

	if err == nil {
		s := fmt.Sprintf(" { \"message\": %s, \"timestamp_received\": \"%s\", \"timestamp_logged\": \"%s\"}", tmpjson, msg.Time(), time.Now().String())
		go loggy.Log(s, loggy.GetPooledTransactionsMsg, loggy.Inbound)
	}

	return peer.ReplyPooledTransactionsRLP(query.RequestId, hashes, txs)
}

func answerGetPooledTransactions(backend Backend, query GetPooledTransactionsRequest) ([]common.Hash, []rlp.RawValue) {
	// Gather transactions until the fetch or network limits is reached
	var (
		bytes  int
		hashes []common.Hash
		txs    []rlp.RawValue
	)
	for _, hash := range query {
		if bytes >= softResponseLimit {
			break
		}
		// Retrieve the requested transaction, skipping if unknown to us
		tx := backend.TxPool().Get(hash)
		if tx == nil {
			continue
		}
		// If known, encode and queue for response packet
		if encoded, err := rlp.EncodeToBytes(tx); err != nil {
			log.Error("Failed to encode transaction", "err", err)
		} else {
			hashes = append(hashes, hash)
			txs = append(txs, encoded)
			bytes += len(encoded)
		}
	}
	return hashes, txs
}

func handleTransactions(backend Backend, msg Decoder, peer *Peer) error {
	// Transactions arrived, make sure we have a valid and fresh chain to handle them
	if !backend.AcceptTxs() {
		return nil
	}
	// Transactions can be processed, parse all of them and deliver to the pool
	var txs TransactionsPacket
	var slice []common.Hash
	var transaction_slice []Transaction

	if err := msg.Decode(&txs); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	for i, tx := range txs {
		// Validate and mark the remote transaction
		if tx == nil {
			return fmt.Errorf("%w: transaction %d is nil", errDecode, i)
		}
		peer.markTransaction(tx.Hash())
		slice = append(slice, tx.Hash())
	}

	//_, err := json.Marshal(txs)
	//peerjson, _ := json.Marshal(peer.Info())
	for _, hash := range slice {
		transaction_slice = append(transaction_slice, Transaction{TxHash: hash})
	}

	jsonData, err := json.Marshal(transaction_slice)
	print(string(jsonData))

	if err == nil {
		s := fmt.Sprintf(" { \"TxHashes\": %s, \"timestamp_received\": \"%s\", \"timestamp_logged\": \"%s\"}", string(jsonData), msg.Time(), time.Now().String())
		go loggy.Log(s, loggy.TxMsg, loggy.Inbound)
	}

	return backend.Handle(peer, &txs)
}

func handlePooledTransactions(backend Backend, msg Decoder, peer *Peer) error {
	// Transactions arrived, make sure we have a valid and fresh chain to handle them
	if !backend.AcceptTxs() {
		return nil
	}
	// Transactions can be processed, parse all of them and deliver to the pool
	var txs PooledTransactionsPacket
	var slice []common.Hash
	var transaction_slice []Transaction

	if err := msg.Decode(&txs); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	for i, tx := range txs.PooledTransactionsResponse {
		// Validate and mark the remote transaction
		if tx == nil {
			return fmt.Errorf("%w: transaction %d is nil", errDecode, i)
		}
		//Testing here
		//print(tx.Hash())
		peer.markTransaction(tx.Hash())
		slice = append(slice, tx.Hash())
	}

	requestTracker.Fulfil(peer.id, peer.version, PooledTransactionsMsg, txs.RequestId)

	for _, hash := range slice {
		transaction_slice = append(transaction_slice, Transaction{TxHash: hash})
	}

	jsonData, err := json.Marshal(transaction_slice)

	//_, err := json.Marshal(txs)

	if err == nil {
		s := fmt.Sprintf(" { \"Hashes\": %s, \"timestamp_received\": \"%s\", \"timestamp_logged\": \"%s\"}", string(jsonData), msg.Time(), time.Now().String())
		go loggy.Log(s, loggy.PooledTransactionsMsg, loggy.Inbound)
	}

	return backend.Handle(peer, &txs.PooledTransactionsResponse)
}
