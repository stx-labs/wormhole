package stacks

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/certusone/wormhole/node/pkg/common"
	gossipv1 "github.com/certusone/wormhole/node/pkg/proto/gossip/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wormhole-foundation/wormhole/sdk/vaa"
	"go.uber.org/zap/zaptest"
)

// Test constants for expected values from fixtures
const (
	// Timeouts
	testChannelTimeout = 100 * time.Millisecond

	// Expected values from block_replay_success.json fixture - first event
	expectedNonceEvent1            = uint32(1642056152)
	expectedSequenceEvent1         = uint64(5)
	expectedConsistencyLevelEvent1 = uint8(0)
	expectedEmitterAddrEvent1      = "da36b89828d4e22d80ffd897c89ed4780fcac601e1d6839f0c1a3eb332914b2f"
	expectedPayloadHexEvent1       = "746573742d7061796c6f61642d737563636573732d63617365"
	expectedPayloadDecodedEvent1   = "test-payload-success-case"

	// Expected values for second event in multi-event test
	expectedNonceEvent2            = uint32(0)
	expectedSequenceEvent2         = uint64(20)
	expectedConsistencyLevelEvent2 = uint8(255)
	expectedEmitterAddrEvent2      = "5555555555555555555555555555555555555555555555555555555555555555"
	expectedPayloadHexEvent2       = "11223344"

	// Modified emitter address for contract principal test
	expectedEmitterAddrContractPrincipal = "da36b89828d4e22d80ffd897c89ed4780fcac601e1d6839f0c1a3eb332914b21"

	// Clarity-encoded event data for testing
	// (to-consensus-buff? { data: { consistency-level: u0, emitter: 0xda36..., ... }, event: "not-post-message" })
	clarityEventNotPostMessage = "0x0c0000000204646174610c0000000611636f6e73697374656e63792d6c6576656c010000000000000000000000000000000007656d69747465720200000020da36b89828d4e22d80ffd897c89ed4780fcac601e1d6839f0c1a3eb332914b2f11656d69747465722d7072696e636970616c051a0bfe0d6c01e84b08f37c8d291ad3d2c35e1d3988056e6f6e63650100000000000000000000000061dfc9d8077061796c6f61640200000019746573742d7061796c6f61642d737563636573732d636173650873657175656e63650100000000000000000000000000000005056576656e740d000000106e6f742d706f73742d6d657373616765"

	// (to-consensus-buff? { data: { consistency-level: u255, emitter: 0x5555..., nonce: u0, payload: 0x11223344, sequence: u20 }, event: "post-message" })
	clarityEventAlternate = "0x0c0000000204646174610c0000000611636f6e73697374656e63792d6c6576656c01000000000000000000000000000000ff07656d69747465720200000020555555555555555555555555555555555555555555555555555555555555555511656d69747465722d7072696e636970616c051a0bfe0d6c01e84b08f37c8d291ad3d2c35e1d3988056e6f6e63650100000000000000000000000000000000077061796c6f61640200000004112233440873657175656e63650100000000000000000000000000000014056576656e740d0000000c706f73742d6d657373616765"

	// (to-consensus-buff? { data: { consistency-level: u0, emitter: 0xda36...21, emitter-principal: 'ST5ZW3BC07M4P27KFJ6JJ6PKTB1NW79SH0BVYB3W.contract, ... }, event: "post-message" })
	clarityEventContractPrincipal = "0x0c0000000204646174610c0000000611636f6e73697374656e63792d6c6576656c010000000000000000000000000000000007656d69747465720200000020da36b89828d4e22d80ffd897c89ed4780fcac601e1d6839f0c1a3eb332914b2111656d69747465722d7072696e636970616c061a0bfe0d6c01e84b08f37c8d291ad3d2c35e1d398808636f6e7472616374056e6f6e63650100000000000000000000000061dfc9d8077061796c6f61640200000019746573742d7061796c6f61642d737563636573732d636173650873657175656e63650100000000000000000000000000000005056576656e740d0000000c706f73742d6d657373616765"

	// Error response hex (err ...) instead of (ok ...)
	clarityErrorResponseHex = "0x080c0000000611636f6e73697374656e63792d6c6576656c010000000000000000000000000000000007656d69747465720200000020da36b89828d4e22d80ffd897c89ed4780fcac601e1d6839f0c1a3eb332914b2f11656d69747465722d7072696e636970616c051a0bfe0d6c01e84b08f37c8d291ad3d2c35e1d3988056e6f6e63650100000000000000000000000061dfc9d8077061796c6f61640200000019746573742d7061796c6f61642d737563636573732d636173650873657175656e63650100000000000000000000000000000005"

	clarityEventWrongSizePrincipal = "0x0c0000000204646174610c0000000611636f6e73697374656e63792d6c6576656c010000000000000000000000000000000007656d69747465720200000021da36b89828d4e22d80ffd897c89ed4780fcac601e1d6839f0c1a3eb332914b21ff11656d69747465722d7072696e636970616c061a0bfe0d6c01e84b08f37c8d291ad3d2c35e1d398808636f6e7472616374056e6f6e63650100000000000000000000000061dfc9d8077061796c6f61640200000019746573742d7061796c6f61642d737563636573732d636173650873657175656e63650100000000000000000000000000000005056576656e740d0000000c706f73742d6d657373616765"

	clarityEventNonceTooLarge = "0x0c0000000204646174610c0000000611636f6e73697374656e63792d6c6576656c010000000000000000000000000000000007656d69747465720200000020da36b89828d4e22d80ffd897c89ed4780fcac601e1d6839f0c1a3eb332914b2111656d69747465722d7072696e636970616c061a0bfe0d6c01e84b08f37c8d291ad3d2c35e1d398808636f6e7472616374056e6f6e63650100000000000000000000000100000000077061796c6f61640200000019746573742d7061796c6f61642d737563636573732d636173650873657175656e63650100000000000000000000000000000005056576656e740d0000000c706f73742d6d657373616765"

	clarityEventNonceWrongType = "0x0c0000000204646174610c0000000611636f6e73697374656e63792d6c6576656c010000000000000000000000000000000007656d69747465720200000020da36b89828d4e22d80ffd897c89ed4780fcac601e1d6839f0c1a3eb332914b2111656d69747465722d7072696e636970616c061a0bfe0d6c01e84b08f37c8d291ad3d2c35e1d398808636f6e7472616374056e6f6e63650000000000000000000000000000000001077061796c6f61640200000019746573742d7061796c6f61642d737563636573732d636173650873657175656e63650100000000000000000000000000000005056576656e740d0000000c706f73742d6d657373616765"

	clarityEventSequenceTooLarge = "0x0c0000000204646174610c0000000611636f6e73697374656e63792d6c6576656c010000000000000000000000000000000007656d69747465720200000021da36b89828d4e22d80ffd897c89ed4780fcac601e1d6839f0c1a3eb332914b21ff11656d69747465722d7072696e636970616c061a0bfe0d6c01e84b08f37c8d291ad3d2c35e1d398808636f6e7472616374056e6f6e63650100000000000000000000000061dfc9d8077061796c6f61640200000019746573742d7061796c6f61642d737563636573732d636173650873657175656e63650100000000000000010000000000000000056576656e740d0000000c706f73742d6d657373616765"

	clarityEventConsistencyLevelTooLarge = "0x0c0000000204646174610c0000000611636f6e73697374656e63792d6c6576656c010000000000000000000000000000006f07656d69747465720200000021da36b89828d4e22d80ffd897c89ed4780fcac601e1d6839f0c1a3eb332914b21ff11656d69747465722d7072696e636970616c061a0bfe0d6c01e84b08f37c8d291ad3d2c35e1d398808636f6e7472616374056e6f6e63650100000000000000000000000061dfc9d8077061796c6f61640200000019746573742d7061796c6f61642d737563636573732d636173650873657175656e63650100000000000000000000000000000001056576656e740d0000000c706f73742d6d657373616765"

	clarityEventMissingSequence = "0x0c0000000204646174610c0000000511636f6e73697374656e63792d6c6576656c010000000000000000000000000000000007656d69747465720200000020da36b89828d4e22d80ffd897c89ed4780fcac601e1d6839f0c1a3eb332914b2111656d69747465722d7072696e636970616c061a0bfe0d6c01e84b08f37c8d291ad3d2c35e1d398808636f6e7472616374056e6f6e63650100000000000000000000000061dfc9d8077061796c6f61640200000019746573742d7061796c6f61642d737563636573732d63617365056576656e740d0000000c706f73742d6d657373616765"

	clarityEventMissingDataTuple = "0x0c00000002056576656e740d0000000c706f73742d6d657373616765086e6f742d646174610c0000000511636f6e73697374656e63792d6c6576656c010000000000000000000000000000000007656d69747465720200000020da36b89828d4e22d80ffd897c89ed4780fcac601e1d6839f0c1a3eb332914b2111656d69747465722d7072696e636970616c061a0bfe0d6c01e84b08f37c8d291ad3d2c35e1d398808636f6e7472616374056e6f6e63650100000000000000000000000061dfc9d8077061796c6f61640200000019746573742d7061796c6f61642d737563636573732d63617365"
)

// TestFixtures holds all test fixture data
type TestFixtures struct {
	BlockReplaySuccess       *StacksV3TenureBlockReplayResponse
	TransactionFailedVmError *StacksV3TenureBlockTransaction
}

// loadFixtures loads all JSON fixtures from testdata directory
func loadFixtures(t *testing.T) *TestFixtures {
	t.Helper()

	fixtures := &TestFixtures{}

	// Load block replay
	fixtures.BlockReplaySuccess = loadJSON[StacksV3TenureBlockReplayResponse](t, "block_replay_success.json")

	// Load abort failed tx
	fixtures.TransactionFailedVmError = loadJSON[StacksV3TenureBlockTransaction](t, "transaction_failed_vm_error.json")

	return fixtures
}

// loadJSON is a generic helper to load and unmarshal JSON fixtures
func loadJSON[T any](t *testing.T, filename string) *T {
	t.Helper()

	path := filepath.Join("testdata", filename)
	data, err := os.ReadFile(path)
	require.NoError(t, err, "failed to read fixture file: %s", filename)

	var result T
	err = json.Unmarshal(data, &result)
	require.NoError(t, err, "failed to unmarshal fixture file: %s", filename)

	return &result
}

// setupTestWatcher creates a test watcher with a message channel
func setupTestWatcher(t *testing.T) (*Watcher, chan *common.MessagePublication) {
	t.Helper()

	msgC := make(chan *common.MessagePublication, 10)
	obsvReqC := make(chan *gossipv1.ObservationRequest)

	watcher := NewWatcher(
		"http://localhost:20443",
		"",
		"ST5ZW3BC07M4P27KFJ6JJ6PKTB1NW79SH0BVYB3W.wormhole-core-state",
		2*time.Second,
		msgC,
		obsvReqC,
	)

	return watcher, msgC
}

// cloneBlockReplay creates a deep copy of a block replay response
func cloneBlockReplay(t *testing.T, original *StacksV3TenureBlockReplayResponse) *StacksV3TenureBlockReplayResponse {
	t.Helper()

	data, err := json.Marshal(original)
	require.NoError(t, err, "failed to marshal block replay")

	var clone StacksV3TenureBlockReplayResponse
	err = json.Unmarshal(data, &clone)
	require.NoError(t, err, "failed to unmarshal block replay")

	return &clone
}

// cloneTransaction creates a deep copy of a transaction
func cloneTransaction(t *testing.T, original *StacksV3TenureBlockTransaction) *StacksV3TenureBlockTransaction {
	t.Helper()

	data, err := json.Marshal(original)
	require.NoError(t, err, "failed to marshal transaction")

	var clone StacksV3TenureBlockTransaction
	err = json.Unmarshal(data, &clone)
	require.NoError(t, err, "failed to unmarshal transaction")

	return &clone
}

// TestProcessStacksTransaction_Success tests processing a successful Wormhole transaction
func TestProcessStacksTransaction_Success(t *testing.T) {
	fixtures := loadFixtures(t)
	watcher, msgC := setupTestWatcher(t)
	logger := zaptest.NewLogger(t)

	// Use the successful transaction from the fixture
	replay := cloneBlockReplay(t, fixtures.BlockReplaySuccess)
	tx := &replay.Transactions[0]

	ctx := context.Background()
	err := watcher.processStacksTransaction(ctx, tx, replay, true, logger)
	assert.NoError(t, err)

	// Should emit a message
	select {
	case msg := <-msgC:
		assert.NotNil(t, msg)
		assert.Equal(t, tx.TxId, hex.EncodeToString(msg.TxID))
		//nolint:gosec // Safe based upon known values
		assert.Equal(t, time.Unix(int64(replay.Timestamp), 0), msg.Timestamp)
		assert.Equal(t, expectedConsistencyLevelEvent1, msg.ConsistencyLevel)
		assert.Equal(t, expectedNonceEvent1, msg.Nonce)
		assert.Equal(t, vaa.ChainIDStacks, msg.EmitterChain)
		assert.Equal(t, expectedEmitterAddrEvent1, msg.EmitterAddress.String())
		assert.Equal(t, expectedSequenceEvent1, msg.Sequence)
		assert.Equal(t, expectedPayloadHexEvent1, hex.EncodeToString(msg.Payload))
		assert.Equal(t, true, msg.IsReobservation)
		t.Logf("Received message publication: TxID=%s, Sequence=%d", msg.TxIDString(), msg.Sequence)
	case <-time.After(testChannelTimeout):
		t.Fatal("Expected message to be sent to msgC")
	}

	// Should NOT emit a second message
	select {
	case msg := <-msgC:
		t.Fatalf("Unexpected message sent for failed transaction: %+v", msg)
	case <-time.After(testChannelTimeout):
		// Expected - no message
	}
}

// TestProcessStacksTransaction_FailedVmError tests a transaction with VM error
func TestProcessStacksTransaction_FailedVmError(t *testing.T) {
	fixtures := loadFixtures(t)
	watcher, msgC := setupTestWatcher(t)
	logger := zaptest.NewLogger(t)

	replay := cloneBlockReplay(t, fixtures.BlockReplaySuccess)
	tx := cloneTransaction(t, fixtures.TransactionFailedVmError)
	// Need to force the error code path to be hit.
	tx.PostConditionAborted = false

	ctx := context.Background()
	err := watcher.processStacksTransaction(ctx, tx, replay, false, logger)

	// Should fail due to VM error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "runtime error")

	// Should NOT emit a message
	select {
	case msg := <-msgC:
		t.Fatalf("Unexpected message sent for failed transaction: %+v", msg)
	case <-time.After(testChannelTimeout):
		// Expected - no message
	}
}

// Tests a transaction when 'PostConditionAborted' is set to true.
func TestProcessStacksTransaction_FailedPostConditionAbort(t *testing.T) {
	fixtures := loadFixtures(t)
	watcher, msgC := setupTestWatcher(t)
	logger := zaptest.NewLogger(t)

	replay := cloneBlockReplay(t, fixtures.BlockReplaySuccess)
	tx := &replay.Transactions[0]
	tx.PostConditionAborted = true

	ctx := context.Background()
	err := watcher.processStacksTransaction(ctx, tx, replay, false, logger)

	// Should fail due to post condition abort
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "post-condition aborted")

	// Should NOT emit a message
	select {
	case msg := <-msgC:
		t.Fatalf("Unexpected message sent for failed transaction: %+v", msg)
	case <-time.After(testChannelTimeout):
		// Expected - no message
	}
}

// Tests a transaction when the result has an error type in the response data.
func TestProcessStacksTransaction_FailedErrorResponse(t *testing.T) {
	fixtures := loadFixtures(t)
	watcher, msgC := setupTestWatcher(t)
	logger := zaptest.NewLogger(t)

	replay := cloneBlockReplay(t, fixtures.BlockReplaySuccess)
	tx := &replay.Transactions[0]
	tx.ResultHex = clarityErrorResponseHex

	ctx := context.Background()
	err := watcher.processStacksTransaction(ctx, tx, replay, false, logger)

	// Should fail due to error in the response data
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed due to response hex")

	// Should NOT emit a message
	select {
	case msg := <-msgC:
		t.Fatalf("Unexpected message sent for failed transaction: %+v", msg)
	case <-time.After(testChannelTimeout):
		// Expected - no message
	}
}

// TestProcessStacksTransaction_FailedCommitted tests a transaction that failed to commit
func TestProcessStacksTransaction_FailedCommitted(t *testing.T) {
	fixtures := loadFixtures(t)
	watcher, msgC := setupTestWatcher(t)
	logger := zaptest.NewLogger(t)

	replay := cloneBlockReplay(t, fixtures.BlockReplaySuccess)
	tx := &replay.Transactions[0]

	// Modify: Set committed to false
	tx.Result = map[string]interface{}{
		"Response": map[string]interface{}{
			"committed": false,
		},
	}

	ctx := context.Background()
	err := watcher.processStacksTransaction(ctx, tx, replay, false, logger)

	// Should fail due to not committed
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed due to response")

	// Should NOT emit a message
	select {
	case msg := <-msgC:
		t.Fatalf("Unexpected message sent for uncommitted transaction: %+v", msg)
	case <-time.After(testChannelTimeout):
		// Expected - no message
	}
}

// Tests a tranaction where there are no events.
func TestProcessStacksTransaction_NoEvents(t *testing.T) {
	fixtures := loadFixtures(t)
	watcher, msgC := setupTestWatcher(t)
	logger := zaptest.NewLogger(t)

	// Use the successful transaction from the fixture
	replay := cloneBlockReplay(t, fixtures.BlockReplaySuccess)
	tx := &replay.Transactions[0]
	tx.Events = []StacksEvent{}

	ctx := context.Background()
	err := watcher.processStacksTransaction(ctx, tx, replay, false, logger)
	assert.NoError(t, err)

	// Should emit a message
	select {
	case msg := <-msgC:
		t.Fatalf("Unexpected message sent for uncommitted transaction: %+v", msg)
	case <-time.After(testChannelTimeout):
		// Expected - no message
	}
}

// Test a transaction that has multiple valid events
func TestProcessStacksTransaction_MultipleEvents(t *testing.T) {
	fixtures := loadFixtures(t)
	watcher, msgC := setupTestWatcher(t)
	logger := zaptest.NewLogger(t)

	// Use the successful transaction from the fixture
	replay := cloneBlockReplay(t, fixtures.BlockReplaySuccess)
	tx := &replay.Transactions[0]
	originalEvent := tx.Events[1]

	// Clone the event to avoid modifying the original
	eventData, marshalErr := json.Marshal(originalEvent)
	require.NoError(t, marshalErr, "failed to marshal event")

	var newEvent StacksEvent
	unmarshalErr := json.Unmarshal(eventData, &newEvent)
	require.NoError(t, unmarshalErr, "failed to unmarshal event")

	// (to-consensus-buff? { data: { consistency-level: u255, emitter: 0x5555..., nonce: u0, payload: 0x11223344, sequence: u20 }, event: "post-message" })
	newEvent.ContractEvent.RawValue = clarityEventAlternate
	tx.Events = append(tx.Events, newEvent)

	ctx := context.Background()
	err := watcher.processStacksTransaction(ctx, tx, replay, true, logger)
	assert.NoError(t, err)

	// Should emit a first event
	select {
	case msg := <-msgC:
		assert.NotNil(t, msg)
		assert.Equal(t, tx.TxId, hex.EncodeToString(msg.TxID))
		//nolint:gosec // Safe based upon known values
		assert.Equal(t, time.Unix(int64(replay.Timestamp), 0), msg.Timestamp)
		assert.Equal(t, expectedConsistencyLevelEvent1, msg.ConsistencyLevel)
		assert.Equal(t, expectedNonceEvent1, msg.Nonce)
		assert.Equal(t, vaa.ChainIDStacks, msg.EmitterChain)
		assert.Equal(t, expectedEmitterAddrEvent1, msg.EmitterAddress.String())
		assert.Equal(t, expectedSequenceEvent1, msg.Sequence)
		assert.Equal(t, true, msg.IsReobservation)
	case <-time.After(testChannelTimeout):
		t.Fatal("Expected message to be sent to msgC")
	}

	// Should emit a second message
	select {
	case msg := <-msgC:
		assert.NotNil(t, msg)
		assert.Equal(t, tx.TxId, hex.EncodeToString(msg.TxID))
		//nolint:gosec // Safe based upon known values
		assert.Equal(t, time.Unix(int64(replay.Timestamp), 0), msg.Timestamp)
		assert.Equal(t, expectedConsistencyLevelEvent2, msg.ConsistencyLevel)
		assert.Equal(t, expectedNonceEvent2, msg.Nonce)
		assert.Equal(t, vaa.ChainIDStacks, msg.EmitterChain)
		assert.Equal(t, expectedEmitterAddrEvent2, msg.EmitterAddress.String())
		assert.Equal(t, expectedSequenceEvent2, msg.Sequence)
		assert.Equal(t, true, msg.IsReobservation)
	case <-time.After(testChannelTimeout):
		t.Fatal("Expected message to be sent to msgC")
	}

	// Should NOT emit a third message
	select {
	case msg := <-msgC:
		t.Fatalf("Unexpected message sent for failed transaction: %+v", msg)
	case <-time.After(testChannelTimeout):
		// Expected - no message
	}
}

// Success with contract principal instead of a regular principal.
func TestProcessStacksTransaction_SuccessContractCallWithPrincipal(t *testing.T) {
	fixtures := loadFixtures(t)
	watcher, msgC := setupTestWatcher(t)
	logger := zaptest.NewLogger(t)

	replay := cloneBlockReplay(t, fixtures.BlockReplaySuccess)
	tx := &replay.Transactions[0]

	// Sets the principal to be a contract
	// (to-consensus-buff? { data: { emitter: 0xda36...21, emitter-principal: 'ST5ZW3BC07M4P27KFJ6JJ6PKTB1NW79SH0BVYB3W.contract, ... }, event: "post-message" })
	tx.Events[1].ContractEvent.RawValue = clarityEventContractPrincipal

	ctx := context.Background()
	err := watcher.processStacksTransaction(ctx, tx, replay, false, logger)

	assert.Nil(t, err)

	select {
	case msg := <-msgC:
		assert.NotNil(t, msg)
		assert.Equal(t, tx.TxId, hex.EncodeToString(msg.TxID))
		//nolint:gosec // Safe based upon known values
		assert.Equal(t, time.Unix(int64(replay.Timestamp), 0), msg.Timestamp)
		assert.Equal(t, expectedConsistencyLevelEvent1, msg.ConsistencyLevel)
		assert.Equal(t, expectedNonceEvent1, msg.Nonce)
		assert.Equal(t, vaa.ChainIDStacks, msg.EmitterChain)
		assert.Equal(t, expectedEmitterAddrContractPrincipal, msg.EmitterAddress.String())
		assert.Equal(t, expectedSequenceEvent1, msg.Sequence)
		assert.Equal(t, expectedPayloadHexEvent1, hex.EncodeToString(msg.Payload))
		assert.Equal(t, false, msg.IsReobservation)
		t.Logf("Received message publication: TxID=%s, Sequence=%d", msg.TxIDString(), msg.Sequence)
	case <-time.After(testChannelTimeout):
		t.Fatal("Expected message to be sent to msgC")
	}

	// Should NOT emit a second message
	select {
	case msg := <-msgC:
		t.Fatalf("Unexpected message sent for failed transaction: %+v", msg)
	case <-time.After(testChannelTimeout):
		// Expected - no message
	}
}

// TestProcessStacksTransaction_FailedVmError tests a transaction with VM error
func TestProcessStacksTransaction_FailedWrongContractEmitterContract(t *testing.T) {
	fixtures := loadFixtures(t)
	watcher, msgC := setupTestWatcher(t)
	logger := zaptest.NewLogger(t)

	replay := cloneBlockReplay(t, fixtures.BlockReplaySuccess)
	tx := &replay.Transactions[0]
	tx.Events[1].ContractEvent.ContractIdentifier = "ST5ZW3BC07M4P27KFJ6JJ6PKTB1NW79SH0BVYB3W.wrong-contract"

	ctx := context.Background()
	err := watcher.processStacksTransaction(ctx, tx, replay, false, logger)
	assert.Nil(t, err)

	// Should NOT emit a message
	select {
	case msg := <-msgC:
		t.Fatalf("Unexpected message sent for failed transaction: %+v", msg)
	case <-time.After(testChannelTimeout):
		// Expected - no message
	}
}

// Tests a transaction where the event has the incorrect emitter address
func TestProcessStacksTransaction_FailedWrongContractEmitterKey(t *testing.T) {
	fixtures := loadFixtures(t)
	watcher, msgC := setupTestWatcher(t)
	logger := zaptest.NewLogger(t)

	replay := cloneBlockReplay(t, fixtures.BlockReplaySuccess)
	tx := &replay.Transactions[0]
	tx.Events[1].ContractEvent.ContractIdentifier = "ST1WNJTS9JM1JYGK758B10DBAMBZ0K23ADP392SBV.wormhole-core-state"

	ctx := context.Background()
	err := watcher.processStacksTransaction(ctx, tx, replay, false, logger)
	assert.Nil(t, err)

	// Should NOT emit a message
	select {
	case msg := <-msgC:
		t.Fatalf("Unexpected message sent for failed transaction: %+v", msg)
	case <-time.After(testChannelTimeout):
		// Expected - no message
	}
}

// Tests a transaction where the event itself is not committed (different than the transaction not being committed)
func TestProcessStacksTransaction_FailedEventNotCommitted(t *testing.T) {
	fixtures := loadFixtures(t)
	watcher, msgC := setupTestWatcher(t)
	logger := zaptest.NewLogger(t)

	replay := cloneBlockReplay(t, fixtures.BlockReplaySuccess)
	tx := &replay.Transactions[0]
	tx.Events[1].Committed = false

	ctx := context.Background()
	err := watcher.processStacksTransaction(ctx, tx, replay, false, logger)
	assert.Nil(t, err)

	// Should NOT emit a message
	select {
	case msg := <-msgC:
		t.Fatalf("Unexpected message sent for failed transaction: %+v", msg)
	case <-time.After(testChannelTimeout):
		// Expected - no message
	}
}

// Test a transaction where the event type is not 'post-message'.
func TestProcessStacksTransaction_FailedWrongEventTypeStacks(t *testing.T) {
	fixtures := loadFixtures(t)
	watcher, msgC := setupTestWatcher(t)
	logger := zaptest.NewLogger(t)

	replay := cloneBlockReplay(t, fixtures.BlockReplaySuccess)
	tx := &replay.Transactions[0]
	tx.Events[1].Type = "not-contract-event"

	ctx := context.Background()
	err := watcher.processStacksTransaction(ctx, tx, replay, false, logger)
	assert.Nil(t, err)

	// Should NOT emit a message
	select {
	case msg := <-msgC:
		t.Fatalf("Unexpected message sent for failed transaction: %+v", msg)
	case <-time.After(testChannelTimeout):
		// Expected - no message
	}
}

// Transction with incorrect event topic type (should be 'print')
func TestProcessStacksTransaction_FailedWrongEventTypeTopic(t *testing.T) {
	fixtures := loadFixtures(t)
	watcher, msgC := setupTestWatcher(t)
	logger := zaptest.NewLogger(t)

	replay := cloneBlockReplay(t, fixtures.BlockReplaySuccess)
	tx := &replay.Transactions[0]
	tx.Events[1].ContractEvent.Topic = "not-print"

	ctx := context.Background()
	err := watcher.processStacksTransaction(ctx, tx, replay, false, logger)

	// Should fail due to VM error
	assert.Nil(t, err)

	// Should NOT emit a message
	select {
	case msg := <-msgC:
		t.Fatalf("Unexpected message sent for failed transaction: %+v", msg)
	case <-time.After(testChannelTimeout):
		// Expected - no message
	}
}

// Transaction with wrong event type.
func TestProcessStacksTransaction_FailedEventTypeContract(t *testing.T) {
	fixtures := loadFixtures(t)
	watcher, msgC := setupTestWatcher(t)
	logger := zaptest.NewLogger(t)

	replay := cloneBlockReplay(t, fixtures.BlockReplaySuccess)
	tx := &replay.Transactions[0]

	// Sets the 'event' to be 'not-post-message'
	// (to-consensus-buff? { data: { ..., event: "not-post-message" })
	tx.Events[1].ContractEvent.RawValue = clarityEventNotPostMessage

	ctx := context.Background()
	err := watcher.processStacksTransaction(ctx, tx, replay, false, logger)

	assert.Nil(t, err)

	// Should NOT emit a message
	select {
	case msg := <-msgC:
		t.Fatalf("Unexpected message sent for failed transaction: %+v", msg)
	case <-time.After(testChannelTimeout):
		// Expected - no message
	}
}

// Tests that a transaction with a sequence value exceeding uint64 max is rejected.
// The sequence field is represented as UInt128 in Clarity but must fit within uint64.
func TestProcessStacksTransaction_FailedSequenceTooLarge(t *testing.T) {
	fixtures := loadFixtures(t)
	watcher, msgC := setupTestWatcher(t)
	logger := zaptest.NewLogger(t)

	replay := cloneBlockReplay(t, fixtures.BlockReplaySuccess)
	tx := &replay.Transactions[0]

	// Sequence value exceeds uint64 max (0x10000000000000000)
	tx.Events[1].ContractEvent.RawValue = clarityEventSequenceTooLarge

	ctx := context.Background()
	err := watcher.processStacksTransaction(ctx, tx, replay, false, logger)

	assert.Nil(t, err)

	// Should NOT emit a message due to validation error
	select {
	case msg := <-msgC:
		t.Fatalf("Unexpected message sent for sequence too large: %+v", msg)
	case <-time.After(testChannelTimeout):
		// Expected - no message
	}
}

// Tests that a transaction with an emitter buffer that is not exactly 32 bytes is rejected.
// The emitter field must be a 32-byte buffer representing the emitter address.
func TestProcessStacksTransaction_FailedEmitterWrongSize(t *testing.T) {
	fixtures := loadFixtures(t)
	watcher, msgC := setupTestWatcher(t)
	logger := zaptest.NewLogger(t)

	replay := cloneBlockReplay(t, fixtures.BlockReplaySuccess)
	tx := &replay.Transactions[0]

	// Emitter buffer is 33 bytes instead of 32
	tx.Events[1].ContractEvent.RawValue = clarityEventWrongSizePrincipal

	ctx := context.Background()
	err := watcher.processStacksTransaction(ctx, tx, replay, false, logger)

	assert.Nil(t, err)

	// Should NOT emit a message due to validation error
	select {
	case msg := <-msgC:
		t.Fatalf("Unexpected message sent for invalid emitter size: %+v", msg)
	case <-time.After(testChannelTimeout):
		// Expected - no message
	}
}

// Tests that a transaction with a nonce value exceeding uint32 max is rejected.
// The nonce field is represented as UInt128 in Clarity but must fit within uint32.
func TestProcessStacksTransaction_FailedNonceTooLarge(t *testing.T) {
	fixtures := loadFixtures(t)
	watcher, msgC := setupTestWatcher(t)
	logger := zaptest.NewLogger(t)

	replay := cloneBlockReplay(t, fixtures.BlockReplaySuccess)
	tx := &replay.Transactions[0]

	// Nonce value exceeds uint32 max (0x100000000)
	tx.Events[1].ContractEvent.RawValue = clarityEventNonceTooLarge

	ctx := context.Background()
	err := watcher.processStacksTransaction(ctx, tx, replay, false, logger)

	assert.Nil(t, err)

	// Should NOT emit a message due to validation error
	select {
	case msg := <-msgC:
		t.Fatalf("Unexpected message sent for nonce too large: %+v", msg)
	case <-time.After(testChannelTimeout):
		// Expected - no message
	}
}

// Tests that a transaction with a nonce field of incorrect type is rejected.
// The nonce must be UInt128 (0x01) but this test uses Int128Signed (0x00).
func TestProcessStacksTransaction_FailedNonceWrongType(t *testing.T) {
	fixtures := loadFixtures(t)
	watcher, msgC := setupTestWatcher(t)
	logger := zaptest.NewLogger(t)

	replay := cloneBlockReplay(t, fixtures.BlockReplaySuccess)
	tx := &replay.Transactions[0]

	// Nonce is Int128Signed instead of UInt128
	tx.Events[1].ContractEvent.RawValue = clarityEventNonceWrongType

	ctx := context.Background()
	err := watcher.processStacksTransaction(ctx, tx, replay, false, logger)

	assert.Nil(t, err)

	// Should NOT emit a message due to type mismatch
	select {
	case msg := <-msgC:
		t.Fatalf("Unexpected message sent for nonce wrong type: %+v", msg)
	case <-time.After(testChannelTimeout):
		// Expected - no message
	}
}

// Tests that a transaction with a consistency level exceeding uint8 max is rejected.
// The consistency level is represented as UInt128 in Clarity but must fit within uint8.
func TestProcessStacksTransaction_FailedConsistencyLevelTooLarge(t *testing.T) {
	fixtures := loadFixtures(t)
	watcher, msgC := setupTestWatcher(t)
	logger := zaptest.NewLogger(t)

	replay := cloneBlockReplay(t, fixtures.BlockReplaySuccess)
	tx := &replay.Transactions[0]

	// Consistency level value exceeds uint8 max (0x6f = 111 in this case)
	tx.Events[1].ContractEvent.RawValue = clarityEventConsistencyLevelTooLarge

	ctx := context.Background()
	err := watcher.processStacksTransaction(ctx, tx, replay, false, logger)

	assert.Nil(t, err)

	// Should NOT emit a message due to validation error
	select {
	case msg := <-msgC:
		t.Fatalf("Unexpected message sent for consistency level too large: %+v", msg)
	case <-time.After(testChannelTimeout):
		// Expected - no message
	}
}

// Tests that a transaction with a missing sequence field is rejected.
// The sequence field is required in the message data tuple.
func TestProcessStacksTransaction_FailedMissingSequence(t *testing.T) {
	fixtures := loadFixtures(t)
	watcher, msgC := setupTestWatcher(t)
	logger := zaptest.NewLogger(t)

	replay := cloneBlockReplay(t, fixtures.BlockReplaySuccess)
	tx := &replay.Transactions[0]

	// Data tuple is missing the 'sequence' field (only has 5 fields instead of 6)
	tx.Events[1].ContractEvent.RawValue = clarityEventMissingSequence

	ctx := context.Background()
	err := watcher.processStacksTransaction(ctx, tx, replay, false, logger)

	assert.Nil(t, err)

	// Should NOT emit a message due to missing field
	select {
	case msg := <-msgC:
		t.Fatalf("Unexpected message sent for missing sequence: %+v", msg)
	case <-time.After(testChannelTimeout):
		// Expected - no message
	}
}

// Tests that a transaction with a missing data field is rejected.
func TestProcessStacksTransaction_FailedMissingDataTuple(t *testing.T) {
	fixtures := loadFixtures(t)
	watcher, msgC := setupTestWatcher(t)
	logger := zaptest.NewLogger(t)

	replay := cloneBlockReplay(t, fixtures.BlockReplaySuccess)
	tx := &replay.Transactions[0]

	tx.Events[1].ContractEvent.RawValue = clarityEventMissingDataTuple

	ctx := context.Background()
	err := watcher.processStacksTransaction(ctx, tx, replay, false, logger)

	assert.Nil(t, err)

	// Should NOT emit a message due to missing field
	select {
	case msg := <-msgC:
		t.Fatalf("Unexpected message sent for missing sequence: %+v", msg)
	case <-time.After(testChannelTimeout):
		// Expected - no message
	}
}

// clarityEventMissingDataTuple
