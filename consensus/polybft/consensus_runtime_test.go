package polybft

import (
	"bytes"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/0xPolygon/polygon-edge/consensus"
	"github.com/0xPolygon/polygon-edge/consensus/polybft/bitmap"
	"github.com/0xPolygon/polygon-edge/consensus/polybft/wallet"
	"github.com/0xPolygon/polygon-edge/contracts"
	"github.com/0xPolygon/polygon-edge/crypto"
	"github.com/0xPolygon/polygon-edge/types"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/umbracle/ethgo"
	"github.com/umbracle/ethgo/abi"
)

func TestConsensusRuntime_GetVotes(t *testing.T) {
	t.Parallel()

	const (
		epoch           = uint64(1)
		validatorsCount = 7
		bundleSize      = 5
		stateSyncsCount = 15
	)

	validatorIds := []string{"A", "B", "C", "D", "E", "F", "G"}
	validatorAccounts := newTestValidatorsWithAliases(validatorIds)
	state := newTestState(t)
	runtime := &consensusRuntime{
		state: state,
		epoch: &epochMetadata{
			Number:     epoch,
			Validators: validatorAccounts.getPublicIdentities(),
		},
	}

	commitment, _, _ := buildCommitmentAndStateSyncs(t, stateSyncsCount, epoch, bundleSize, 0)

	quorumSize := uint(getQuorumSize(len(runtime.epoch.Validators)))
	require.NoError(t, state.insertEpoch(epoch))

	votesCount := quorumSize + 1
	hash, err := commitment.Hash()
	require.NoError(t, err)

	for i := 0; i < int(votesCount); i++ {
		validator := validatorAccounts.getValidator(validatorIds[i])
		signature, err := validator.mustSign(hash.Bytes()).Marshal()
		require.NoError(t, err)

		_, err = state.insertMessageVote(epoch, hash.Bytes(),
			&MessageSignature{
				From:      validator.Key().String(),
				Signature: signature,
			})
		require.NoError(t, err)
	}

	votes, err := runtime.state.getMessageVotes(runtime.epoch.Number, hash.Bytes())
	require.NoError(t, err)
	require.Len(t, votes, int(votesCount))
}

func TestConsensusRuntime_GetVotesError(t *testing.T) {
	t.Parallel()

	const (
		epoch           = uint64(1)
		stateSyncsCount = 30
		startIndex      = 0
		bundleSize      = uint64(5)
	)

	state := newTestState(t)
	runtime := &consensusRuntime{state: state}
	commitment, _, _ := buildCommitmentAndStateSyncs(t, 5, epoch, bundleSize, startIndex)
	hash, err := commitment.Hash()
	require.NoError(t, err)
	_, err = runtime.state.getMessageVotes(epoch, hash.Bytes())
	assert.ErrorContains(t, err, "could not find")
}

func TestConsensusRuntime_deliverMessage_MessageWhenEpochNotStarted(t *testing.T) {
	t.Parallel()

	const epoch = uint64(5)

	validatorIds := []string{"A", "B", "C", "D", "E", "F", "G"}
	state := newTestState(t)
	validators := newTestValidatorsWithAliases(validatorIds)
	localValidator := validators.getValidator("A")
	runtime := &consensusRuntime{
		logger:              hclog.NewNullLogger(),
		activeValidatorFlag: 1,
		state:               state,
		config:              &runtimeConfig{Key: localValidator.Key()},
		epoch: &epochMetadata{
			Number:     epoch,
			Validators: validators.getPublicIdentities(),
		},
		lastBuiltBlock: &types.Header{},
	}

	// dummy hash
	hash := crypto.Keccak256Hash(generateRandomBytes(t)).Bytes()

	// insert dummy epoch to the state
	require.NoError(t, state.insertEpoch(epoch))

	// insert dummy message vote
	_, err := runtime.state.insertMessageVote(epoch, hash,
		createTestMessageVote(t, hash, localValidator))
	require.NoError(t, err)

	// prevent node sender is the local node
	senderID := ""
	for senderID == "" || senderID == localValidator.alias {
		senderID = validatorIds[rand.Intn(len(validatorIds))]
	}
	// deliverMessage should not fail, although epochMetadata is not initialized
	// message vote should be added to the consensus runtime state.
	msgProcessed, err := runtime.deliverMessage(createTestTransportMessage(t, hash, epoch, validators.getValidator(senderID).Key()))
	require.NoError(t, err)
	require.True(t, msgProcessed)

	// assert that no additional message signatures aren't inserted into the consensus runtime state
	// (other than the one we have previously inserted by ourselves)
	signatures, err := runtime.state.getMessageVotes(epoch, hash)
	require.NoError(t, err)
	require.Len(t, signatures, 2)
}

func TestConsensusRuntime_AddLog(t *testing.T) {
	t.Parallel()

	state := newTestState(t)
	runtime := &consensusRuntime{
		logger: hclog.NewNullLogger(),
		state:  state,
		config: &runtimeConfig{Key: createTestKey(t)},
	}
	topics := make([]ethgo.Hash, 4)
	topics[0] = stateTransferEventABI.ID()
	topics[1] = ethgo.BytesToHash([]byte{0x1})
	topics[2] = ethgo.BytesToHash(runtime.config.Key.Address().Bytes())
	topics[3] = ethgo.BytesToHash(contracts.NativeTokenContract[:])
	personType := abi.MustNewType("tuple(string firstName, string lastName)")
	encodedData, err := personType.Encode(map[string]string{"firstName": "John", "lastName": "Doe"})
	require.NoError(t, err)

	log := &ethgo.Log{
		LogIndex:        uint64(0),
		BlockNumber:     uint64(0),
		TransactionHash: ethgo.BytesToHash(generateRandomBytes(t)),
		BlockHash:       ethgo.BytesToHash(generateRandomBytes(t)),
		Address:         ethgo.ZeroAddress,
		Topics:          topics,
		Data:            encodedData,
	}
	event, err := decodeStateSyncEvent(log)
	require.NoError(t, err)
	runtime.AddLog(log)

	stateSyncs, err := runtime.state.getStateSyncEventsForCommitment(1, 1)
	require.NoError(t, err)
	require.Len(t, stateSyncs, 1)
	require.Equal(t, event.ID, stateSyncs[0].ID)
}

func TestConsensusRuntime_getQuorumSize(t *testing.T) {
	t.Parallel()

	var cases = []struct {
		num, quorum int
	}{
		{4, 2},
		{5, 3},
	}

	for _, c := range cases {
		assert.Equal(t, c.quorum, getQuorumSize(c.num))
	}
}

func TestConsensusRuntime_isEndOfEpoch_NotReachedEnd(t *testing.T) {
	t.Parallel()

	// because of slashing, we can assume some epochs started at random numbers
	var cases = []struct {
		epochSize, firstBlockInEpoch, parentBlockNumber uint64
	}{
		{4, 1, 2},
		{5, 1, 3},
		{6, 0, 6},
		{7, 0, 4},
		{8, 0, 5},
		{9, 4, 9},
		{10, 7, 10},
		{10, 1, 1},
	}

	runtime := &consensusRuntime{
		config: &runtimeConfig{
			PolyBFTConfig: &PolyBFTConfig{},
		},
		lastBuiltBlock: &types.Header{},
		epoch:          &epochMetadata{},
	}

	for _, c := range cases {
		runtime.config.PolyBFTConfig.EpochSize = c.epochSize
		runtime.epoch.FirstBlockInEpoch = c.firstBlockInEpoch
		assert.False(
			t,
			runtime.isEndOfEpoch(c.parentBlockNumber+1),
			fmt.Sprintf(
				"Not expected end of epoch for epoch size=%v and parent block number=%v",
				c.epochSize,
				c.parentBlockNumber),
		)
	}
}

func TestConsensusRuntime_isEndOfEpoch_ReachedEnd(t *testing.T) {
	t.Parallel()

	// because of slashing, we can assume some epochs started at random numbers
	var cases = []struct {
		epochSize, firstBlockInEpoch, parentBlockNumber uint64
	}{
		{4, 1, 4},
		{5, 1, 5},
		{6, 0, 5},
		{7, 0, 6},
		{8, 0, 7},
		{9, 4, 12},
		{10, 7, 16},
		{10, 1, 10},
	}

	runtime := &consensusRuntime{
		config: &runtimeConfig{
			PolyBFTConfig: &PolyBFTConfig{},
		},
		epoch: &epochMetadata{},
	}

	for _, c := range cases {
		runtime.config.PolyBFTConfig.EpochSize = c.epochSize
		runtime.epoch.FirstBlockInEpoch = c.firstBlockInEpoch
		assert.True(
			t,
			runtime.isEndOfEpoch(c.parentBlockNumber),
			fmt.Sprintf(
				"Not expected end of epoch for epoch size=%v and parent block number=%v",
				c.epochSize,
				c.parentBlockNumber),
		)
	}
}

func TestConsensusRuntime_isEndOfSprint_NotReachedEnd(t *testing.T) {
	t.Parallel()

	var cases = []struct {
		sprintSize, parentBlockNumber uint64
	}{
		{4, 2},
		{5, 3},
		{6, 6},
		{7, 7},
		{8, 8},
		{9, 9},
		{10, 10},
		{5, 1},
	}

	runtime := &consensusRuntime{
		config: &runtimeConfig{
			PolyBFTConfig: &PolyBFTConfig{},
		},
		lastBuiltBlock: &types.Header{},
	}

	for _, c := range cases {
		runtime.config.PolyBFTConfig.SprintSize = c.sprintSize
		assert.False(t,
			runtime.isEndOfSprint(c.parentBlockNumber+1),
			fmt.Sprintf(
				"Not expected end of sprint for sprint size=%v and parent block number=%v",
				c.sprintSize,
				c.parentBlockNumber),
		)
	}
}

func TestConsensusRuntime_isEndOfSprint_ReachedEnd(t *testing.T) {
	t.Parallel()

	runtime := &consensusRuntime{
		config: &runtimeConfig{
			PolyBFTConfig: &PolyBFTConfig{
				EpochSize:  10,
				SprintSize: 5,
			},
		},
	}

	for _, v := range []uint64{5, 10, 25, 100} {
		assert.True(t, runtime.isEndOfSprint(v))
	}
}

func TestConsensusRuntime_deliverMessage_EpochNotStarted(t *testing.T) {
	t.Parallel()

	state := newTestState(t)
	err := state.insertEpoch(1)
	assert.NoError(t, err)

	// random node not among validator set
	account := newTestValidator("A", 1)

	runtime := &consensusRuntime{
		logger: hclog.NewNullLogger(),
		state:  state,
		config: &runtimeConfig{
			PolyBFTConfig: &PolyBFTConfig{
				EpochSize: 1,
			},
			Key: account.Key(),
		},
		epoch: &epochMetadata{
			Number:     1,
			Validators: newTestValidators(5).getPublicIdentities(),
		},
		lastBuiltBlock: &types.Header{},
	}

	msg := createTestTransportMessage(t, generateRandomBytes(t), 1, account.Key())
	isProcessed, err := runtime.deliverMessage(msg)
	assert.False(t, isProcessed)
	assert.ErrorContains(t, err, "not among the active validator set")

	votes, err := state.getMessageVotes(1, msg.Hash)
	assert.NoError(t, err)
	assert.Empty(t, votes)
}

func TestConsensusRuntime_deliverMessage_ForExistingEpochAndCommitmentMessage(t *testing.T) {
	t.Parallel()

	state := newTestState(t)
	err := state.insertEpoch(1)
	require.NoError(t, err)

	validators := newTestValidatorsWithAliases([]string{"SENDER", "RECEIVER"})
	validatorSet := validators.getPublicIdentities()
	sender := validators.getValidator("SENDER").Key()

	runtime := &consensusRuntime{
		logger:              hclog.NewNullLogger(),
		state:               state,
		activeValidatorFlag: 1,
		config: &runtimeConfig{
			PolyBFTConfig: &PolyBFTConfig{
				EpochSize: 1,
			},
		},
		epoch: &epochMetadata{
			Number:     1,
			Validators: validatorSet,
		},
		lastBuiltBlock: &types.Header{},
	}

	msg := createTestTransportMessage(t, generateRandomBytes(t), 1, sender)
	isProcessed, err := runtime.deliverMessage(msg)
	assert.True(t, isProcessed)
	assert.NoError(t, err)

	votes, err := state.getMessageVotes(1, msg.Hash)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(votes))
	assert.True(t, bytes.Equal(msg.Signature, votes[0].Signature))
}

func TestConsensusRuntime_deliverMessage_SenderMessageNotInCurrentValidatorset(t *testing.T) {
	t.Parallel()

	state := newTestState(t)
	err := state.insertEpoch(1)
	require.NoError(t, err)

	validators := newTestValidators(6)

	runtime := &consensusRuntime{
		state:               state,
		activeValidatorFlag: 1,
		config: &runtimeConfig{
			PolyBFTConfig: &PolyBFTConfig{
				EpochSize: 1,
			},
		},
		epoch: &epochMetadata{
			Number:     1,
			Validators: validators.getPublicIdentities(),
		},
		lastBuiltBlock: &types.Header{},
	}

	msg := createTestTransportMessage(t, generateRandomBytes(t), 1, createTestKey(t))
	isProcessed, err := runtime.deliverMessage(msg)
	assert.False(t, isProcessed)
	assert.Error(t, err)
	assert.ErrorContains(t, err,
		fmt.Sprintf("message is received from sender %s, which is not in current validator set", msg.NodeID))
}

func TestConsensusRuntime_OnBlockInserted_EndOfEpoch(t *testing.T) {
	t.Parallel()

	const (
		epochSize       = uint64(10)
		validatorsCount = 7
	)

	currentEpochNumber := getEpochNumber(t, epochSize, epochSize)
	validatorSet := newTestValidators(validatorsCount).getPublicIdentities()
	header := &types.Header{Number: epochSize, ExtraData: createTestExtraForAccounts(t, currentEpochNumber, validatorSet, nil)}
	builtBlock := consensus.BuildBlock(consensus.BuildBlockParams{
		Header: header,
	})

	newEpochNumber := currentEpochNumber + 1
	systemStateMock := new(systemStateMock)
	systemStateMock.On("GetEpoch").Return(newEpochNumber).Once()

	blockchainMock := new(blockchainMock)
	blockchainMock.On("GetStateProviderForBlock", mock.Anything).Return(new(stateProviderMock)).Once()
	blockchainMock.On("GetSystemState", mock.Anything, mock.Anything).Return(systemStateMock)

	polybftBackendMock := new(polybftBackendMock)
	polybftBackendMock.On("GetValidators", mock.Anything, mock.Anything).Return(validatorSet).Once()

	txPool := new(txPoolMock)
	txPool.On("ResetWithHeaders", mock.Anything).Once()

	runtime := &consensusRuntime{
		logger: hclog.NewNullLogger(),
		state:  newTestState(t),
		config: &runtimeConfig{
			PolyBFTConfig: &PolyBFTConfig{
				EpochSize: epochSize,
			},
			blockchain:     blockchainMock,
			polybftBackend: polybftBackendMock,
			txPool:         txPool,
		},
		epoch: &epochMetadata{
			Number:            currentEpochNumber,
			FirstBlockInEpoch: header.Number - epochSize + 1,
		},
	}
	runtime.OnBlockInserted(builtBlock)

	require.True(t, runtime.state.isEpochInserted(currentEpochNumber+1))
	require.Equal(t, newEpochNumber, runtime.epoch.Number)

	blockchainMock.AssertExpectations(t)
	systemStateMock.AssertExpectations(t)
	polybftBackendMock.AssertExpectations(t)
}

func TestConsensusRuntime_OnBlockInserted_MiddleOfEpoch(t *testing.T) {
	t.Parallel()

	const (
		epoch             = 2
		epochSize         = uint64(10)
		firstBlockInEpoch = epochSize + 1
		blockNumber       = epochSize + 2
	)

	header := &types.Header{Number: blockNumber}
	builtBlock := consensus.BuildBlock(consensus.BuildBlockParams{
		Header: header,
	})

	txPool := new(txPoolMock)
	txPool.On("ResetWithHeaders", mock.Anything).Once()

	runtime := &consensusRuntime{
		lastBuiltBlock: header,
		config: &runtimeConfig{
			PolyBFTConfig: &PolyBFTConfig{EpochSize: epochSize},
			blockchain:    new(blockchainMock),
			txPool:        txPool,
		},
		epoch: &epochMetadata{
			Number:            epoch,
			FirstBlockInEpoch: firstBlockInEpoch,
		},
	}
	runtime.OnBlockInserted(builtBlock)

	require.Equal(t, header.Number, runtime.lastBuiltBlock.Number)
}

func TestConsensusRuntime_FSM_NotInValidatorSet(t *testing.T) {
	t.Parallel()

	validators := newTestValidatorsWithAliases([]string{"A", "B", "C", "D"})
	runtime := &consensusRuntime{
		activeValidatorFlag: 1,
		config: &runtimeConfig{
			PolyBFTConfig: &PolyBFTConfig{
				EpochSize: 1,
			},
			Key: createTestKey(t),
		},
		epoch: &epochMetadata{
			Number:     1,
			Validators: validators.getPublicIdentities(),
		},
		lastBuiltBlock: &types.Header{},
	}

	err := runtime.FSM()
	assert.ErrorIs(t, err, errNotAValidator)
}

func TestConsensusRuntime_FSM_NotEndOfEpoch_NotEndOfSprint(t *testing.T) {
	t.Parallel()

	state := newTestState(t)

	lastBlock := &types.Header{Number: 1}
	validators := newTestValidators(3)
	blockchainMock := new(blockchainMock)
	blockchainMock.On("NewBlockBuilder", mock.Anything).Return(&BlockBuilder{}, nil).Once()

	runtime := &consensusRuntime{
		logger:              hclog.NewNullLogger(),
		activeValidatorFlag: 1,
		config: &runtimeConfig{
			PolyBFTConfig: &PolyBFTConfig{
				EpochSize:  10,
				SprintSize: 5,
			},
			Key:        wallet.NewKey(validators.getPrivateIdentities()[0]),
			blockchain: blockchainMock,
		},
		epoch: &epochMetadata{
			Number:     1,
			Validators: validators.getPublicIdentities(),
		},
		lastBuiltBlock: lastBlock,
		state:          state,
	}

	err := runtime.FSM()
	assert.NoError(t, err)

	assert.True(t, runtime.isActiveValidator())
	assert.False(t, runtime.fsm.isEndOfEpoch)
	assert.False(t, runtime.fsm.isEndOfSprint)
	assert.Equal(t, lastBlock.Number, runtime.fsm.parent.Number)

	address := types.Address(runtime.config.Key.Address())
	assert.True(t, runtime.fsm.ValidatorSet().Includes(address))

	assert.NotNil(t, runtime.fsm.blockBuilder)
	assert.NotNil(t, runtime.fsm.backend)

	blockchainMock.AssertExpectations(t)
}

func TestConsensusRuntime_FSM_EndOfEpoch_BuildRegisterCommitment_And_Uptime(t *testing.T) {
	t.Parallel()

	const (
		epoch               = 1
		epochSize           = uint64(10)
		firstBlockInEpoch   = uint64(1)
		sprintSize          = uint64(3)
		beginStateSyncIndex = uint64(0)
		bundleSize          = stateSyncBundleSize
		fromIndex           = uint64(0)
		toIndex             = uint64(9)
	)

	validatorAccounts := newTestValidatorsWithAliases([]string{"A", "B", "C", "D", "E", "F"})
	validators := validatorAccounts.getPublicIdentities()
	accounts := validatorAccounts.getPrivateIdentities()

	lastBuiltBlock, headerMap := createTestBlocks(t, 9, epochSize, validators)

	systemStateMock := new(systemStateMock)
	systemStateMock.On("GetNextExecutionIndex").Return(beginStateSyncIndex, nil).Once()
	systemStateMock.On("GetNextCommittedIndex").Return(beginStateSyncIndex, nil).Once()

	blockchainMock := new(blockchainMock)
	blockchainMock.On("NewBlockBuilder", mock.Anything).Return(&BlockBuilder{}, nil).Once()
	blockchainMock.On("GetStateProviderForBlock", mock.Anything).Return(new(stateProviderMock)).Once()
	blockchainMock.On("GetSystemState", mock.Anything, mock.Anything).Return(systemStateMock)
	blockchainMock.On("GetHeaderByNumber", mock.Anything).Return(headerMap.getHeader)

	state := newTestState(t)
	require.NoError(t, state.insertEpoch(epoch))

	stateSyncs := generateStateSyncEvents(t, bundleSize, 0)
	for _, event := range stateSyncs {
		require.NoError(t, state.insertStateSyncEvent(event))
	}

	trie, err := createMerkleTree(stateSyncs, bundleSize)
	require.NoError(t, err)

	commitment := &Commitment{MerkleTree: trie, Epoch: epoch}

	hash, err := commitment.Hash()
	require.NoError(t, err)

	for _, a := range accounts {
		signature, err := a.Bls.Sign(hash.Bytes())
		require.NoError(t, err)
		signatureRaw, err := signature.Marshal()
		require.NoError(t, err)
		_, err = state.insertMessageVote(epoch, hash.Bytes(), &MessageSignature{
			From:      a.Ecdsa.Address().String(),
			Signature: signatureRaw,
		})
		require.NoError(t, err)
	}

	metadata := &epochMetadata{
		Validators:        validators,
		Number:            epoch,
		FirstBlockInEpoch: firstBlockInEpoch,
		Commitment:        commitment,
	}

	config := &runtimeConfig{
		PolyBFTConfig: &PolyBFTConfig{
			EpochSize:  epochSize,
			SprintSize: sprintSize,
			Bridge:     &BridgeConfig{},
		},
		Key:        validatorAccounts.getValidator("A").Key(),
		blockchain: blockchainMock,
	}

	runtime := &consensusRuntime{
		logger:         hclog.NewNullLogger(),
		state:          state,
		epoch:          metadata,
		config:         config,
		lastBuiltBlock: lastBuiltBlock,
	}

	err = runtime.FSM()
	fsm := runtime.fsm

	assert.NoError(t, err)
	assert.True(t, fsm.isEndOfEpoch)
	assert.NotNil(t, fsm.uptimeCounter)
	assert.NotEmpty(t, fsm.uptimeCounter)
	assert.NotNil(t, fsm.proposerCommitmentToRegister)
	assert.Equal(t, fromIndex, fsm.proposerCommitmentToRegister.Message.FromIndex)
	assert.Equal(t, toIndex, fsm.proposerCommitmentToRegister.Message.ToIndex)
	assert.Equal(t, uint64(bundleSize), fsm.proposerCommitmentToRegister.Message.BundleSize)
	assert.Equal(t, trie.Hash(), fsm.proposerCommitmentToRegister.Message.MerkleRootHash)

	systemStateMock.AssertExpectations(t)
	blockchainMock.AssertExpectations(t)
}

func TestConsensusRuntime_FSM_EndOfEpoch_RegisterCommitmentNotFound(t *testing.T) {
	t.Parallel()

	const (
		epochSize           = uint64(10)
		sprintSize          = uint64(5)
		beginStateSyncIndex = uint64(5)
	)

	validatorAccs := newTestValidatorsWithAliases([]string{"A", "B", "C", "D", "E", "F"})
	validators := validatorAccs.getPublicIdentities()
	lastBuiltBlock, headerMap := createTestBlocks(t, 9, epochSize, validators)

	systemStateMock := new(systemStateMock)
	systemStateMock.On("GetNextExecutionIndex").Return(beginStateSyncIndex, nil).Once()
	systemStateMock.On("GetNextCommittedIndex").Return(beginStateSyncIndex, nil).Once()

	blockchainMock := new(blockchainMock)
	blockchainMock.On("NewBlockBuilder", mock.Anything).Return(new(blockBuilderMock), nil).Once()
	blockchainMock.On("GetStateProviderForBlock", mock.Anything).Return(new(stateProviderMock)).Once()
	blockchainMock.On("GetSystemState", mock.Anything, mock.Anything).Return(systemStateMock)
	blockchainMock.On("GetHeaderByNumber", mock.Anything).Return(headerMap.getHeader)

	epoch := getEpochNumber(t, lastBuiltBlock.Number, epochSize)
	metadata := &epochMetadata{
		Validators:        validators,
		Number:            epoch,
		FirstBlockInEpoch: epoch*epochSize - epochSize + 1,
	}

	config := &runtimeConfig{
		PolyBFTConfig: &PolyBFTConfig{
			EpochSize:  epochSize,
			SprintSize: sprintSize,
			Bridge:     &BridgeConfig{},
		},
		Key:        validatorAccs.getValidator("A").Key(),
		blockchain: blockchainMock,
	}

	runtime := &consensusRuntime{
		logger:         hclog.NewNullLogger(),
		epoch:          metadata,
		config:         config,
		lastBuiltBlock: lastBuiltBlock,
		state:          newTestState(t),
	}

	err := runtime.FSM()
	fsm := runtime.fsm

	require.NoError(t, err)
	require.NotNil(t, fsm)
	require.Nil(t, fsm.proposerCommitmentToRegister)
	require.True(t, fsm.isEndOfEpoch)
	require.NotNil(t, fsm.uptimeCounter)
	require.NotEmpty(t, fsm.uptimeCounter)
}

func TestConsensusRuntime_FSM_EndOfEpoch_BuildRegisterCommitment_QuorumNotReached(t *testing.T) {
	t.Parallel()

	const (
		epoch               = 1
		epochSize           = uint64(10)
		firstBlockInEpoch   = uint64(1)
		sprintSize          = uint64(5)
		beginStateSyncIndex = uint64(0)
		bundleSize          = stateSyncBundleSize
	)

	validatorAccs := newTestValidatorsWithAliases([]string{"A", "B", "C", "D", "E", "F"})
	validators := validatorAccs.getPublicIdentities()
	lastBuiltBlock, headerMap := createTestBlocks(t, 9, epochSize, validators)

	systemStateMock := new(systemStateMock)
	systemStateMock.On("GetNextExecutionIndex").Return(beginStateSyncIndex, nil).Once()
	systemStateMock.On("GetNextCommittedIndex").Return(beginStateSyncIndex, nil).Once()

	blockchainMock := new(blockchainMock)
	blockchainMock.On("NewBlockBuilder", mock.Anything).Return(&BlockBuilder{}, nil).Once()
	blockchainMock.On("GetStateProviderForBlock", mock.Anything).Return(new(stateProviderMock)).Once()
	blockchainMock.On("GetSystemState", mock.Anything, mock.Anything).Return(systemStateMock)
	blockchainMock.On("GetHeaderByNumber", mock.Anything).Return(headerMap.getHeader)

	state := newTestState(t)
	require.NoError(t, state.insertEpoch(epoch))

	stateSyncs := generateStateSyncEvents(t, bundleSize, 0)
	for _, event := range stateSyncs {
		require.NoError(t, state.insertStateSyncEvent(event))
	}

	trie, err := createMerkleTree(stateSyncs, bundleSize)
	require.NoError(t, err)

	commitment := &Commitment{MerkleTree: trie, Epoch: epoch}

	hash, err := commitment.Hash()
	require.NoError(t, err)

	validatorKey := validatorAccs.getValidator("C").Key()
	signature, err := validatorKey.Sign(hash.Bytes())
	require.NoError(t, err)
	_, err = state.insertMessageVote(epoch, hash.Bytes(), &MessageSignature{
		From:      validators[0].Address.String(),
		Signature: signature,
	})
	require.NoError(t, err)

	metadata := &epochMetadata{
		Validators:        validators,
		Number:            epoch,
		FirstBlockInEpoch: firstBlockInEpoch,
		Commitment:        commitment,
	}

	config := &runtimeConfig{
		PolyBFTConfig: &PolyBFTConfig{
			EpochSize:  epochSize,
			SprintSize: sprintSize,
			Bridge:     &BridgeConfig{},
		},
		Key:        validatorKey,
		blockchain: blockchainMock,
	}

	runtime := &consensusRuntime{
		logger:         hclog.NewNullLogger(),
		state:          state,
		epoch:          metadata,
		config:         config,
		lastBuiltBlock: lastBuiltBlock,
	}

	err = runtime.FSM()
	fsm := runtime.fsm

	assert.NoError(t, err)
	assert.Nil(t, fsm.proposerCommitmentToRegister)
	assert.True(t, fsm.isEndOfEpoch)
	assert.NotNil(t, fsm.uptimeCounter)
	assert.NotEmpty(t, fsm.uptimeCounter)

	systemStateMock.AssertExpectations(t)
	blockchainMock.AssertExpectations(t)
}

func Test_NewConsensusRuntime(t *testing.T) {
	t.Parallel()

	_, err := os.Create("/tmp/consensusState.db")
	require.NoError(t, err)

	polyBftConfig := &PolyBFTConfig{
		Bridge: &BridgeConfig{
			BridgeAddr:      types.Address{0x13},
			CheckpointAddr:  types.Address{0x10},
			JSONRPCEndpoint: "testEndpoint",
		},
		ValidatorSetAddr: types.Address{0x11},
		EpochSize:        10,
		SprintSize:       10,
		BlockTime:        2 * time.Second,
	}

	key := createTestKey(t)

	tmpDir := t.TempDir()
	config := &runtimeConfig{
		PolyBFTConfig: polyBftConfig,
		DataDir:       tmpDir,
		Key:           key,
		blockchain:    &blockchainMock{},
	}
	runtime := newConsensusRuntime(hclog.NewNullLogger(), config)

	assert.False(t, runtime.isActiveValidator())
	assert.Equal(t, runtime.config.DataDir, tmpDir)
	assert.Equal(t, uint64(10), runtime.config.PolyBFTConfig.SprintSize)
	assert.Equal(t, uint64(10), runtime.config.PolyBFTConfig.EpochSize)
	assert.Equal(t, "0x1100000000000000000000000000000000000000", runtime.config.PolyBFTConfig.ValidatorSetAddr.String())
	assert.Equal(t, "0x1300000000000000000000000000000000000000", runtime.config.PolyBFTConfig.Bridge.BridgeAddr.String())
	assert.Equal(t, "0x1000000000000000000000000000000000000000", runtime.config.PolyBFTConfig.Bridge.CheckpointAddr.String())
	assert.Equal(t, uint64(10), runtime.config.PolyBFTConfig.EpochSize)
	assert.True(t, runtime.IsBridgeEnabled())
}

func TestConsensusRuntime_FSM_EndOfSprint_HasBundlesToExecute(t *testing.T) {
	t.Parallel()

	const (
		epochNumber        = uint64(2)
		fromIndex          = uint64(5)
		nextCommittedIndex = uint64(3)
		stateSyncsCount    = 30
		bundleSize         = stateSyncsCount / 3
	)

	state := newTestState(t)
	err := state.insertEpoch(epochNumber)
	require.NoError(t, err)

	stateSyncs := insertTestStateSyncEvents(t, stateSyncsCount, fromIndex, state)

	commitment, err := NewCommitment(epochNumber, fromIndex, fromIndex+bundleSize, bundleSize, stateSyncs)
	require.NoError(t, err)

	commitmentMsg := NewCommitmentMessage(commitment.MerkleTree.Hash(), fromIndex,
		fromIndex+bundleSize, bundleSize)
	signedCommitmentMsg := &CommitmentMessageSigned{
		Message:      commitmentMsg,
		AggSignature: Signature{},
	}
	require.NoError(t, state.insertCommitmentMessage(signedCommitmentMsg))

	validatorAccs := newTestValidatorsWithAliases([]string{"A", "B", "C", "D", "E", "F", "G"})
	validatorSet := validatorAccs.getPublicIdentities()

	lastBlock := types.Header{Number: 24}

	systemStateMock := new(systemStateMock)
	systemStateMock.On("GetNextCommittedIndex").Return(nextCommittedIndex, nil).Once()
	systemStateMock.On("GetNextExecutionIndex").Return(uint64(stateSyncMainBundleSize), nil).Once()

	blockchainMock := new(blockchainMock)
	blockchainMock.On("NewBlockBuilder").Return(&BlockBuilder{}, nil).Once()
	blockchainMock.On("GetStateProviderForBlock", mock.Anything).Return(new(stateProviderMock)).Once()
	blockchainMock.On("GetSystemState", mock.Anything, mock.Anything).Return(systemStateMock).Once()

	runtime := &consensusRuntime{
		logger:              hclog.NewNullLogger(),
		activeValidatorFlag: 1,
		state:               state,
		config: &runtimeConfig{
			PolyBFTConfig: &PolyBFTConfig{
				EpochSize:  10,
				SprintSize: 5,
				Bridge: &BridgeConfig{
					BridgeAddr: types.BytesToAddress(big.NewInt(23).Bytes()),
				},
			},
			Key:        validatorAccs.getValidator("A").Key(),
			blockchain: blockchainMock,
		},
		epoch: &epochMetadata{
			Number:     epochNumber,
			Validators: validatorSet,
			Commitment: commitment,
		},
		lastBuiltBlock: &lastBlock,
	}

	require.NoError(t, runtime.buildBundles(runtime.getEpoch().Commitment, commitmentMsg, fromIndex))

	err = runtime.FSM()
	fsm := runtime.fsm

	require.NoError(t, err)

	// check if it is end of sprint
	require.True(t, fsm.isEndOfSprint)

	// check if commitment message to execute is attached to fsm
	require.Len(t, fsm.bundleProofs, 1)
	require.Len(t, fsm.commitmentsToVerifyBundles, 1)
	require.Nil(t, fsm.proposerCommitmentToRegister)

	systemStateMock.AssertExpectations(t)
	blockchainMock.AssertExpectations(t)
}

func TestConsensusRuntime_restartEpoch_SameEpochNumberAsTheLastOne(t *testing.T) {
	t.Parallel()

	const originalBlockNumber = uint64(5)

	newCurrentHeader := &types.Header{Number: originalBlockNumber + 1}
	validatorSet := newTestValidators(3).getPublicIdentities()

	systemStateMock := new(systemStateMock)
	systemStateMock.On("GetEpoch").Return(uint64(1), nil).Once()

	blockchainMock := new(blockchainMock)
	blockchainMock.On("GetStateProviderForBlock", mock.Anything).Return(new(stateProviderMock)).Once()
	blockchainMock.On("GetSystemState", mock.Anything, mock.Anything).Return(systemStateMock).Once()

	runtime := &consensusRuntime{
		activeValidatorFlag: 1,
		config: &runtimeConfig{
			blockchain: blockchainMock,
		},
		epoch: &epochMetadata{
			Number:     1,
			Validators: validatorSet,
		},
		lastBuiltBlock: &types.Header{
			Number: originalBlockNumber,
		},
	}

	err := runtime.restartEpoch(newCurrentHeader)

	require.NoError(t, err)

	lastBuiltBlock, _ := runtime.getLastBuiltBlockAndEpoch()

	assert.Equal(t, originalBlockNumber, lastBuiltBlock.Number)

	for _, a := range validatorSet.GetAddresses() {
		assert.True(t, runtime.epoch.Validators.ContainsAddress(a))
	}

	systemStateMock.AssertExpectations(t)
	blockchainMock.AssertExpectations(t)
}

func TestConsensusRuntime_restartEpoch_FirstRestart_NoStateSyncEvents(t *testing.T) {
	t.Parallel()

	newCurrentHeader := &types.Header{Number: 0}
	state := newTestState(t)

	systemStateMock := new(systemStateMock)
	systemStateMock.On("GetEpoch").Return(uint64(1), nil).Once()

	validators := newTestValidators(3)
	blockchainMock := new(blockchainMock)
	blockchainMock.On("GetStateProviderForBlock", mock.Anything).Return(new(stateProviderMock)).Once()
	blockchainMock.On("GetSystemState", mock.Anything, mock.Anything).Return(systemStateMock).Once()

	polybftBackendMock := new(polybftBackendMock)
	polybftBackendMock.On("GetValidators", mock.Anything, mock.Anything).Return(validators.getPublicIdentities()).Once()

	runtime := &consensusRuntime{
		logger:              hclog.NewNullLogger(),
		activeValidatorFlag: 1,
		state:               state,
		config: &runtimeConfig{
			blockchain:     blockchainMock,
			polybftBackend: polybftBackendMock,
			PolyBFTConfig:  &PolyBFTConfig{},
		},
	}

	require.NoError(t, runtime.restartEpoch(newCurrentHeader))
	require.Equal(t, uint64(1), runtime.epoch.Number)
	require.Equal(t, 3, len(runtime.epoch.Validators))
	require.Equal(t, newCurrentHeader.Number, runtime.lastBuiltBlock.Number)
	require.True(t, runtime.isActiveValidator())
	require.True(t, state.isEpochInserted(1))

	systemStateMock.AssertExpectations(t)
	blockchainMock.AssertExpectations(t)
	polybftBackendMock.AssertExpectations(t)
}

func TestConsensusRuntime_restartEpoch_FirstRestart_BuildsCommitment(t *testing.T) {
	t.Parallel()

	const (
		newEpoch           = uint64(3)
		epochSize          = uint64(10)
		nextCommittedIndex = uint64(10)
		stateSyncsCount    = 20
	)

	state := newTestState(t)
	stateSyncs := insertTestStateSyncEvents(t, stateSyncsCount, 0, state)
	validatorIds := []string{"A", "B", "C", "D", "E", "F"}
	validatorAccs := newTestValidatorsWithAliases(validatorIds)
	validators := validatorAccs.getPublicIdentities()

	header := &types.Header{Number: newEpoch * epochSize, ExtraData: createTestExtraForAccounts(t, newEpoch-1, validators, nil)}

	transportMock := new(transportMock)
	transportMock.On("Multicast", mock.Anything).Once()

	systemStateMock := new(systemStateMock)
	systemStateMock.On("GetNextCommittedIndex").Return(nextCommittedIndex, nil).Once()
	systemStateMock.On("GetEpoch").Return(newEpoch, nil).Once()

	blockchainMock := new(blockchainMock)
	blockchainMock.On("GetStateProviderForBlock", mock.Anything).Return(new(stateProviderMock)).Once()
	blockchainMock.On("GetSystemState", mock.Anything, mock.Anything).Return(systemStateMock).Once()

	polybftBackendMock := new(polybftBackendMock)
	polybftBackendMock.On("GetValidators", mock.Anything, mock.Anything).Return(validators).Once()

	localValidatorID := validatorIds[rand.Intn(len(validatorIds))]
	localValidator := validatorAccs.getValidator(localValidatorID)
	runtime := &consensusRuntime{
		logger:              hclog.NewNullLogger(),
		activeValidatorFlag: 1,
		state:               state,
		config: &runtimeConfig{
			blockchain:      blockchainMock,
			polybftBackend:  polybftBackendMock,
			BridgeTransport: transportMock,
			Key:             localValidator.Key(),
			PolyBFTConfig: &PolyBFTConfig{
				Bridge: &BridgeConfig{},
			},
		},
	}

	require.NoError(t, runtime.restartEpoch(header))
	require.Equal(t, newEpoch, runtime.epoch.Number)
	require.Equal(t, len(validatorIds), len(runtime.epoch.Validators))
	require.Equal(t, header.Number, runtime.lastBuiltBlock.Number)
	require.True(t, runtime.isActiveValidator())
	require.True(t, state.isEpochInserted(newEpoch))

	commitment := runtime.epoch.Commitment
	require.NotNil(t, commitment)
	require.Equal(t, newEpoch, commitment.Epoch)

	commitmentHash, err := commitment.Hash()
	require.NoError(t, err)
	stateSyncsTrie, err := createMerkleTree(stateSyncs[nextCommittedIndex:nextCommittedIndex+stateSyncMainBundleSize], stateSyncBundleSize)
	require.NoError(t, err)
	require.Equal(t, stateSyncsTrie.Hash(), commitment.MerkleTree.Hash())

	votes, err := state.getMessageVotes(newEpoch, commitmentHash.Bytes())
	require.NoError(t, err)
	require.Equal(t, 1, len(votes))
	require.Equal(t, localValidator.Key().String(), votes[0].From)

	signature, err := localValidator.mustSign(commitmentHash.Bytes()).Marshal()
	require.NoError(t, err)
	require.Equal(t, signature, votes[0].Signature)

	for _, validator := range validatorAccs.validators {
		if localValidator.Key().String() == validator.Key().String() {
			continue
		}

		signature, err := validator.mustSign(commitmentHash.Bytes()).Marshal()
		require.NoError(t, err)

		_, err = state.insertMessageVote(runtime.epoch.Number, commitmentHash.Bytes(),
			&MessageSignature{
				From:      validator.Key().String(),
				Signature: signature,
			})
		require.NoError(t, err)
	}

	commitmentMsgSigned, err := runtime.getCommitmentToRegister(runtime.epoch, nextCommittedIndex)
	require.NoError(t, err)
	require.NotNil(t, commitmentMsgSigned)
	require.Equal(t, nextCommittedIndex, commitmentMsgSigned.Message.FromIndex)

	transportMock.AssertExpectations(t)
	systemStateMock.AssertExpectations(t)
	blockchainMock.AssertExpectations(t)
	polybftBackendMock.AssertExpectations(t)
}

func TestConsensusRuntime_restartEpoch_NewEpochToRun_BuildCommitment(t *testing.T) {
	t.Parallel()

	const (
		blockNumber        = 11
		epochSize          = 10
		nextCommittedIndex = uint64(10)
		oldEpoch           = uint64(1)
		newEpoch           = oldEpoch + 1
		validatorsCount    = 6
	)

	// create originalValidators
	originalValidatorIds := []string{"A", "B", "C", "D", "E", "F"}
	originalValidators := newTestValidatorsWithAliases(originalValidatorIds)
	oldValidatorSet := originalValidators.getPublicIdentities()

	// remove first validator and add a new one to the end
	newValidatorSet := make(AccountSet, validatorsCount)
	for i := 1; i < len(oldValidatorSet); i++ {
		newValidatorSet[i-1] = oldValidatorSet[i].Copy()
	}

	newValidatorSet[validatorsCount-1] = newTestValidator("G", 1).ValidatorMetadata()

	header, headerMap := createTestBlocks(t, blockNumber, epochSize, oldValidatorSet)

	state := newTestState(t)
	allStateSyncs := insertTestStateSyncEvents(t, 4*stateSyncMainBundleSize, 0, state)

	transportMock := &transportMock{}
	transportMock.On("Multicast", mock.Anything).Once()

	systemStateMock := new(systemStateMock)
	systemStateMock.On("GetNextCommittedIndex").Return(nextCommittedIndex, nil).Once()
	systemStateMock.On("GetEpoch").Return(newEpoch, nil).Once()

	blockchainMock := new(blockchainMock)
	blockchainMock.On("GetStateProviderForBlock", mock.Anything).Return(new(stateProviderMock)).Once()
	blockchainMock.On("GetSystemState", mock.Anything, mock.Anything).Return(systemStateMock).Once()
	blockchainMock.On("GetHeaderByNumber", mock.Anything).Return(headerMap.getHeader)

	polybftBackendMock := new(polybftBackendMock)
	polybftBackendMock.On("GetValidators", mock.Anything, mock.Anything).Return(newValidatorSet).Once()

	runtime := &consensusRuntime{
		logger:              hclog.NewNullLogger(),
		activeValidatorFlag: 1,
		state:               state,
		config: &runtimeConfig{
			PolyBFTConfig: &PolyBFTConfig{
				EpochSize:  10,
				SprintSize: 5,
				Bridge: &BridgeConfig{
					BridgeAddr: types.BytesToAddress(big.NewInt(23).Bytes()),
				},
			},
			BridgeTransport: transportMock,
			Key:             originalValidators.getValidator("A").Key(),
			blockchain:      blockchainMock,
			polybftBackend:  polybftBackendMock,
		},
		epoch: &epochMetadata{
			Number:     oldEpoch,
			Validators: originalValidators.getPublicIdentities(),
		},
		lastBuiltBlock: header,
	}

	require.NoError(t, runtime.restartEpoch(header))

	// check new epoch number
	assert.Equal(t, newEpoch, runtime.epoch.Number)

	// check new epoch number
	assert.Equal(t, header.Number, runtime.lastBuiltBlock.Number)

	// check if it is validator
	assert.True(t, runtime.isActiveValidator())

	// check if new epoch is inserted
	assert.True(t, state.isEpochInserted(newEpoch))

	// check if new epoch is created
	assert.NotNil(t, runtime.epoch)

	// check new validators
	assert.Equal(t, len(originalValidatorIds), len(runtime.epoch.Validators))

	for _, a := range newValidatorSet.GetAddresses() {
		assert.True(t, runtime.epoch.Validators.ContainsAddress(a))
	}

	commitment := runtime.epoch.Commitment
	require.NotNil(t, commitment)
	require.Equal(t, newEpoch, commitment.Epoch)

	commitmentHash, err := commitment.Hash()
	require.NoError(t, err)

	for _, validatorID := range originalValidatorIds {
		validator := originalValidators.getValidator(validatorID)
		signature, err := validator.mustSign(commitmentHash.Bytes()).Marshal()
		require.NoError(t, err)
		_, err = state.insertMessageVote(runtime.epoch.Number, commitmentHash.Bytes(),
			&MessageSignature{
				From:      validator.Key().String(),
				Signature: signature,
			})
		require.NoError(t, err)
	}

	stateSyncTrie, err := createMerkleTree(allStateSyncs[nextCommittedIndex:nextCommittedIndex+stateSyncMainBundleSize], stateSyncBundleSize)
	require.NoError(t, err)
	require.NotNil(t, stateSyncTrie)

	commitmentMsgSigned, err := runtime.getCommitmentToRegister(runtime.epoch, nextCommittedIndex)
	require.NoError(t, err)
	require.NotNil(t, commitmentMsgSigned)
	require.Equal(t, stateSyncTrie.Hash(), commitmentMsgSigned.Message.MerkleRootHash)
	require.Equal(t, nextCommittedIndex, commitmentMsgSigned.Message.FromIndex)
	require.Equal(t, nextCommittedIndex+stateSyncMainBundleSize-1, commitmentMsgSigned.Message.ToIndex)

	transportMock.AssertExpectations(t)
	systemStateMock.AssertExpectations(t)
	blockchainMock.AssertExpectations(t)
	polybftBackendMock.AssertExpectations(t)
}

func TestConsensusRuntime_calculateUptime_SecondEpoch(t *testing.T) {
	t.Parallel()

	const (
		epoch           = 2
		epochSize       = 10
		epochStartBlock = 11
		epochEndBlock   = 20
		sprintSize      = 5
	)

	validators := newTestValidatorsWithAliases([]string{"A", "B", "C", "D", "E"})
	config := &PolyBFTConfig{
		ValidatorSetAddr: contracts.ValidatorSetContract,
		EpochSize:        epochSize,
		SprintSize:       sprintSize,
	}
	lastBuiltBlock, headerMap := createTestBlocks(t, 19, epochSize, validators.getPublicIdentities())

	blockchainMock := new(blockchainMock)
	blockchainMock.On("GetHeaderByNumber", mock.Anything).Return(headerMap.getHeader)

	polybftBackendMock := new(polybftBackendMock)
	polybftBackendMock.On("GetValidators", mock.Anything, mock.Anything).Return(validators.getPublicIdentities()).Once()

	consensusRuntime := &consensusRuntime{
		config: &runtimeConfig{
			PolyBFTConfig:  config,
			blockchain:     blockchainMock,
			polybftBackend: polybftBackendMock,
			Key:            validators.getValidator("A").Key(),
		},
		epoch: &epochMetadata{
			Number:            epoch,
			Validators:        validators.getPublicIdentities(),
			FirstBlockInEpoch: epochStartBlock,
		},
		lastBuiltBlock: lastBuiltBlock,
	}

	lastBuiltBlock, epochMetadata := consensusRuntime.getLastBuiltBlockAndEpoch()
	uptime, err := consensusRuntime.calculateUptime(lastBuiltBlock, epochMetadata)
	assert.NoError(t, err)
	assert.NotEmpty(t, uptime)
	assert.Equal(t, uint64(epoch), uptime.EpochID)
	assert.Equal(t, uint64(epochStartBlock), uptime.Epoch.StartBlock)
	assert.Equal(t, uint64(epochEndBlock), uptime.Epoch.EndBlock)

	blockchainMock.AssertExpectations(t)
	polybftBackendMock.AssertExpectations(t)
}

func TestConsensusRuntime_validateVote_VoteSentFromUnknownValidator(t *testing.T) {
	t.Parallel()

	epoch := &epochMetadata{Validators: newTestValidators(5).getPublicIdentities()}
	nonValidatorAccount := createTestKey(t)
	hash := crypto.Keccak256Hash(generateRandomBytes(t)).Bytes()
	// Sign content by non validator account
	signature, err := nonValidatorAccount.Sign(hash)
	require.NoError(t, err)

	vote := &MessageSignature{
		From:      nonValidatorAccount.String(),
		Signature: signature}
	assert.ErrorContains(t, validateVote(vote, epoch),
		fmt.Sprintf("message is received from sender %s, which is not in current validator set", vote.From))
}

func TestConsensusRuntime_buildBundles_NoCommitment(t *testing.T) {
	t.Parallel()

	state := newTestState(t)
	commitmentMsg := NewCommitmentMessage(types.Hash{}, 0, 4, 5)
	runtime := &consensusRuntime{
		logger:         hclog.NewNullLogger(),
		state:          state,
		epoch:          &epochMetadata{Number: 0},
		lastBuiltBlock: &types.Header{},
	}

	_, epoch := runtime.getLastBuiltBlockAndEpoch()
	assert.NoError(t, runtime.buildBundles(epoch.Commitment, commitmentMsg, 0))

	bundles, err := state.getBundles(0, 4)

	assert.NoError(t, err)
	assert.Nil(t, bundles)
}

func TestConsensusRuntime_buildBundles(t *testing.T) {
	t.Parallel()

	const (
		epoch                 = 1
		bundleSize            = 5
		fromIndex             = 0
		toIndex               = 4
		expectedBundlesNumber = 1
	)

	state := newTestState(t)
	stateSyncs := insertTestStateSyncEvents(t, bundleSize, 0, state)
	trie, err := createMerkleTree(stateSyncs, bundleSize)
	require.NoError(t, err)

	commitmentMsg := NewCommitmentMessage(trie.Hash(), fromIndex, toIndex, bundleSize)
	commitmentMsgSigned := &CommitmentMessageSigned{
		Message: commitmentMsg,
		AggSignature: Signature{
			Bitmap:              []byte{5, 1},
			AggregatedSignature: []byte{1, 1},
		},
	}
	require.NoError(t, state.insertCommitmentMessage(commitmentMsgSigned))

	runtime := &consensusRuntime{
		logger: hclog.NewNullLogger(),
		state:  state,
		epoch: &epochMetadata{
			Number: epoch,
			Commitment: &Commitment{
				MerkleTree: trie,
				Epoch:      epoch,
			},
		},
		lastBuiltBlock: &types.Header{},
	}

	_, epochData := runtime.getLastBuiltBlockAndEpoch()
	assert.NoError(t, runtime.buildBundles(epochData.Commitment, commitmentMsg, 0))

	bundles, err := state.getBundles(fromIndex, maxBundlesPerSprint)
	assert.NoError(t, err)
	assert.Equal(t, expectedBundlesNumber, len(bundles))
}

func TestConsensusRuntime_FSM_EndOfEpoch_OnBlockInserted(t *testing.T) {
	t.Parallel()

	const (
		epoch               = 1
		epochSize           = uint64(10)
		firstBlockInEpoch   = uint64(1)
		sprintSize          = uint64(5)
		beginStateSyncIndex = uint64(0)
		fromIndex           = uint64(0)
		toIndex             = uint64(9)
	)

	validatorAccounts := newTestValidatorsWithAliases([]string{"A", "B", "C", "D", "E"})
	signingAccounts := validatorAccounts.getPrivateIdentities()
	validators := validatorAccounts.getPublicIdentities()
	lastBuiltBlock, headerMap := createTestBlocks(t, 9, epochSize, validators)

	systemStateMock := new(systemStateMock)
	systemStateMock.On("GetNextCommittedIndex").Return(beginStateSyncIndex, nil)
	systemStateMock.On("GetNextExecutionIndex").Return(beginStateSyncIndex, nil)

	blockchainMock := new(blockchainMock)
	blockchainMock.On("NewBlockBuilder", mock.Anything).Return(&BlockBuilder{}, nil).Once()
	blockchainMock.On("GetStateProviderForBlock", mock.Anything).Return(new(stateProviderMock))
	blockchainMock.On("GetSystemState", mock.Anything, mock.Anything).Return(systemStateMock)
	blockchainMock.On("GetHeaderByNumber", mock.Anything).Return(headerMap.getHeader)

	txPool := new(txPoolMock)

	state := newTestState(t)
	require.NoError(t, state.insertEpoch(epoch))

	stateSyncs := generateStateSyncEvents(t, stateSyncMainBundleSize, 0)
	for _, event := range stateSyncs {
		require.NoError(t, state.insertStateSyncEvent(event))
	}

	trie, err := createMerkleTree(stateSyncs, stateSyncBundleSize)
	require.NoError(t, err)

	commitment := &Commitment{MerkleTree: trie, Epoch: epoch}
	hash, err := commitment.Hash()
	require.NoError(t, err)

	for _, a := range signingAccounts {
		signature, err := a.Bls.Sign(hash.Bytes())
		require.NoError(t, err)
		signatureRaw, err := signature.Marshal()
		require.NoError(t, err)
		_, err = state.insertMessageVote(epoch, hash.Bytes(), &MessageSignature{
			From:      a.Ecdsa.Address().String(),
			Signature: signatureRaw,
		})
		require.NoError(t, err)
	}

	metadata := &epochMetadata{
		Validators:        validators,
		Number:            epoch,
		FirstBlockInEpoch: firstBlockInEpoch,
		Commitment:        commitment,
	}

	config := &runtimeConfig{
		PolyBFTConfig: &PolyBFTConfig{
			EpochSize:  epochSize,
			SprintSize: sprintSize,
			Bridge:     &BridgeConfig{},
		},
		Key:        validatorAccounts.getValidator("A").Key(),
		blockchain: blockchainMock,
		txPool:     txPool,
	}

	runtime := &consensusRuntime{
		logger:            hclog.NewNullLogger(),
		state:             state,
		epoch:             metadata,
		config:            config,
		lastBuiltBlock:    lastBuiltBlock,
		checkpointManager: newCheckpointManager(types.StringToAddress("3"), 5, nil, nil, nil),
	}

	err = runtime.FSM()
	fsm := runtime.fsm

	assert.NoError(t, err)
	assert.NotNil(t, fsm.proposerCommitmentToRegister)
	assert.Equal(t, fromIndex, fsm.proposerCommitmentToRegister.Message.FromIndex)
	assert.Equal(t, toIndex, fsm.proposerCommitmentToRegister.Message.ToIndex)
	assert.Equal(t, uint64(stateSyncBundleSize), fsm.proposerCommitmentToRegister.Message.BundleSize)
	assert.Equal(t, trie.Hash(), fsm.proposerCommitmentToRegister.Message.MerkleRootHash)
	assert.NotNil(t, fsm.proposerCommitmentToRegister.AggSignature)
	assert.True(t, fsm.isEndOfEpoch)
	assert.NotNil(t, fsm.uptimeCounter)
	assert.NotEmpty(t, fsm.uptimeCounter)

	inputData, err := fsm.proposerCommitmentToRegister.EncodeAbi()
	assert.NoError(t, err)

	tx := createStateTransactionWithData(fsm.config.StateReceiverAddr, inputData)

	block := consensus.BuildBlock(consensus.BuildBlockParams{
		Header: &types.Header{Number: 1},
		Txns: []*types.Transaction{
			tx,
		},
	})

	txPool.On("ResetWithHeaders", mock.MatchedBy(func(i interface{}) bool {
		ph, ok := i.([]*types.Header)
		require.True(t, ok)
		require.Len(t, ph, 1)

		return ph[0].Number == block.Header.Number
	})).Once()

	runtime.OnBlockInserted(block)

	commitmentMsgFromDB, err := state.getCommitmentMessage(toIndex)
	assert.NoError(t, err)
	assert.Equal(t, fromIndex, commitmentMsgFromDB.Message.FromIndex)
	assert.Equal(t, toIndex, commitmentMsgFromDB.Message.ToIndex)
	assert.Equal(t, uint64(stateSyncBundleSize), commitmentMsgFromDB.Message.BundleSize)
	assert.Equal(t, trie.Hash(), commitmentMsgFromDB.Message.MerkleRootHash)
	assert.NotNil(t, commitmentMsgFromDB.AggSignature)

	bundles, err := state.getBundles(fromIndex, maxBundlesPerSprint)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(bundles))

	systemStateMock.AssertExpectations(t)
	blockchainMock.AssertExpectations(t)
}

func TestConsensusRuntime_getExitEventRootHash(t *testing.T) {
	t.Parallel()

	const (
		numOfBlocks         = 10
		numOfEventsPerBlock = 2
	)

	state := newTestState(t)
	runtime := &consensusRuntime{
		state: state,
	}

	encodedEvents := setupExitEventsForProofVerification(t, state, numOfBlocks, numOfEventsPerBlock)

	t.Run("Get exit event root hash", func(t *testing.T) {
		t.Parallel()

		tree, err := NewMerkleTree(encodedEvents)
		require.NoError(t, err)

		hash, err := runtime.BuildEventRoot(1, nil)
		require.NoError(t, err)
		require.Equal(t, tree.Hash(), hash)
	})

	t.Run("Get exit event root hash - no events", func(t *testing.T) {
		t.Parallel()

		hash, err := runtime.BuildEventRoot(2, nil)
		require.NoError(t, err)
		require.Equal(t, types.Hash{}, hash)
	})
}

func TestConsensusRuntime_GenerateExitProof(t *testing.T) {
	t.Parallel()

	const (
		numOfBlocks         = 10
		numOfEventsPerBlock = 2
	)

	state := newTestState(t)
	runtime := &consensusRuntime{
		state: state,
	}

	encodedEvents := setupExitEventsForProofVerification(t, state, numOfBlocks, numOfEventsPerBlock)
	checkpointEvents := encodedEvents[:numOfEventsPerBlock]

	// manually create merkle tree for a desired checkpoint to verify the generated proof
	tree, err := NewMerkleTree(checkpointEvents)
	require.NoError(t, err)

	proof, err := runtime.GenerateExitProof(1, 1, 1)
	require.NoError(t, err)
	require.NotNil(t, proof)

	t.Run("Generate and validate exit proof", func(t *testing.T) {
		t.Parallel()
		// verify generated proof on desired tree
		require.NoError(t, VerifyProof(1, encodedEvents[1], proof, tree.Hash()))
	})

	t.Run("Generate and validate exit proof - invalid proof", func(t *testing.T) {
		t.Parallel()

		var invalidProof []types.Hash
		invalidProof = append(invalidProof, proof...)
		invalidProof[0][0]++

		// verify generated proof on desired tree
		require.ErrorContains(t, VerifyProof(1, encodedEvents[1], invalidProof, tree.Hash()), "not a member of merkle tree")
	})

	t.Run("Generate exit proof - no event", func(t *testing.T) {
		t.Parallel()

		_, err := runtime.GenerateExitProof(21, 1, 1)
		require.ErrorContains(t, err, "could not find any exit event that has an id")
	})
}

func setupExitEventsForProofVerification(t *testing.T, state *State,
	numOfBlocks, numOfEventsPerBlock uint64) [][]byte {
	t.Helper()

	encodedEvents := make([][]byte, numOfBlocks*numOfEventsPerBlock)
	index := uint64(0)

	for i := uint64(1); i <= numOfBlocks; i++ {
		for j := uint64(1); j <= numOfEventsPerBlock; j++ {
			e := &ExitEvent{index, ethgo.ZeroAddress, ethgo.ZeroAddress, []byte{0, 1}, 1, i}
			require.NoError(t, state.insertExitEvent(e))

			b, err := exitEventABIType.Encode(e)

			require.NoError(t, err)

			encodedEvents[index] = b
			index++
		}
	}

	return encodedEvents
}

func createTestTransportMessage(t *testing.T, hash []byte, epochNumber uint64, key *wallet.Key) *TransportMessage {
	t.Helper()

	signature, _ := key.Sign(hash)

	return &TransportMessage{
		Hash:        hash,
		Signature:   signature,
		NodeID:      key.String(),
		EpochNumber: epochNumber,
	}
}

func createTestMessageVote(t *testing.T, hash []byte, validator *testValidator) *MessageSignature {
	t.Helper()

	signature, err := validator.mustSign(hash).Marshal()
	require.NoError(t, err)

	return &MessageSignature{
		From:      validator.Key().String(),
		Signature: signature,
	}
}

func createTestBlocks(t *testing.T, numberOfBlocks, defaultEpochSize uint64,
	validatorSet AccountSet) (*types.Header, *testHeadersMap) {
	t.Helper()

	headerMap := &testHeadersMap{}
	bitmaps := createTestBitmaps(t, validatorSet, numberOfBlocks)

	extra := &Extra{
		Checkpoint: &CheckpointData{EpochNumber: 0},
	}

	genesisBlock := &types.Header{
		Number:    0,
		ExtraData: append(make([]byte, ExtraVanity), extra.MarshalRLPTo(nil)...),
	}
	parentHash := types.BytesToHash(big.NewInt(0).Bytes())

	headerMap.addHeader(genesisBlock)

	var hash types.Hash

	var blockHeader *types.Header

	for i := uint64(1); i <= numberOfBlocks; i++ {
		big := big.NewInt(int64(i))
		hash = types.BytesToHash(big.Bytes())

		header := &types.Header{
			Number:     i,
			ParentHash: parentHash,
			ExtraData:  createTestExtraForAccounts(t, getEpochNumber(t, i, defaultEpochSize), validatorSet, bitmaps[i]),
			GasLimit:   types.StateTransactionGasLimit,
		}

		headerMap.addHeader(header)

		parentHash = hash
		blockHeader = header
	}

	return blockHeader, headerMap
}

func createTestBitmaps(t *testing.T, validators AccountSet, numberOfBlocks uint64) map[uint64]bitmap.Bitmap {
	t.Helper()

	bitmaps := make(map[uint64]bitmap.Bitmap, numberOfBlocks)

	rand.Seed(time.Now().Unix())

	for i := numberOfBlocks; i > 1; i-- {
		bitmap := bitmap.Bitmap{}
		j := 0

		for j != 3 {
			validator := validators[rand.Intn(validators.Len())]
			index := uint64(validators.Index(validator.Address))

			if !bitmap.IsSet(index) {
				bitmap.Set(index)
				j++
			}
		}

		bitmaps[i] = bitmap
	}

	return bitmaps
}

func createTestExtraForAccounts(t *testing.T, epoch uint64, validators AccountSet, b bitmap.Bitmap) []byte {
	t.Helper()

	dummySignature := [64]byte{}
	extraData := Extra{
		Validators: &ValidatorSetDelta{
			Added:   validators,
			Removed: bitmap.Bitmap{},
		},
		Parent:     &Signature{Bitmap: b, AggregatedSignature: dummySignature[:]},
		Committed:  &Signature{Bitmap: b, AggregatedSignature: dummySignature[:]},
		Checkpoint: &CheckpointData{EpochNumber: epoch},
	}

	marshaled := extraData.MarshalRLPTo(nil)
	result := make([]byte, ExtraVanity+len(marshaled))

	copy(result[ExtraVanity:], marshaled)

	return result
}

func insertTestStateSyncEvents(t *testing.T, numberOfEvents int, startIndex uint64, state *State) []*StateSyncEvent {
	t.Helper()

	stateSyncs := generateStateSyncEvents(t, numberOfEvents, startIndex)
	for _, stateSync := range stateSyncs {
		require.NoError(t, state.insertStateSyncEvent(stateSync))
	}

	return stateSyncs
}
