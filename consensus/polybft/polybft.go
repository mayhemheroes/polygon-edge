// Package polybft implements PBFT consensus algorithm integration and bridge feature
package polybft

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/0xPolygon/pbft-consensus"
	"github.com/0xPolygon/polygon-edge/chain"
	"github.com/0xPolygon/polygon-edge/command/rootchain/helper"
	"github.com/0xPolygon/polygon-edge/consensus"
	"github.com/0xPolygon/polygon-edge/consensus/polybft/proto"
	"github.com/0xPolygon/polygon-edge/consensus/polybft/wallet"
	"github.com/0xPolygon/polygon-edge/contracts"
	"github.com/0xPolygon/polygon-edge/helper/progress"
	"github.com/0xPolygon/polygon-edge/network"
	"github.com/0xPolygon/polygon-edge/secrets"
	"github.com/0xPolygon/polygon-edge/state"
	"github.com/0xPolygon/polygon-edge/syncer"
	"github.com/0xPolygon/polygon-edge/types"
	"github.com/hashicorp/go-hclog"
	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	minSyncPeers = 2
	pbftProto    = "/pbft/0.2"
	bridgeProto  = "/bridge/0.2"
)

// polybftBackend is an interface defining polybft methods needed by fsm and sync tracker
type polybftBackend interface {
	// CheckIfStuck checks if state machine is stuck.
	CheckIfStuck(num uint64) (uint64, bool)

	// GetValidators retrieves validator set for the given block
	GetValidators(blockNumber uint64, parents []*types.Header) (AccountSet, error)
}

// Factory is the factory function to create a discovery consensus
func Factory(params *consensus.Params) (consensus.Consensus, error) {
	logger := params.Logger.Named("polybft")

	setupHeaderHashFunc()

	polybft := &Polybft{
		config:  params,
		closeCh: make(chan struct{}),
		logger:  logger,
	}

	// initialize polybft consensus config
	customConfigJSON, err := json.Marshal(params.Config.Config)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(customConfigJSON, &polybft.consensusConfig)
	if err != nil {
		return nil, err
	}

	return polybft, nil
}

type Polybft struct {
	// close closes all the pbft consensus
	closeCh chan struct{}

	// ibft is the ibft engine
	ibft *MyIBFTConsensus

	// state is reference to the struct which encapsulates consensus data persistence logic
	state *State

	// consensus parametres
	config *consensus.Params

	// consensusConfig is genesis configuration for polybft consensus protocol
	consensusConfig *PolyBFTConfig

	// blockchain is a reference to the blockchain object
	blockchain blockchainBackend

	// runtime handles consensus runtime features like epoch, state and event management
	runtime *consensusRuntime

	// block time duration
	blockTime time.Duration

	// dataDir is the data directory to store the info
	dataDir string

	// reference to the syncer
	syncer syncer.Syncer

	// topic for pbft consensus
	consensusTopic *network.Topic

	// topic for pbft consensus
	bridgeTopic *network.Topic

	// key encapsulates ECDSA address and BLS signing logic
	key *wallet.Key

	// validatorsCache represents cache of validators snapshots
	validatorsCache *validatorsSnapshotCache

	// logger
	logger hclog.Logger
}

func GenesisPostHookFactory(config *chain.Chain, engineName string) func(txn *state.Transition) error {
	return func(transition *state.Transition) error {
		var pbftConfig PolyBFTConfig

		customConfigJSON, err := json.Marshal(config.Params.Engine[engineName])
		if err != nil {
			return err
		}

		err = json.Unmarshal(customConfigJSON, &pbftConfig)
		if err != nil {
			return err
		}
		// Initialize child validator set
		input, err := getInitChildValidatorSetInput(pbftConfig.InitialValidatorSet, pbftConfig.Governance)
		if err != nil {
			return err
		}

		if err = initContract(contracts.ValidatorSetContract, input, "ChildValidatorSet", transition); err != nil {
			return err
		}

		input, err = initNativeTokenMethod.Encode(
			[]interface{}{helper.GetDefAccount(), nativeTokenName, nativeTokenSymbol})
		if err != nil {
			return err
		}

		return initContract(contracts.NativeTokenContract, input, "MRC20", transition)
	}
}

// Initialize initializes the consensus (e.g. setup data)
func (p *Polybft) Initialize() error {
	p.logger.Info("initializing polybft...")

	// read account
	account, err := wallet.GenerateNewAccountFromSecret(
		p.config.SecretsManager, secrets.ValidatorBLSKey)
	if err != nil {
		return fmt.Errorf("failed to read account data. Error: %w", err)
	}

	// set key
	p.key = wallet.NewKey(account)

	// create and set syncer
	p.syncer = syncer.NewSyncer(
		p.config.Logger.Named("syncer"),
		p.config.Network,
		p.config.Blockchain,
		time.Duration(p.config.BlockTime)*3*time.Second,
	)

	// set blockchain backend
	p.blockchain = &blockchainWrapper{
		blockchain: p.config.Blockchain,
		executor:   p.config.Executor,
	}

	// create bridge and consensus topics
	if err := p.createTopics(); err != nil {
		return err
	}

	// set pbft topic, it will be check if/when the bridge is enabled
	p.initRuntime()

	// initialize pbft engine
	// opts := []pbft.ConfigOption{
	// 	pbft.WithLogger(p.logger.Named("Pbft").
	// 		StandardLogger(&hclog.StandardLoggerOptions{}),
	// 	),
	// 	pbft.WithTracer(otel.Tracer("Pbft")),
	// }

	p.ibft = newIBFT(p.logger, p.runtime, p.runtime)

	// subscribe to consensus and bridge topics
	if err = p.subscribeToTopics(); err != nil {
		return err
	}

	// set block time
	p.blockTime = time.Duration(p.config.BlockTime)

	// initialize polybft consensus data directory
	p.dataDir = filepath.Join(p.config.Config.Path, "polybft")
	// create the data dir if not exists
	if err := os.MkdirAll(p.dataDir, 0750); err != nil {
		return fmt.Errorf("failed to create data directory. Error: %w", err)
	}

	stt, err := newState(filepath.Join(p.dataDir, stateFileName), p.logger)
	if err != nil {
		return fmt.Errorf("failed to create state instance. Error: %w", err)
	}

	p.state = stt
	p.validatorsCache = newValidatorsSnapshotCache(p.config.Logger, stt, p.consensusConfig.EpochSize, p.blockchain)

	return nil
}

// Start starts the consensus and servers
func (p *Polybft) Start() error {
	p.logger.Info("starting polybft consensus")

	// start syncer
	if err := p.startSyncing(); err != nil {
		return err
	}

	// start consensus
	return p.startSealing()
}

// startSyncing starts the synchroniser
func (p *Polybft) startSyncing() error {
	if err := p.syncer.Start(); err != nil {
		return fmt.Errorf("failed to start syncer. Error: %w", err)
	}

	go func() {
		nullHandler := func(b *types.Block) bool {
			return false
		}

		if err := p.syncer.Sync(nullHandler); err != nil {
			panic(fmt.Errorf("failed to sync blocks. Error: %w", err))
		}
	}()

	return nil
}

// startSealing is executed if the PolyBFT protocol is running in sealing mode.
func (p *Polybft) startSealing() error {
	p.logger.Info("Using signer", "address", p.key.String())

	if err := p.startRuntime(); err != nil {
		return fmt.Errorf("consensus runtime start failed: %w", err)
	}

	go func() {
		// start the pbft process
		p.startPbftProcess()
	}()

	return nil
}

// initRuntime creates consensus runtime
func (p *Polybft) initRuntime() {
	transportWrapper := newRuntimeTransportWrapper(p.bridgeTopic, p.consensusTopic)
	runtimeConfig := &runtimeConfig{
		PolyBFTConfig:      p.consensusConfig,
		Key:                p.key,
		DataDir:            p.dataDir,
		BridgeTransport:    transportWrapper,
		ConsensusTransport: transportWrapper,
		State:              p.state,
		blockchain:         p.blockchain,
		polybftBackend:     p,
		txPool:             p.config.TxPool,
	}

	p.runtime = newConsensusRuntime(p.logger, runtimeConfig)
}

// startRuntime starts consensus runtime
func (p *Polybft) startRuntime() error {
	if p.runtime.IsBridgeEnabled() {
		err := p.runtime.startEventTracker()
		if err != nil {
			return fmt.Errorf("starting event tracker  failed:%w", err)
		}

		err = p.bridgeTopic.Subscribe(func(obj interface{}, from peer.ID) {
			msg, _ := obj.(*proto.TransportMessage)
			var transportMsg *TransportMessage
			if err := json.Unmarshal(msg.Data, &transportMsg); err != nil {
				p.logger.Warn("Failed to deliver message", "err", err)

				return
			}

			if _, err := p.runtime.deliverMessage(transportMsg); err != nil {
				p.logger.Warn("Failed to deliver message", "err", err)
			}
		})
		if err != nil {
			return fmt.Errorf("topic subscription failed:%w", err)
		}
	}

	return nil
}

func (p *Polybft) startPbftProcess() {
	// wait to have at least n peers connected. The 2 is just an initial heuristic value
	// Most likely we will parametrize this in the future.
	if !p.waitForNPeers() {
		return
	}

	newBlockSub := p.blockchain.SubscribeEvents()
	syncerBlockCh := make(chan struct{})

	go func() {
		eventCh := newBlockSub.GetEventCh()

		for {
			if ev := <-eventCh; ev.Source == "syncer" {
				if ev.NewChain[0].Number < p.blockchain.CurrentHeader().Number {
					// The blockchain notification system can eventually deliver
					// stale block notifications. These should be ignored
					continue
				}

				syncerBlockCh <- struct{}{}
			}
		}
	}()

	defer newBlockSub.Close()

	sequenceCh := make(<-chan struct{})
	isValidator := false

	for {
		latest := p.blockchain.CurrentHeader().Number
		pending := latest + 1

		currentValidators, err := p.GetValidators(latest, nil)
		if err != nil {
			p.logger.Error("failed to query current validator set", "block number", latest, "error", err)
		}

		p.runtime.setIsActiveValidator(currentValidators.ContainsNodeID(p.key.NodeID()))
		isValidator = p.runtime.isActiveValidator()

		//p.txpool.SetSealing(isValidator) // Nemanja: is this necessary

		if isValidator {
			_, err := p.runtime.FSM() // Nemanja: what to do if it is an error
			if err != nil {
				p.logger.Error("failed to create fsm", "block number", latest, "error", err)

				continue
			}

			sequenceCh = p.ibft.runSequence(pending)
		}

		select {
		case <-syncerBlockCh:
			if isValidator {
				p.ibft.stopSequence()
				p.logger.Info("canceled sequence", "sequence", pending)
			}
		case <-sequenceCh:
		case <-p.closeCh:
			if isValidator {
				p.ibft.stopSequence()
			}

			return
		}
	}
}

// isSynced return true if the current header from the local storage corresponds to the highest block of syncer
func (p *Polybft) isSynced() bool {
	// TODO: Check could we change following condition to this:
	// p.syncer.GetSyncProgression().CurrentBlock >= p.syncer.GetSyncProgression().HighestBlock
	syncProgression := p.syncer.GetSyncProgression()

	return syncProgression == nil ||
		p.blockchain.CurrentHeader().Number >= syncProgression.HighestBlock
}

func (p *Polybft) waitForNPeers() bool {
	for {
		select {
		case <-p.closeCh:
			return false
		case <-time.After(2 * time.Second):
		}

		numPeers := len(p.config.Network.Peers())
		if numPeers >= minSyncPeers {
			break
		}
	}

	return true
}

// Close closes the connection
func (p *Polybft) Close() error {
	if p.syncer != nil {
		if err := p.syncer.Close(); err != nil {
			return err
		}
	}

	close(p.closeCh)

	return nil
}

// GetSyncProgression retrieves the current sync progression, if any
func (p *Polybft) GetSyncProgression() *progress.Progression {
	return p.syncer.GetSyncProgression()
}

// VerifyHeader implements consensus.Engine and checks whether a header conforms to the consensus rules
func (p *Polybft) VerifyHeader(header *types.Header) error {
	// Short circuit if the header is known
	_, ok := p.blockchain.GetHeaderByHash(header.Hash)
	if ok {
		return nil
	}

	parent, ok := p.blockchain.GetHeaderByHash(header.ParentHash)
	if !ok {
		return fmt.Errorf(
			"unable to get parent header by hash for block number %d",
			header.Number,
		)
	}

	return p.verifyHeaderImpl(parent, header, nil)
}

func (p *Polybft) verifyHeaderImpl(parent, header *types.Header, parents []*types.Header) error {
	blockNumber := header.Number
	if blockNumber == 0 {
		// TODO: Remove, this was just for simplicity since I had started the chain already,
		//  add the mix hash into the genesis command
		return nil
	}

	//validate header fields
	if err := validateHeaderFields(parent, header); err != nil {
		return fmt.Errorf("failed to validate header for block %d. error = %w", blockNumber, err)
	}

	validators, err := p.GetValidators(blockNumber-1, parents)
	if err != nil {
		return fmt.Errorf("failed to validate header for block %d. could not retrieve block validators:%w", blockNumber, err)
	}

	// decode the extra field and validate the signatures
	extra, err := GetIbftExtra(header.ExtraData)
	if err != nil {
		return fmt.Errorf("failed to verify header for block %d. get extra error = %w", blockNumber, err)
	}

	if extra.Committed == nil {
		return fmt.Errorf(
			"failed to verify signatures for block %d because signatures are nil. Block hash: %v",
			blockNumber,
			header.Hash,
		)
	}

	if err := extra.Committed.VerifyCommittedFields(validators, header.Hash); err != nil {
		return fmt.Errorf("failed to verify signatures for block %d. Block hash: %v", blockNumber, header.Hash)
	}

	// validate the signatures for parent (skip block 1 because genesis does not have committed)
	if blockNumber > 1 {
		if extra.Parent == nil {
			return fmt.Errorf(
				"failed to verify signatures for parent of block %d because signatures are nil. Parent hash: %v",
				blockNumber,
				parent.Hash,
			)
		}

		parentValidators, err := p.GetValidators(blockNumber-2, parents)
		if err != nil {
			return fmt.Errorf(
				"failed to validate header for block %d. could not retrieve parent validators:%w",
				blockNumber,
				err,
			)
		}

		if err := extra.Parent.VerifyCommittedFields(parentValidators, parent.Hash); err != nil {
			return fmt.Errorf("failed to verify signatures for parent of block %d. Parent hash: %v", blockNumber, parent.Hash)
		}
	}

	return nil
}

func (p *Polybft) CheckIfStuck(num uint64) (uint64, bool) {
	if !p.isSynced() {
		// we are currently syncing new data, for sure we are stuck.
		// We can return 0 here at least for now since that value is only used
		// for the open telemetry tracing.
		return 0, true
	}

	// Now, we have to check if the current value of the round 'num' is lower
	// than our currently synced block.
	currentHeader := p.blockchain.CurrentHeader().Number
	if currentHeader > num {
		// at this point, it will exit the sync process and start the fsm round again
		// (or sync a small number of blocks) to start from the correct position.
		return currentHeader, true
	}

	return 0, false
}

func (p *Polybft) GetValidators(blockNumber uint64, parents []*types.Header) (AccountSet, error) {
	return p.validatorsCache.GetSnapshot(blockNumber, parents)
}

// ProcessHeaders updates the snapshot based on the verified headers
func (p *Polybft) ProcessHeaders(_ []*types.Header) error {
	// Not required
	return nil
}

// GetBlockCreator retrieves the block creator (or signer) given the block header
func (p *Polybft) GetBlockCreator(h *types.Header) (types.Address, error) {
	return types.BytesToAddress(h.Miner), nil
}

// PreCommitState a hook to be called before finalizing state transition on inserting block
func (p *Polybft) PreCommitState(_ *types.Header, _ *state.Transition) error {
	// Not required
	return nil
}

type pbftTransportWrapper struct {
	topic *network.Topic
}

func (p *pbftTransportWrapper) Gossip(msg *pbft.MessageReq) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	return p.topic.Publish(
		&proto.GossipMessage{
			Data: data,
		})
}

var _ polybftBackend = &Polybft{}