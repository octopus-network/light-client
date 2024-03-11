use alloc::string::ToString;
use beefy_primitives::{known_payloads::MMR_ROOT_ID, mmr::BeefyNextAuthoritySet};
use codec::{Decode, Encode};
use core::{convert::TryFrom, fmt::Debug, marker::PhantomData, time::Duration};
use serde::{Deserialize, Serialize};
use sp_core::H256;
use sp_runtime::SaturatedConversion;
use tendermint_proto::Protobuf;

use crate::proto::{BeefyAuthoritySet, ClientState as RawClientState};

use crate::{client_message::BeefyHeader, error::Error};

use crate::client_def::BeefyClient;
use ibc::core::ics02_client::client_type::ClientType;
use ibc::{core::ics24_host::identifier::ChainId, timestamp::Timestamp, Height};
use light_client_common::RelayChain;

/// Protobuf type url for Beefy ClientState
pub const BEEFY_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.beefy.v1.ClientState";

#[derive(PartialEq, Clone, Debug, Default, Eq)]
pub struct ClientState<H> {
    /// The chain id
    pub chain_id: ChainId,
    /// Relay chain
    pub relay_chain: RelayChain,
    /// Latest mmr root hash
    pub mmr_root_hash: H256,
    /// block number for the latest mmr_root_hash
    pub latest_beefy_height: u32,
    /// Block height when the client was frozen due to a misbehaviour
    pub frozen_height: Option<Height>,
    /// latest parachain height
    pub latest_para_height: u32,
    /// ParaId of associated parachain
    pub para_id: u32,
    /// authorities for the current round
    pub authority: BeefyNextAuthoritySet<H256>,
    /// authorities for the next round
    pub next_authority_set: BeefyNextAuthoritySet<H256>,
    /// Phantom type
    pub _phantom: PhantomData<H>,
}

impl<H: Clone> Protobuf<RawClientState> for ClientState<H> {}

impl<H: Clone> ClientState<H> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        relay_chain: RelayChain,
        para_id: u32,
        latest_para_height: u32,
        mmr_root_hash: H256,
        latest_beefy_height: u32,
        authority_set: BeefyNextAuthoritySet<H256>,
        next_authority_set: BeefyNextAuthoritySet<H256>,
    ) -> Result<ClientState<H>, Error> {
        if authority_set.id >= next_authority_set.id {
            return Err(Error::Custom(
                "ClientState next authority set id must be greater than current authority set id"
                    .to_string(),
            ));
        }
        let chain_id = ChainId::new(relay_chain.to_string(), para_id.into());

        Ok(Self {
            chain_id,
            mmr_root_hash,
            latest_beefy_height,
            frozen_height: None,
            authority: authority_set,
            next_authority_set,
            relay_chain,
            latest_para_height,
            para_id,
            _phantom: PhantomData,
        })
    }

    /// Should only be called if this header has been verified successfully
    pub fn from_header(self, header: BeefyHeader) -> Result<Self, Error> {
        let mut clone = self.clone();
        let mut authority_changed = false;
        let (mmr_root_hash, latest_beefy_height, next_authority_set) =
            if let Some(mmr_update) = header.mmr_update_proof {
                if mmr_update.signed_commitment.commitment.validator_set_id
                    == self.next_authority_set.id
                {
                    authority_changed = true;
                }
                (
                    H256::from_slice(
                        mmr_update
                            .signed_commitment
                            .commitment
                            .payload
                            .get_raw(&MMR_ROOT_ID)
                            .ok_or_else(|| Error::Custom("Invalid header".into()))?,
                    ),
                    mmr_update.signed_commitment.commitment.block_number,
                    mmr_update.latest_mmr_leaf.beefy_next_authority_set,
                )
            } else {
                (
                    self.mmr_root_hash,
                    self.latest_beefy_height,
                    self.next_authority_set,
                )
            };
        clone.mmr_root_hash = mmr_root_hash;
        clone.latest_beefy_height = latest_beefy_height;
        if authority_changed {
            clone.authority = clone.next_authority_set;
            clone.next_authority_set = next_authority_set;
        }
        Ok(clone)
    }

    /// Verify the time and height delays
    pub fn verify_delay_passed(
        current_time: Timestamp,
        current_height: Height,
        processed_time: Timestamp,
        processed_height: Height,
        delay_period_time: Duration,
        delay_period_blocks: u64,
    ) -> Result<(), Error> {
        let earliest_time = (processed_time + delay_period_time)
            .map_err(|_| Error::Custom("Timestamp overflowed!".into()))?;
        if !(current_time == earliest_time || current_time.after(&earliest_time)) {
            return Err(Error::Custom(format!("Not enough time elapsed current time: {current_time}, earliest time: {earliest_time}")));
        }

        let earliest_height = processed_height.add(delay_period_blocks);
        if current_height < earliest_height {
            return Err(Error::Custom(format!("Not enough blocks elapsed, current height: {current_height}, earliest height: {earliest_height}")));
        }

        Ok(())
    }

    pub fn with_frozen_height(self, h: Height) -> Result<Self, Error> {
        if h == Height::zero() {
            return Err(Error::Custom(
                "ClientState frozen height must be greater than zero".to_string(),
            ));
        }
        Ok(Self {
            frozen_height: Some(h),
            ..self
        })
    }

    /// Verify that the client is at a sufficient height and unfrozen at the given height
    pub fn verify_height(&self, height: Height) -> Result<(), Error> {
        let latest_para_height = Height::new(self.para_id.into(), self.latest_para_height.into());
        if latest_para_height < height {
            return Err(Error::Custom(format!(
                "Insufficient height, known height: {latest_para_height}, given height: {height}"
            )));
        }

        match self.frozen_height {
            Some(frozen_height) if frozen_height <= height => Err(Error::Custom(format!(
                "Client has been frozen at height {frozen_height}"
            ))),
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeOptions;

impl<H> ClientState<H> {
    pub fn latest_height(&self) -> Height {
        Height::new(self.para_id.into(), self.latest_para_height.into())
    }

    pub fn chain_id(&self) -> ChainId {
        self.chain_id.clone()
    }

    pub fn client_type() -> ClientType {
        "11-beefy".to_string()
    }

    pub fn frozen_height(&self) -> Option<Height> {
        self.frozen_height
    }

    pub fn upgrade(
        mut self,
        upgrade_height: Height,
        _upgrade_options: UpgradeOptions,
        _chain_id: ChainId,
    ) -> Self {
        self.frozen_height = None;
        // Upgrade the client state
        self.latest_beefy_height = upgrade_height.revision_height.saturated_into::<u32>();

        self
    }

    /// Check if the state is expired when `elapsed` time has passed since the latest consensus
    /// state timestamp
    pub fn expired(&self, elapsed: Duration) -> bool {
        elapsed > self.relay_chain.trusting_period()
    }
}

impl<H> ibc::core::ics02_client::client_state::ClientState for ClientState<H>
where
    H: light_client_common::HostFunctions + beefy_light_client_primitives::HostFunctions,
{
    fn chain_id(&self) -> ChainId {
        self.chain_id()
    }

    fn client_type(&self) -> ClientType {
        Self::client_type()
    }

    fn latest_height(&self) -> Height {
        self.latest_height()
    }

    fn frozen_height(&self) -> Option<Height> {
        self.frozen_height()
    }

    fn expired(&self, elapsed: Duration) -> bool {
        self.expired(elapsed)
    }

    /// Helper function to verify the upgrade client procedure.
    /// Resets all fields except the blockchain-specific ones,
    /// and updates the given fields.
    fn zero_custom_fields(&mut self) {}

    fn initialise(&self, consensus_state: Any) -> Result<Box<dyn ConsensusState>, ClientError> {
        todo!()
    }

    fn check_header_and_update_state(
        &self,
        ctx: &dyn ClientReader,
        client_id: ClientId,
        header: Any,
    ) -> Result<UpdatedState, ClientError> {
        todo!("check_header_and_update_state")
    }

    fn check_misbehaviour_and_update_state(
        &self,
        ctx: &dyn ClientReader,
        client_id: ClientId,
        misbehaviour: Any,
    ) -> Result<Box<dyn ClientState>, ClientError> {
        todo!()
    }

    /// Verify the upgraded client and consensus states and validate proofs
    /// against the given root.
    ///
    /// NOTE: proof heights are not included as upgrade to a new revision is
    /// expected to pass only on the last height committed by the current
    /// revision. Clients are responsible for ensuring that the planned last
    /// height of the current revision is somehow encoded in the proof
    /// verification process. This is to ensure that no premature upgrades
    /// occur, since upgrade plans committed to by the counterparty may be
    /// cancelled or modified before the last planned height.
    fn verify_upgrade_client(
        &self,
        upgraded_client_state: Any,
        upgraded_consensus_state: Any,
        proof_upgrade_client: MerkleProof,
        proof_upgrade_consensus_state: MerkleProof,
        root: &CommitmentRoot,
    ) -> Result<(), ClientError> {
        todo!()
    }

    // Update the client state and consensus state in the store with the upgraded ones.
    fn update_state_with_upgrade_client(
        &self,
        upgraded_client_state: Any,
        upgraded_consensus_state: Any,
    ) -> Result<UpdatedState, ClientError> {
        todo!()
    }

    /// Verification functions as specified in:
    /// <https://github.com/cosmos/ibc/tree/master/spec/core/ics-002-client-semantics>
    ///
    /// Verify a `proof` that the consensus state of a given client (at height `consensus_height`)
    /// matches the input `consensus_state`. The parameter `counterparty_height` represent the
    /// height of the counterparty chain that this proof assumes (i.e., the height at which this
    /// proof was computed).
    #[allow(clippy::too_many_arguments)]
    fn verify_client_consensus_state(
        &self,
        proof_height: Height,
        counterparty_prefix: &CommitmentPrefix,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        counterparty_client_id: &ClientId,
        consensus_height: Height,
        expected_consensus_state: &dyn ConsensusState,
    ) -> Result<(), ClientError> {
        todo!()
    }

    /// Verify a `proof` that a connection state matches that of the input `connection_end`.
    #[allow(clippy::too_many_arguments)]
    fn verify_connection_state(
        &self,
        proof_height: Height,
        counterparty_prefix: &CommitmentPrefix,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        counterparty_connection_id: &ConnectionId,
        expected_counterparty_connection_end: &ConnectionEnd,
    ) -> Result<(), ClientError> {
        todo!()
    }

    /// Verify a `proof` that a channel state matches that of the input `channel_end`.
    #[allow(clippy::too_many_arguments)]
    fn verify_channel_state(
        &self,
        proof_height: Height,
        counterparty_prefix: &CommitmentPrefix,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        counterparty_port_id: &PortId,
        counterparty_channel_id: &ChannelId,
        expected_counterparty_channel_end: &ChannelEnd,
    ) -> Result<(), ClientError> {
        todo!()
    }

    /// Verify the client state for this chain that it is stored on the counterparty chain.
    #[allow(clippy::too_many_arguments)]
    fn verify_client_full_state(
        &self,
        proof_height: Height,
        counterparty_prefix: &CommitmentPrefix,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        client_id: &ClientId,
        expected_client_state: Any,
    ) -> Result<(), ClientError> {
        todo!()
    }

    /// Verify a `proof` that a packet has been committed.
    #[allow(clippy::too_many_arguments)]
    fn verify_packet_data(
        &self,
        ctx: &dyn ChannelReader,
        height: Height,
        connection_end: &ConnectionEnd,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
        commitment: PacketCommitment,
    ) -> Result<(), ClientError> {
        todo!()
    }

    /// Verify a `proof` that a packet has been committed.
    #[allow(clippy::too_many_arguments)]
    fn verify_packet_acknowledgement(
        &self,
        ctx: &dyn ChannelReader,
        height: Height,
        connection_end: &ConnectionEnd,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
        ack: AcknowledgementCommitment,
    ) -> Result<(), ClientError> {
        todo!()
    }

    /// Verify a `proof` that of the next_seq_received.
    #[allow(clippy::too_many_arguments)]
    fn verify_next_sequence_recv(
        &self,
        ctx: &dyn ChannelReader,
        height: Height,
        connection_end: &ConnectionEnd,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<(), ClientError> {
        todo!()
    }

    /// Verify a `proof` that a packet has not been received.
    #[allow(clippy::too_many_arguments)]
    fn verify_packet_receipt_absence(
        &self,
        ctx: &dyn ChannelReader,
        height: Height,
        connection_end: &ConnectionEnd,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<(), ClientError> {
        todo!()
    }
}

// Implements `Clone` for `Box<dyn ClientState>`
dyn_clone::clone_trait_object!(ClientState);

// Implements `serde::Serialize` for all types that have ClientState as supertrait
#[cfg(feature = "serde")]
erased_serde::serialize_trait_object!(ClientState);

impl PartialEq for dyn ClientState {
    fn eq(&self, other: &Self) -> bool {
        self.eq_client_state(other)
    }
}

// see https://github.com/rust-lang/rust/issues/31740
impl PartialEq<&Self> for Box<dyn ClientState> {
    fn eq(&self, other: &&Self) -> bool {
        self.eq_client_state(other.as_ref())
    }
}

pub fn downcast_client_state<CS: ClientState>(h: &dyn ClientState) -> Option<&CS> {
    h.as_any().downcast_ref::<CS>()
}

pub struct UpdatedState {
    pub client_state: Box<dyn ClientState>,
    pub consensus_state: Box<dyn ConsensusState>,
}

mod sealed {
    use super::*;

    pub trait ErasedPartialEqClientState {
        fn eq_client_state(&self, other: &dyn ClientState) -> bool;
    }

    impl<CS> ErasedPartialEqClientState for CS
    where
        CS: ClientState + PartialEq,
    {
        fn eq_client_state(&self, other: &dyn ClientState) -> bool {
            other
                .as_any()
                .downcast_ref::<CS>()
                .map_or(false, |h| self == h)
        }
    }
}

impl<H> TryFrom<RawClientState> for ClientState<H> {
    type Error = Error;

    fn try_from(raw: RawClientState) -> Result<Self, Self::Error> {
        let authority_set = raw
            .authority
            .and_then(|set| {
                Some(BeefyNextAuthoritySet {
                    id: set.id,
                    len: set.len,
                    root: H256::decode(&mut &*set.authority_root).ok()?,
                })
            })
            .ok_or_else(|| Error::Custom(format!("Current authority set is missing")))?;

        let next_authority_set = raw
            .next_authority_set
            .and_then(|set| {
                Some(BeefyNextAuthoritySet {
                    id: set.id,
                    len: set.len,
                    root: H256::decode(&mut &*set.authority_root).ok()?,
                })
            })
            .ok_or_else(|| Error::Custom(format!("Next authority set is missing")))?;

        let mmr_root_hash = H256::decode(&mut &*raw.mmr_root_hash)?;
        let relay_chain = RelayChain::from_i32(raw.relay_chain)?;
        let chain_id = ChainId::new(relay_chain.to_string(), raw.para_id.into());

        Ok(Self {
            chain_id,
            mmr_root_hash,
            latest_beefy_height: raw.latest_beefy_height,
            frozen_height: raw
                .frozen_height
                .map(|height| Height::new(raw.para_id.into(), height)),
            authority: authority_set,
            next_authority_set,
            relay_chain,
            latest_para_height: raw.latest_para_height,
            para_id: raw.para_id,
            _phantom: Default::default(),
        })
    }
}

impl<H> From<ClientState<H>> for RawClientState {
    fn from(client_state: ClientState<H>) -> Self {
        RawClientState {
            mmr_root_hash: client_state.mmr_root_hash.encode(),
            latest_beefy_height: client_state.latest_beefy_height,
            frozen_height: client_state
                .frozen_height
                .map(|frozen_height| frozen_height.revision_height),
            authority: Some(BeefyAuthoritySet {
                id: client_state.authority.id,
                len: client_state.authority.len,
                authority_root: client_state.authority.root.encode(),
            }),
            next_authority_set: Some(BeefyAuthoritySet {
                id: client_state.next_authority_set.id,
                len: client_state.next_authority_set.len,
                authority_root: client_state.next_authority_set.root.encode(),
            }),
            relay_chain: client_state.relay_chain as i32,
            para_id: client_state.para_id,
            latest_para_height: client_state.latest_para_height,
        }
    }
}

#[cfg(test)]
pub mod test_util {
    use super::*;
    use crate::mock::AnyClientState;

    pub fn get_dummy_beefy_state() -> AnyClientState {
        AnyClientState::Beefy(
            ClientState::new(
                RelayChain::Rococo,
                2000,
                0,
                Default::default(),
                0,
                Default::default(),
                Default::default(),
            )
            .unwrap(),
        )
    }
}
