//! Light client error definition

use codec::alloc::string::String;
use sp_core::H256;
use sp_std::prelude::*;

#[derive(sp_std::fmt::Debug, derive_more::From, derive_more::Display)]
/// Error definition for the light client
pub enum BeefyClientError {
    /// Outdated commitment
    #[from(ignore)]
    #[display(
        fmt = "OutdatedCommitment: latest_beefy_height {}, commitment_block_number {}",
        latest_beefy_height,
        commitment_block_number
    )]
    OutdatedCommitment {
        /// Latest beefy height stored
        latest_beefy_height: u32,
        /// Commitment block number received
        commitment_block_number: u32,
    },
    /// Expected proof for latest leaf, found a batch proof
    ExpectedSingleLeafIndex,
    /// Mmr root hash not found in commitment
    MmrRootHashNotFound,
    /// Invalid Authority set id received
    #[from(ignore)]
    #[display(
        fmt = "AuthoritySetMismatch: current_set_id {}, next_set_id {}, commitment_set_id {}",
        current_set_id,
        next_set_id,
        commitment_set_id
    )]
    AuthoritySetMismatch {
        /// Current authority set id
        current_set_id: u64,
        /// Next authority set id
        next_set_id: u64,
        /// Authority set id in commitment
        commitment_set_id: u64,
    },
    /// Incomplete Signature threshold
    IncompleteSignatureThreshold,
    /// Error recovering public key from signature
    InvalidSignature,
    /// Some invalid merkle root hash
    #[from(ignore)]
    #[display(fmt = "InvalidRootHash with len: {}", len)]
    InvalidRootHash {
        /// Root hash
        root_hash: Vec<u8>,
        /// Root hash length
        len: u64,
    },
    /// Some invalid mmr proof
    #[display(
        fmt = "InvalidMmrProof, expected: {}, found: {}, during: {}",
        expected,
        found,
        location
    )]
    InvalidMmrProof {
        /// The root hash that was expected
        expected: H256,
        /// The root hash that was derived
        found: H256,
        /// The location of the error
        location: &'static str,
    },
    /// Invalid authority proof
    InvalidAuthorityProof,
    /// Invalid merkle proof
    InvalidMerkleProof,
    /// Mmr Error
    MmrVerificationError(mmr_lib::Error),
    /// Codec error
    Codec(codec::Error),
    /// Custom error
    Custom(String),
}
