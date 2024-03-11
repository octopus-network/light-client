//! Contains metadata generated code for interacting with the relay chain.

#![allow(missing_docs)]

#[cfg(feature = "build-metadata-from-ws")]
include!(concat!(env!("OUT_DIR"), "/runtime.rs"));

#[cfg(not(feature = "build-metadata-from-ws"))]
pub use subxt_generated::relaychain::*;
