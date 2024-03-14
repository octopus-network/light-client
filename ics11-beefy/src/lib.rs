#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::all)]

//! ICS-11: Beefy IBC light client protocol implementation

extern crate alloc;
extern crate core;

// pub mod client_def;
pub mod client_message;
pub mod client_state;
pub mod consensus_state;
pub mod error;
pub mod misbehaviour;
mod proto;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
