//! # keymesh-core
//!
//! Security-critical protocol core for KEYMESH: a non-custodial key
//! management, transaction authorization, and recovery protocol.
//!
//! ## Maturity: PROTOTYPE
//!
//! This crate defines the protocol state machines, policy evaluation, and
//! serialization boundaries. It contains **no real cryptography**. The
//! [`crypto`] module exposes the interface that a reviewed implementation
//! (threshold signatures / MPC in Phase 2) must satisfy; the bundled mock
//! provider exists strictly for tests and local development.
//!
//! ## Module map
//!
//! - [`crypto`]: cryptographic provider boundary (mock implementation only)
//! - [`signing`]: signing service boundary over the crypto provider
//! - [`recovery`]: guardian recovery state machine (pure, deterministic)
//! - [`policy`]: transaction authorization policy evaluation
//! - [`serialization`]: deterministic binary encoding for protocol messages
//! - [`errors`]: shared error type

pub mod crypto;
pub mod errors;
pub mod policy;
pub mod recovery;
pub mod serialization;
pub mod signing;

pub use errors::KeymeshError;

/// Protocol version of this core library.
pub const PROTOCOL_VERSION: &str = "0.1.0";
