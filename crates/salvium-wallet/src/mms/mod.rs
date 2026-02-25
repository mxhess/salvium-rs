//! Multisig Messaging System (MMS).
//!
//! Provides a complete subsystem for coordinating multisig wallet operations
//! between multiple signers via message passing (PyBitmessage transport).
//!
//! - `types`: Message types, states, directions, and processing actions
//! - `message_store`: CRUD operations for messages and signers
//! - `transport`: Bitmessage XML-RPC client with ChaCha20 encryption
//! - `state_machine`: Determines next recommended action

pub mod message_store;
pub mod state_machine;
pub mod transport;
pub mod types;

pub use state_machine::next_action;
pub use transport::{decrypt_message, encrypt_message, BitmessageTransport, TransportMessage};
pub use types::*;
