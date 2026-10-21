//! Runspace pool: lifecycle state machine + async driver.
//!
//! - [`state`] contains the **pure, sync** state machine
//!   (`RunspacePoolStateMachine`) that maps every `(state, event)` pair to a
//!   list of actions — no I/O, trivially unit-testable.
//! - [`pool`] contains the async [`RunspacePool`] that owns a
//!   [`crate::transport::PsrpTransport`] and executes the actions produced
//!   by the state machine.

pub mod pool;
pub mod state;

pub use pool::{DisconnectedPool, RunspacePool};
pub use state::{Action, PROTOCOL_VERSION, RunspacePoolState, RunspacePoolStateMachine};
