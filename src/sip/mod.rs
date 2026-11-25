//! SIP proxy registration and INVITE interception.
//!
//! Maintains SIP registrations on behalf of mobile devices and intercepts
//! incoming INVITEs to trigger push notifications.

pub mod digest;
pub mod failover;
pub mod message;
pub mod outgoing;
#[cfg(test)]
mod pbx_sim;
pub mod proxy;
pub mod resolver;
pub mod rtp_relay;
pub mod transaction;
pub mod transport;
pub mod trust;
pub mod validate;

pub use proxy::{SipAccountConfig, SipProxyManager};
