//! API types for the notification system.
//!
//! Contains the schema-annotated types used for
//!   - endpoint and matcher configuration
//!   - the generic target listing
//!   - send receipts.

use serde::{Deserialize, Serialize};

use proxmox_schema::api;

mod gotify;
pub use gotify::*;

mod sendmail;
pub use sendmail::*;

mod webhook;
pub use webhook::*;

mod smtp;
pub use smtp::*;

mod matcher;
pub use matcher::*;

#[api]
#[derive(Clone, Debug, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
/// The origin of a notification configuration entry.
pub enum Origin {
    /// User-created config entry
    UserCreated,
    /// Config entry provided by the system
    Builtin,
    /// Config entry provided by the system, but modified by the user.
    ModifiedBuiltin,
}
