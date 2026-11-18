//! API types for the notification system.
//!
//! Contains the schema-annotated types used for
//!   - endpoint and matcher configuration
//!   - the generic target listing
//!   - send receipts.

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
