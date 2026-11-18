use crate::{Error, Notification};

#[cfg(feature = "gotify")]
pub mod gotify;
#[cfg(feature = "sendmail")]
pub mod sendmail;
#[cfg(feature = "smtp")]
pub mod smtp;
#[cfg(feature = "webhook")]
pub mod webhook;

mod common;

/// Notification endpoint trait, implemented by all endpoint plugins
pub(crate) trait Endpoint {
    /// Send a notification to this endpoint.
    fn send(&self, notification: &Notification) -> Result<(), Error>;

    /// The name/identifier for this endpoint
    fn name(&self) -> &str;

    /// Check if the endpoint is disabled
    fn disabled(&self) -> bool;
}
