use crate::Context;
use crate::Error;
use crate::Notification;

pub mod gotify;
pub mod sendmail;
pub mod smtp;
pub mod webhook;

mod common;

/// Notification endpoint trait, implemented by all endpoint plugins
pub(crate) trait Endpoint {
    /// Send a notification to this endpoint.
    fn send(&self, context: &Context, notification: &Notification) -> Result<(), Error>;

    /// The name/identifier for this endpoint
    fn name(&self) -> &str;

    /// Check if the endpoint is disabled
    fn disabled(&self) -> bool;
}
