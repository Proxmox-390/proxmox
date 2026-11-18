#![allow(dead_code)]

use std::borrow::Cow;

/// Boxed, type-erased error that can be sent and shared across threads.
pub type BoxedError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
/// Error type for `proxmox_notify`.
pub enum Error {
    /// The notification target with the given name does not exist.
    #[error("target '{0}' does not exist")]
    TargetDoesNotExist(String),

    /// A notification template could not be rendered.
    #[error("could not render notification template: {0}")]
    TemplateRendering(String),

    /// A notification template could not be loaded.
    #[error("could not load notification template: {0}")]
    TemplateCouldNotBeRead(#[source] BoxedError),

    /// The notification configuration is invalid.
    #[error("invalid configuration: {err}", err = print_optional_error(.message, .source))]
    InvalidConfig {
        /// Description of the error.
        message: String,
        /// Underlying error, if any.
        source: Option<BoxedError>,
    },

    /// An HTTP request to a notification endpoint failed.
    #[error("HTTP request failed: {0}")]
    HttpRequestFailed(#[source] BoxedError),

    /// Sending a mail via SMTP failed.
    #[error("SMTP request failed: {0}")]
    SmtpError(#[source] BoxedError),

    /// A notification passed to proxmox_notify is invalid.
    #[error("notification is invalid: {err}", err = print_optional_error(.message, .source))]
    InvalidNotification {
        /// Description of the error.
        message: String,
        /// Underlying error, if any.
        source: Option<BoxedError>,
    },

    /// A mail message to be forwarded could not be parsed or rebuilt.
    #[error("forwarded email message is invalid: {err}", err = print_optional_error(.message, .source))]
    InvalidForwardedMessage {
        /// Description of the error.
        message: String,
        /// Underlying error, if any.
        source: Option<BoxedError>,
    },

    /// The notification configuration could not be serialized.
    #[error("could not serialize config: {0}")]
    ConfigSerialization(#[source] BoxedError),

    /// The notification configuration could not be deserialized.
    #[error("could not deserialize config: {0}")]
    ConfigDeserialization(#[source] BoxedError),

    /// Any other error.
    #[error("{err}", err = print_optional_error(.message, .source))]
    Other {
        /// Description of the error.
        message: String,
        /// Underlying error, if any.
        source: Option<BoxedError>,
    },
}

fn print_optional_error<'a>(message: &'a str, err: &Option<BoxedError>) -> Cow<'a, str> {
    if let Some(err) = err {
        Cow::Owned(format!("{message}: {err}"))
    } else {
        Cow::Borrowed(message)
    }
}

impl Error {
    /// Create an [`Error::InvalidForwardedMessage`] without an underlying error.
    pub(crate) fn invalid_forwarded_message(s: impl Into<String>) -> Self {
        Self::InvalidForwardedMessage {
            message: s.into(),
            source: None,
        }
    }

    /// Create an [`Error::HttpRequestFailed`] from the given error.
    pub(crate) fn http_request_failed(err: impl Into<BoxedError>) -> Self {
        Self::HttpRequestFailed(err.into())
    }

    /// Create an [`Error::SmtpError`] from the given error.
    pub(crate) fn smtp_error(err: impl Into<BoxedError>) -> Self {
        Self::SmtpError(err.into())
    }

    /// Create an [`Error::InvalidForwardedMessage`] with an underlying error.
    pub(crate) fn invalid_forwarded_message_with_source(
        s: impl Into<String>,
        source: impl Into<BoxedError>,
    ) -> Self {
        Self::InvalidForwardedMessage {
            message: s.into(),
            source: Some(source.into()),
        }
    }

    /// Create an [`Error::TemplateCouldNotBeRead`] from the given error.
    pub(crate) fn template_could_not_be_read(err: impl Into<BoxedError>) -> Self {
        Self::TemplateCouldNotBeRead(err.into())
    }

    /// Create an [`Error::InvalidConfig`] without an underlying error.
    pub(crate) fn invalid_config(s: impl Into<String>) -> Self {
        Self::InvalidConfig {
            message: s.into(),
            source: None,
        }
    }

    /// Create an [`Error::InvalidConfig`] with an underlying error.
    pub(crate) fn invalid_config_with_source(
        s: impl Into<String>,
        source: impl Into<BoxedError>,
    ) -> Self {
        Self::InvalidConfig {
            message: s.into(),
            source: Some(source.into()),
        }
    }

    /// Create an [`Error::InvalidNotification`] without an underlying error.
    pub(crate) fn invalid_notification(s: impl Into<String>) -> Self {
        Self::InvalidNotification {
            message: s.into(),
            source: None,
        }
    }

    /// Create an [`Error::InvalidNotification`] with an underlying error.
    pub(crate) fn invalid_notification_with_source(
        s: impl Into<String>,
        source: impl Into<BoxedError>,
    ) -> Self {
        Self::InvalidNotification {
            message: s.into(),
            source: Some(source.into()),
        }
    }

    /// Create an [`Error::ConfigDeserialization`] from the given error.
    pub(crate) fn config_deserialization(err: impl Into<BoxedError>) -> Self {
        Self::ConfigDeserialization(err.into())
    }

    /// Create an [`Error::ConfigSerialization`] from the given error.
    pub(crate) fn config_serialization(err: impl Into<BoxedError>) -> Self {
        Self::ConfigSerialization(err.into())
    }

    /// Create an [`Error::TargetDoesNotExist`] for the given target name.
    pub(crate) fn target_does_not_exist(target: impl Into<String>) -> Self {
        Self::TargetDoesNotExist(target.into())
    }

    /// Create an [`Error::TemplateRendering`] with the given message.
    pub(crate) fn template_rendering(message: impl Into<String>) -> Self {
        Self::TemplateRendering(message.into())
    }

    /// Create an [`Error::Other`].
    pub(crate) fn other(s: impl Into<String>) -> Self {
        Self::Other {
            message: s.into(),
            source: None,
        }
    }

    /// Create an [`Error::Other`] with an underlying error.
    pub(crate) fn other_with_source(s: impl Into<String>, source: impl Into<BoxedError>) -> Self {
        Self::Other {
            message: s.into(),
            source: Some(source.into()),
        }
    }
}
