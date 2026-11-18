use std::fmt::Debug;
use std::ops::Deref;
use std::sync::Arc;

use crate::error::BoxedError;
use crate::renderer::TemplateSource;

#[cfg(any(feature = "pve-context", feature = "pbs-context"))]
pub mod common;
#[cfg(feature = "pbs-context")]
pub mod pbs;
#[cfg(feature = "pve-context")]
pub mod pve;
#[cfg(test)]
pub(crate) mod test;

/// Product-specific context.
///
/// This is a thin convenience wrapper around the actual [`ContextImpl`] trait object.
#[derive(Clone)]
pub struct Context(Arc<dyn ContextImpl>);

impl Context {
    /// Create notification context by wrapping the product-specific context
    /// implementation.
    pub fn new(context_impl: impl ContextImpl + 'static) -> Self {
        Self(Arc::new(context_impl))
    }
}

impl Deref for Context {
    type Target = dyn ContextImpl;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

// NOTE: Don't use proxmox_notify::Error in this trait, rather return a [`BoxedError`]. You
// may wrap the boxed error into an appropriate variant of proxmox_notify::Error at
// the callsite, but product-code (which includes the trait implementations of Context) should
// not have to instantiate proxmox_notify::Error themselves.

/// Product-specific context
pub trait ContextImpl: Send + Sync + Debug {
    /// Look up a user's email address from users.cfg
    fn lookup_email_for_user(&self, user: &str) -> Option<String>;
    /// Default mail author for mail-based targets
    fn default_sendmail_author(&self) -> String;
    /// Default from address for sendmail-based targets
    fn default_sendmail_from(&self) -> String;
    /// Proxy configuration for the current node
    fn http_proxy_config(&self) -> Option<String>;
    /// Return default config for built-in targets/matchers.
    fn default_config(&self) -> &'static str;
    /// Return the path of `filename` from `source` and a certain (optional) `namespace`
    fn lookup_template(
        &self,
        filename: &str,
        namespace: Option<&str>,
        source: TemplateSource,
    ) -> Result<Option<String>, BoxedError>;
}
