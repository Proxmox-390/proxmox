#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![deny(unsafe_code)]

#[cfg(feature = "api-impl")]
pub mod api;

#[cfg(feature = "api-types")]
pub mod api_types;

#[cfg(any(feature = "api-impl", feature = "send-impl"))]
mod config;
#[cfg(any(feature = "api-impl", feature = "send-impl"))]
pub use config::{Config, ConfigEntity, PrivateConfigEntity};

#[cfg(any(feature = "api-impl", feature = "send-impl"))]
pub mod context;
#[cfg(any(feature = "api-impl", feature = "send-impl"))]
pub use context::{Context, ContextImpl};

#[cfg(feature = "send-impl")]
mod endpoints;

#[cfg(feature = "send-impl")]
mod renderer;

#[cfg(feature = "send-impl")]
mod send;
#[cfg(feature = "send-impl")]
pub use send::send;

mod error;
pub use error::Error;

mod notification;
pub use notification::*;
