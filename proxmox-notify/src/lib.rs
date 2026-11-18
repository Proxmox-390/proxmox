#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![deny(unsafe_code)]

#[cfg(feature = "api-impl")]
pub mod api;

pub mod config;
pub mod context;
pub mod endpoints;
pub mod renderer;
pub mod schema;

#[cfg(feature = "send-impl")]
pub mod send;

#[cfg(feature = "api-types")]
pub mod api_types;

mod error;
pub use error::Error;

pub use config::Config;
pub use context::Context;
pub use context::ContextImpl;

mod notification;
pub use notification::*;
