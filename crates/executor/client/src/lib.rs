#![cfg_attr(not(test), warn(unused_crate_dependencies))]

/// Client program input data types.
pub mod io;
#[macro_use]
pub mod utils;
pub mod custom;
pub mod error;
mod events_hash;
pub mod executor;
#[cfg(feature = "nitro")]
pub mod nitro;
pub mod tracking;

mod into_primitives;

pub use into_primitives::{BlockValidator, FromInput, IntoInput, IntoPrimitives};
