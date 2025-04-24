#![cfg_attr(not(test), warn(unused_crate_dependencies))]

/// Client program input data types.
pub mod io;
#[macro_use]
pub mod utils;
pub mod custom;
pub mod error;
pub mod executor;
pub mod tracking;

mod into_primitives;
mod withdrawal_event_hash;

pub use into_primitives::{FromInput, IntoInput, IntoPrimitives};
pub use into_primitives::{BlockValidator, FromInput, IntoInput, IntoPrimitives};
