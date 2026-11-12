#![forbid(unsafe_code)]

mod engine;
mod error;
mod messaging;
mod net;
pub mod tui;

pub use engine::{Client, PollReport, ReceivedEvent};
pub use error::{ClientError, Result};
