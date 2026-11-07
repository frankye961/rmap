//! Console reports and progress, kept separate from measured data and AI interpretation.

mod ai;
mod branding;
mod constants;
mod measured;
pub mod progress;

pub use ai::print_ai_analysis;
pub use branding::print_banner;
pub use measured::print_results;
