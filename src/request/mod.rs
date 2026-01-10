use crate::program::Program;

use self::prompt::Prompt;

pub mod openai;
pub mod prompt;

pub trait Handler {
    /// generate programs via a formatted prompt
    fn generate(&self, prompt: &Prompt) -> eyre::Result<Vec<Program>>;
}