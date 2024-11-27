pub mod config;
pub mod proof;
use proof::{test_batch_proof, test_proof};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    test_proof()?;
    test_batch_proof(100)?;
    Ok(())
}
