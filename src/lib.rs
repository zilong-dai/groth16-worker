pub mod groth16;
pub use groth16::Groth16Prover;

#[cfg(test)]
mod tests {
    use super::groth16::{Groth16Prover, WORKER_PATH};

    #[test]
    fn test_build(){
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let gnark_dir = manifest_dir.join(WORKER_PATH);
        let binding = gnark_dir.join("./testdata");
        let build_dir = binding.to_str().expect("join build dir error");
        Groth16Prover::build(build_dir);
    }
    #[test]
    fn test_prove(){
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let gnark_dir = manifest_dir.join(WORKER_PATH);
        let binding = gnark_dir.join("./testdata");
        let build_dir = binding.to_str().expect("join build dir error");
        let prover = Groth16Prover::new();
        prover.prove(build_dir);
    }
    #[test]
    fn test_verify(){
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let gnark_dir = manifest_dir.join(WORKER_PATH);
        let binding = gnark_dir.join("./testdata");
        let build_dir = binding.to_str().expect("join build dir error");
        let prover = Groth16Prover::new();
        prover.verify(build_dir);
    }
}
