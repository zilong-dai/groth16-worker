use std::{
    env,
    panic,
    path::PathBuf,
    process::{Command, Stdio},
};

pub (crate)const WORKER_PATH : &str = "./worker";
pub (crate)const EXE_PATH: &str = "./bin/local_worker.go";
/// A prover that can generate proofs with the Groth16 protocol using bindings to Gnark.
#[derive(Debug, Clone)]
pub struct Groth16Prover;

impl Groth16Prover {
    /// Creates a new [Groth16Prover].
    pub fn new() -> Self {
        Self
    }

    pub fn build(build_dir: &str) {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let gnark_dir = manifest_dir.join(WORKER_PATH);

        // Run the build script.
        Self::run_cmd(
            &gnark_dir,
            "build".to_string(),
            vec![
                "--data".to_string(),
                build_dir.to_string(),
            ],
        );
    }

    /// Generates a Groth16 proof by sending a request to the Gnark server.
    pub fn prove(&self, build_dir: &str) {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let gnark_dir = manifest_dir.join(WORKER_PATH);

        // Run the build script.
        Self::run_cmd(
            &gnark_dir,
            "prove".to_string(),
            vec![
                "--data".to_string(),
                build_dir.to_string(),
            ],
        );
    }

    pub fn verify(
        &self,
        build_dir: &str,
    ) {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let gnark_dir = manifest_dir.join(WORKER_PATH);

        // Run the build script.
        Self::run_cmd(
            &gnark_dir,
            "verify".to_string(),
            vec![
                "--data".to_string(),
                build_dir.to_string(),
            ],
        );
    }

    /// Runs the FFI command to interface with the Gnark library. Command is one of the commands
    /// defined in recursion/gnark/main.go.
    fn run_cmd(gnark_dir: &PathBuf, command: String, args: Vec<String>) {
        let mut command_args = vec!["run".to_string(), EXE_PATH.to_string(), command.clone()];

        command_args.extend(args);

        let result = Command::new("go")
            .args(command_args)
            .current_dir(gnark_dir)
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()
            .unwrap();

        if !result.status.success() {
            panic!(
                "failed to run script for {:?}: {:?}",
                command, result.status
            );
        }
    }
}

impl Default for Groth16Prover {
    fn default() -> Self {
        Self::new()
    }
}
