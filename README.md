## groth16-worker

reference: https://github.com/succinctlabs/sp1/tree/main/recursion/gnark

### Usage

```rust
// main.rs
use groth16_worker::Groth16Prover;

fn main(){
    // build dir must contain proof_with_public_inputs.json, verifier_only_circuit_data.json, common_circuit_data.json
    // build circuit, setup pk, vk, save pk, vk, circuit in data dir
    let build_dir = "./testdata";
    Groth16Prover::build(build_dir);

    // start proving, circuit, pk must exist in data dir
    let prover = Groth16Prover::new();
    prover.prove(build_dir);

    // start verifying, vk, proof, public_inputs must exist in data dir
    prover.verify(build_dir);
}
```

Cargo.toml
```txt
[dependencies]
groth16-worker = {git = "https://github.com/zilong-dai/groth16-worker", branch = "dev"}
```
