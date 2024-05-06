package worker

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cf/gnark-plonky2-verifier/types"
	"github.com/cf/gnark-plonky2-verifier/variables"
	"github.com/cf/gnark-plonky2-verifier/verifier"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func NewGroth16Prover(Path string) (*Groth16Prover, error) {
	return &Groth16Prover{Path: Path}, nil
}

func (w *Groth16Prover) CheckPath() error {
	files := []string{
		"common_circuit_data.json",
		"proof_with_public_inputs.json",
		"verifier_only_circuit_data.json",
	}

	for _, file := range files {
		path := filepath.Join(w.Path, file)
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("path %s does not exist", path)
			} else {
				return fmt.Errorf("error checking path %s: %s", path, err)
			}
		}
	}

	return nil
}

func (w *Groth16Prover) Setup() error {
	if err := w.CheckPath(); err != nil {
		return fmt.Errorf("failed to check path: %w", err)
	}

	commonCircuitData := types.ReadCommonCircuitData(filepath.Join(w.Path, "common_circuit_data.json"))
	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs(filepath.Join(w.Path, "proof_with_public_inputs.json")))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData(filepath.Join(w.Path, "verifier_only_circuit_data.json")))

	circuit := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	builder := r1cs.NewBuilder

	r1cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), builder, &circuit)
	if err != nil {
		return fmt.Errorf("failed to compile circuit: %w", err)
	}
	w.r1cs = r1cs

	var errSetup error

	fmt.Println("Running circuit setup", time.Now())
	w.pk, _, errSetup = groth16.Setup(w.r1cs)

	if errSetup != nil {
		return fmt.Errorf("error in setting up circuit: %w", errSetup)
	}

	return nil
}

func (w *Groth16Prover) Prove() error {

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs(w.Path + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData(w.Path + "/verifier_only_circuit_data.json"))
	assignment := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
	}

	fmt.Println("Generating witness", time.Now())
	witness, err := frontend.NewWitness(&assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		return fmt.Errorf("error in generating witness: %s", err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		return fmt.Errorf("error in creating publicWitness: %s", err)
	}
	w.PublicWitness = publicWitness
	// if saveArtifacts {
	// 	fWitness, _ := os.Create("witness")
	// 	witness.WriteTo(fWitness)
	// 	fWitness.Close()
	// }

	fmt.Println("Creating proof", time.Now())
	proof, err := groth16.Prove(w.r1cs, w.pk, witness)
	if err != nil {
		return fmt.Errorf("error in creating proof: %s", err)
	}
	w.Proof = proof
	return nil
}

func (w *Groth16Prover) ReadProvingKey(keyPath string) error {
	if w.pk == nil {
		return fmt.Errorf("proving key is not initialized")
	}

	provingKeyFile, err := os.Open(keyPath)
	if err != nil {
		return fmt.Errorf("failed to open proving key file: %w", err)
	}
	defer provingKeyFile.Close()

	_, err = w.pk.ReadFrom(provingKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read proving key: %w", err)
	}

	return nil
}

func (w *Groth16Prover) WriteProvingKey(keyPath string) error {
	if w.pk == nil {
		return fmt.Errorf("proving key is not initialized")
	}

	fPK, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer fPK.Close()

	if _, err := w.pk.WriteTo(fPK); err != nil {
		return fmt.Errorf("failed to write verifying key to file: %w", err)
	}

	return nil
}

func (w *Groth16Prover) ReadProof(keyPath string) error {
	if w.Proof == nil {
		return fmt.Errorf("proof is not initialized")
	}

	proofFile, err := os.Open(keyPath)
	if err != nil {
		return fmt.Errorf("failed to open proof file: %w", err)
	}
	defer proofFile.Close()

	_, err = w.Proof.ReadFrom(proofFile)
	if err != nil {
		return fmt.Errorf("failed to read proof: %w", err)
	}

	return nil
}

func (w *Groth16Prover) WriteProof(keyPath string) error {
	if w.Proof == nil {
		return fmt.Errorf("verifier or proof is not initialized")
	}

	fVK, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer fVK.Close()

	if _, err := w.Proof.WriteTo(fVK); err != nil {
		return fmt.Errorf("failed to write proof to file: %w", err)
	}

	return nil
}
