package worker

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cf/gnark-plonky2-verifier/types"
	"github.com/cf/gnark-plonky2-verifier/variables"
	"github.com/cf/gnark-plonky2-verifier/verifier"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func NewGroth16Verifier(Path string, curveId ecc.ID) (*Groth16Verifier, error) {
	vk := groth16.NewVerifyingKey(curveId)

	proof := groth16.NewProof(curveId)

	publicWitness, err := witness.New(curveId.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("error creating public witness: %w", err)
	}
	return &Groth16Verifier{Path: Path, Vk: vk, Proof: proof, PublicWitness: publicWitness}, nil
}

func (w *Groth16Verifier) CheckPath() error {
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

func (w *Groth16Verifier) Setup() error {
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

	var errSetup error

	_, w.Vk, errSetup = groth16.Setup(r1cs)

	if errSetup != nil {
		return fmt.Errorf("error in setting up circuit: %w", errSetup)
	}

	return nil
}

func (w *Groth16Verifier) Verify() error {
	if w.Vk == nil || w.PublicWitness == nil || w.Proof == nil {
		return fmt.Errorf("Verifier keys, public witness, or proof are not set")
	}
	if err := groth16.Verify(w.Proof, w.Vk, w.PublicWitness); err != nil {
		return fmt.Errorf("error in verifying proof: %w", err)
	}
	return nil
}

func (w *Groth16Verifier) ReadVerifyingKey(keyPath string) error {
	if w.Vk == nil {
		return fmt.Errorf("verifying key is not initialized")
	}

	verifyingKeyFile, err := os.Open(keyPath)
	if err != nil {
		return fmt.Errorf("failed to open verifying key file: %w", err)
	}
	defer verifyingKeyFile.Close()

	_, err = w.Vk.ReadFrom(verifyingKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read verifying key: %w", err)
	}

	return nil
}

func (w *Groth16Verifier) WriteVerifyingKey(keyPath string) error {
	if w.Vk == nil {
		return fmt.Errorf("verifying key is not initialized")
	}

	fVK, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer fVK.Close()

	if _, err := w.Vk.WriteTo(fVK); err != nil {
		return fmt.Errorf("failed to write verifying key to file: %w", err)
	}

	return nil
}

func (w *Groth16Verifier) ReadProof(keyPath string) error {
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

func (w *Groth16Verifier) WriteProof(keyPath string) error {
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

func (w *Groth16Verifier) ReadPublicInputs(inputPath string) error {
	if w.PublicWitness == nil {
		return fmt.Errorf("public inputs is not initialized")
	}

	publicinputsFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open public inputs file: %w", err)
	}
	defer publicinputsFile.Close()

	_, err = w.PublicWitness.ReadFrom(publicinputsFile)
	if err != nil {
		return fmt.Errorf("failed to read public inputs: %w", err)
	}

	return nil
}

func (w *Groth16Verifier) WritePublicInputs(inputPath string) error {
	if w.PublicWitness == nil {
		return fmt.Errorf("public inputs is not initialized")
	}

	publicinputsFile, err := os.Create(inputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer publicinputsFile.Close()

	if _, err := w.PublicWitness.WriteTo(publicinputsFile); err != nil {
		return fmt.Errorf("failed to write proof to file: %w", err)
	}

	return nil
}
