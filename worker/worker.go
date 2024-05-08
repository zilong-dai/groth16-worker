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
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func NewGroth16Worker(Path string, curveId ecc.ID) (*Groth16Worker, error) {
	pk := groth16.NewProvingKey(curveId)

	vk := groth16.NewVerifyingKey(curveId)

	r1cs := groth16.NewCS(curveId)

	return &Groth16Worker{Path: Path, Pk: pk, Vk: vk, curveId: curveId, r1cs: r1cs}, nil
}

func (w *Groth16Worker) CheckPath() error {
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

func (w *Groth16Worker) Setup() error {
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

	r1cs, err := frontend.Compile(w.curveId.ScalarField(), builder, &circuit)
	if err != nil {
		return fmt.Errorf("failed to compile circuit: %w", err)
	}
	w.r1cs = r1cs

	var errSetup error

	w.Pk, w.Vk, errSetup = groth16.Setup(r1cs)

	if errSetup != nil {
		return fmt.Errorf("error in setting up circuit: %w", errSetup)
	}

	return nil
}

func (w *Groth16Worker) ReadProvingKey(keyPath string) error {
	if w.Pk == nil {
		return fmt.Errorf("proving key is not initialized")
	}

	provingKeyFile, err := os.Open(keyPath)
	if err != nil {
		return fmt.Errorf("failed to open proving key file: %w", err)
	}
	defer provingKeyFile.Close()

	_, err = w.Pk.ReadFrom(provingKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read proving key: %w", err)
	}

	return nil
}

func (w *Groth16Worker) WriteProvingKey(keyPath string) error {
	if w.Pk == nil {
		return fmt.Errorf("proving key is not initialized")
	}

	fPK, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer fPK.Close()

	if _, err := w.Pk.WriteRawTo(fPK); err != nil {
		return fmt.Errorf("failed to write verifying key to file: %w", err)
	}

	return nil
}

func (w *Groth16Worker) ReadVerifyingKey(keyPath string) error {
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

func (w *Groth16Worker) WriteVerifyingKey(keyPath string) error {
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

func (w *Groth16Worker) ReadCircuit(keyPath string) error {
	if w.r1cs == nil {
		return fmt.Errorf("r1cs is not initialized")
	}

	circuitFile, err := os.Open(keyPath)
	if err != nil {
		return fmt.Errorf("failed to open circuit file: %w", err)
	}
	defer circuitFile.Close()

	_, err = w.r1cs.ReadFrom(circuitFile)
	if err != nil {
		return fmt.Errorf("failed to read circuit: %w", err)
	}

	return nil
}

func (w *Groth16Worker) WriteCircuit(keyPath string) error {
	if w.r1cs == nil {
		return fmt.Errorf("r1cs is not initialized")
	}

	circuitFile, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to circuit file: %w", err)
	}
	defer circuitFile.Close()

	if _, err := w.r1cs.WriteTo(circuitFile); err != nil {
		return fmt.Errorf("failed to write circuit to file: %w", err)
	}

	return nil
}
