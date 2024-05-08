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

func NewGroth16Prover(Path string, curveId ecc.ID) (*Groth16Prover, error) {
	pk := groth16.NewProvingKey(curveId)
	vk := groth16.NewVerifyingKey(curveId)

	proof := groth16.NewProof(curveId)

	witness, err := witness.New(curveId.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("error creating public witness: %w", err)
	}
	r1cs := groth16.NewCS(curveId)
	// PublicWitness: publicWitness
	return &Groth16Prover{Path: Path, pk: pk, vk: vk, Proof: proof, Witness: witness, curveId: curveId, r1cs: r1cs}, nil
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

	r1cs, err := frontend.Compile(w.curveId.ScalarField(), builder, &circuit)
	if err != nil {
		return fmt.Errorf("failed to compile circuit: %w", err)
	}
	w.r1cs = r1cs

	var errSetup error

	w.pk, w.vk, errSetup = groth16.Setup(r1cs)

	if errSetup != nil {
		return fmt.Errorf("error in setting up circuit: %w", errSetup)
	}

	return nil
}

func (w *Groth16Prover) GenerateWitness() error {
	// https://github.com/Consensys/gnark/issues/1038
	// error in generating witness: can't set fr.Element from type expr.LinearExpression

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs(filepath.Join(w.Path, "proof_with_public_inputs.json")))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData(filepath.Join(w.Path, "verifier_only_circuit_data.json")))

	assignment := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
	}

	witness, err := frontend.NewWitness(&assignment, w.curveId.ScalarField())
	if err != nil {
		return fmt.Errorf("error in generating witness: %s", err)
	}

	w.Witness = witness

	return nil
}

func (w *Groth16Prover) GenerateR1CS() error {
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
	return nil
}

func (w *Groth16Prover) Prove() error {

	proof, err := groth16.Prove(w.r1cs, w.pk, w.Witness)
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

	if _, err := w.pk.WriteRawTo(fPK); err != nil {
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

	proofFile, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer proofFile.Close()

	if _, err := w.Proof.WriteTo(proofFile); err != nil {
		return fmt.Errorf("failed to write proof to file: %w", err)
	}

	return nil
}

// func (w *Groth16Prover) ReadPublicInputs(inputPath string) error {
// 	if w.Witness == nil {
// 		return fmt.Errorf("public inputs is not initialized")
// 	}

// 	publicinputsFile, err := os.Open(inputPath)
// 	if err != nil {
// 		return fmt.Errorf("failed to open public inputs file: %w", err)
// 	}
// 	defer publicinputsFile.Close()

// 	publicwitness, err := w.Witness.Public()

// 	_, err = publicwitness.ReadFrom(publicinputsFile)
// 	if err != nil {
// 		return fmt.Errorf("failed to read public inputs: %w", err)
// 	}

// 	return nil
// }

func (w *Groth16Prover) WritePublicInputs(inputPath string) error {
	if w.Witness == nil {
		return fmt.Errorf("public inputs is not initialized")
	}

	publicinputsFile, err := os.Create(inputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer publicinputsFile.Close()

	publicWitness, err := w.Witness.Public()
	if err != nil {
		return fmt.Errorf("failed to create publicWitness: %w", err)
	}

	if _, err := publicWitness.WriteTo(publicinputsFile); err != nil {
		return fmt.Errorf("failed to write proof to file: %w", err)
	}

	return nil
}

func (w *Groth16Prover) ReadVerifyingKey(keyPath string) error {
	if w.vk == nil {
		return fmt.Errorf("verifying key is not initialized")
	}

	verifyingKeyFile, err := os.Open(keyPath)
	if err != nil {
		return fmt.Errorf("failed to open verifying key file: %w", err)
	}
	defer verifyingKeyFile.Close()

	_, err = w.vk.ReadFrom(verifyingKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read verifying key: %w", err)
	}

	return nil
}

func (w *Groth16Prover) WriteVerifyingKey(keyPath string) error {
	if w.vk == nil {
		return fmt.Errorf("verifying key is not initialized")
	}

	fVK, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer fVK.Close()

	if _, err := w.vk.WriteTo(fVK); err != nil {
		return fmt.Errorf("failed to write verifying key to file: %w", err)
	}

	return nil
}

func (w *Groth16Prover) ReadCircuit(keyPath string) error {
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

func (w *Groth16Prover) WriteCircuit(keyPath string) error {
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
