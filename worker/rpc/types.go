package rpc

import (
	"fmt"
	"log"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
	"github.com/zilong-dai/gorth16-worker/utils"
)

var COMMON_CIRCUIT_DATA_FILE = "common_circuit_data.json"
var PROOF_WITH_PUBLIC_INPUTS_FILE = "proof_with_public_inputs.json"
var VERIFIER_ONLY_CIRCUIT_DATA_FILE = "verifier_only_circuit_data.json"

var KEY_STORE_PATH string = "/tmp/groth16-keystore"
var CIRCUIT_FILE string = "circuit_groth16.bin"
var VK_FILE string = "vk_groth16.bin"
var PK_FILE string = "pk_groth16.bin"
var PROOF_FILE string = "proof_groth16.bin"
var WITNESS_FILE string = "witness_groth16.bin"

type WorkerService struct {
	worker *Groth16Prover
}

func NewWorkerService(curveId ecc.ID) (*WorkerService, error) {
	worker, err := NewProver(curveId)
	if err != nil {
		return nil, err
	}
	// create key store if not exists
	if _, err := os.Stat(filepath.Join(KEY_STORE_PATH)); os.IsNotExist(err) {
		if err := os.Mkdir(KEY_STORE_PATH, 0755); err != nil {
			return nil, err
		}
	}
	return &WorkerService{worker: worker}, nil
}

func (ws *WorkerService) Run(port int) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatal("listen error:", err)
	}

	rpc.RegisterName("WorkerService", ws)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("accept error:", err)
			continue
		}

		go rpc.ServeCodec(jsonrpc.NewServerCodec(conn))
	}

}

type Groth16Prover struct {
	pk      groth16.ProvingKey
	vk      groth16.VerifyingKey
	r1cs    constraint.ConstraintSystem
	md5     string
	curveId ecc.ID
}

func NewProver(curveId ecc.ID) (*Groth16Prover, error) {
	pk := groth16.NewProvingKey(curveId)

	vk := groth16.NewVerifyingKey(curveId)

	r1cs := groth16.NewCS(curveId)

	if pk == nil || vk == nil || r1cs == nil {
		return nil, fmt.Errorf("pk, vk or r1cs is null")
	}

	w := Groth16Prover{
		pk:      pk,
		vk:      vk,
		r1cs:    r1cs,
		md5:     "",
		curveId: curveId,
	}
	return &w, nil
}

func (w *Groth16Prover) Build(proofDataPath string) error {

	if proofDataPath == "" {
		return fmt.Errorf("--data is required")
	}

	if err := utils.CheckPlonky2Path(proofDataPath); err != nil {
		return fmt.Errorf("plonky2 proof files not exist: %v", err)
	}

	setupFlag := true

	md5String, err := utils.GetPlonky2PathMD5(proofDataPath)
	if err != nil {
		return fmt.Errorf("failed to get md5 of plonky2 path: %v", err)
	}
	flag := utils.CheckKeysExist(KEY_STORE_PATH)

	if md5String == w.md5 && flag {
		setupFlag = false
	}

	if setupFlag {
		commonCircuitData := types.ReadCommonCircuitData(filepath.Join(proofDataPath, COMMON_CIRCUIT_DATA_FILE))
		proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs(filepath.Join(proofDataPath, PROOF_WITH_PUBLIC_INPUTS_FILE)))
		verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData(filepath.Join(proofDataPath, VERIFIER_ONLY_CIRCUIT_DATA_FILE)))

		circuit := verifier.ExampleVerifierCircuit{
			Proof:                   proofWithPis.Proof,
			PublicInputs:            proofWithPis.PublicInputs,
			VerifierOnlyCircuitData: verifierOnlyCircuitData,
			CommonCircuitData:       commonCircuitData,
		}

		// Compile the circuit.
		r1cs, err := frontend.Compile(w.curveId.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			return fmt.Errorf("failed to compile circuit: %v", err)
		}

		// Perform the trusted setup.
		pk, vk, err := groth16.Setup(r1cs)
		if err != nil {
			return fmt.Errorf("failed to perform trusted setup: %v", err)
		}

		// Write the R1CS.
		if err := utils.WriteCircuit(r1cs, KEY_STORE_PATH+"/"+CIRCUIT_FILE); err != nil {
			return fmt.Errorf("failed to write r1cs to %s: %v", KEY_STORE_PATH+"/"+CIRCUIT_FILE, err)
		}

		// Write the verifier key.
		if err := utils.WriteVerifyingKey(vk, KEY_STORE_PATH+"/"+VK_FILE); err != nil {
			return fmt.Errorf("failed to write verifier key to %s: %v", KEY_STORE_PATH+"/"+VK_FILE, err)
		}

		// Write the proving key.
		if err := utils.WriteProvingKey(pk, KEY_STORE_PATH+"/"+PK_FILE); err != nil {
			return fmt.Errorf("failed to write proving key to %s: %v", KEY_STORE_PATH+"/"+PK_FILE, err)
		}
	}

	return nil
}

func (w *Groth16Prover) Prove(proofDataPath string) error {

	if proofDataPath == "" {
		return fmt.Errorf("--data is required")
	}

	if err := utils.CheckPlonky2Path(proofDataPath); err != nil {
		return fmt.Errorf("plonky2 proof files not exist")
	}

	if flag := utils.CheckKeysExist(KEY_STORE_PATH); !flag {
		return fmt.Errorf("keys not exist")
	}

	// Read the R1CS.
	r1cs, err := utils.ReadCircuit(w.curveId, proofDataPath+"/"+CIRCUIT_FILE)
	if err != nil {
		return fmt.Errorf("failed to read R1CS from %s: %v", proofDataPath+"/"+CIRCUIT_FILE, err)
	}

	// Read the proving key.
	pk, err := utils.ReadProvingKey(w.curveId, proofDataPath+"/"+PK_FILE)
	if err != nil {
		return fmt.Errorf("failed to read proving key from %s: %v", proofDataPath+"/"+PK_FILE, err)
	}

	// Read the verifier key.
	vk, err := utils.ReadVerifyingKey(w.curveId, proofDataPath+"/"+VK_FILE)
	if err != nil {
		return fmt.Errorf("failed to read verifier key from %s: %v", proofDataPath+"/"+VK_FILE, err)
	}

	// Read the file.
	// commonCircuitData := types.ReadCommonCircuitData(filepath.Join(proofDataPath, COMMON_CIRCUIT_DATA_FILE))
	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs(filepath.Join(proofDataPath, PROOF_WITH_PUBLIC_INPUTS_FILE)))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData(filepath.Join(proofDataPath, VERIFIER_ONLY_CIRCUIT_DATA_FILE)))

	assignment := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
	}
	witness, err := frontend.NewWitness(&assignment, w.curveId.ScalarField())
	if err != nil {
		return fmt.Errorf("failed to create witness: %v", err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		return fmt.Errorf("failed to get public witness: %v", err)
	}

	// Generate the proof.
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		return fmt.Errorf("failed to generate proof: %v", err)
	}

	// Verify proof.
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		return fmt.Errorf("failed to verify proof: %v", err)
	}

	// Serialize the proof to a file.
	if err := utils.WriteProof(proof, proofDataPath+"/"+PROOF_FILE); err != nil {
		return fmt.Errorf("failed to write proof to %s: %v", proofDataPath+"/"+PROOF_FILE, err)
	}

	if err := utils.WritePublicInputs(publicWitness, proofDataPath+"/"+WITNESS_FILE); err != nil {
		return fmt.Errorf("failed to write public inputs to %s: %v", proofDataPath+"/"+WITNESS_FILE, err)
	}
	return nil
}

func (w *Groth16Prover) Verify(proofDataPath string) error {

	if proofDataPath == "" {
		return fmt.Errorf("--data is required")
	}

	if flag := utils.CheckVKeysExist(KEY_STORE_PATH); !flag {
		return fmt.Errorf("keys not exist")
	}

	// Read the verifier key.
	vk, err := utils.ReadVerifyingKey(w.curveId, proofDataPath+"/"+VK_FILE)
	if err != nil {
		return fmt.Errorf("failed to read verifier key from %s: %v", proofDataPath+"/"+VK_FILE, err)
	}

	// Read the proof.
	proof, err := utils.ReadProof(w.curveId, proofDataPath+"/"+PROOF_FILE)
	if err != nil {
		return fmt.Errorf("proof is missing: %v", err)
	}

	// Read the public witness.
	publicWitness, err := utils.ReadPublicInputs(w.curveId, proofDataPath+"/"+WITNESS_FILE)
	if err != nil {
		return fmt.Errorf("public witness is missing: %v", err)
	}

	// Verify proof.
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		return fmt.Errorf("failed to verify proof: %v", err)
	}

	return nil
}
