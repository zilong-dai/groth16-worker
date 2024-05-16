package rpc

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/zilong-dai/gorth16-worker/utils"
)

var COMMON_CIRCUIT_DATA_FILE = "common_circuit_data.json"
var PROOF_WITH_PUBLIC_INPUTS_FILE = "proof_with_public_inputs.json"
var VERIFIER_ONLY_CIRCUIT_DATA_FILE = "verifier_only_circuit_data.json"

var KEY_STORE_PATH string = "/tmp/groth16-keystore/"
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
	// w.init()
	return &w, nil
}

func (w *Groth16Prover) init() error {
	// check keystore is exist
	if _, err := os.Stat(KEY_STORE_PATH); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(KEY_STORE_PATH, os.ModePerm)
		}
	}

	// check pk, vk is exist
	if _, err := os.Stat(filepath.Join(KEY_STORE_PATH, PK_FILE)); err != nil {
		if os.IsNotExist(err) {
			panic("pk file not exist")
		} else {
			if w.pk, err = utils.ReadProvingKey(w.curveId, filepath.Join(KEY_STORE_PATH, PK_FILE)); err != nil {
				panic("reading pk failed")
			}
		}
	}

	if _, err := os.Stat(filepath.Join(KEY_STORE_PATH, VK_FILE)); err != nil {
		if os.IsNotExist(err) {
			panic("vk file not exist")
		} else {
			if w.vk, err = utils.ReadVerifyingKey(w.curveId, filepath.Join(KEY_STORE_PATH, VK_FILE)); err != nil {
				panic("reading vk failed")
			}
		}
	}

	return nil
}

type G16ProofWithPublicInputs struct {
	Proof        groth16.Proof
	PublicInputs witness.Witness
}

func NewG16ProofWithPublicInputs(curveId ecc.ID) *G16ProofWithPublicInputs {

	proof := groth16.NewProof(curveId)

	publicInputs, err := witness.New(curveId.ScalarField())
	if err != nil {
		panic(err)
	}

	return &G16ProofWithPublicInputs{
		Proof:        proof,
		PublicInputs: publicInputs,
	}

}

type G16VerifyingKey struct {
	VK groth16.VerifyingKey
}

func NewG16VerifyingKey(curveId ecc.ID) *G16VerifyingKey {
	vk := groth16.NewVerifyingKey(curveId)
	return &G16VerifyingKey{
		VK: vk,
	}
}
