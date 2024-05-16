package utils

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
)

type CRVerifierCircuit struct {
	PublicInputs            []frontend.Variable               `gnark:",public"`
	Proof                   variables.Proof                   `gnark:"-"`
	VerifierOnlyCircuitData variables.VerifierOnlyCircuitData `gnark:"-"`

	OriginalPublicInputs []gl.Variable `gnark:"_"`

	// This is configuration for the circuit, it is a constant not a variable
	CommonCircuitData types.CommonCircuitData
}

func (c *CRVerifierCircuit) Define(api frontend.API) error {
	verifierChip := verifier.NewVerifierChip(api, c.CommonCircuitData)
	if len(c.PublicInputs) != 2 {
		panic("invalid public inputs, should contain 2 BLS12_381 elements")
	}
	if len(c.OriginalPublicInputs) != 8 {
		panic("invalid original public inputs, should contain 8 goldilocks elements")
	}

	two_to_63 := new(big.Int).SetUint64(1 << 63)

	blockStateHashAcc := frontend.Variable(0)
	sighashAcc := frontend.Variable(0)
	for i := 3; i >= 0; i-- {
		blockStateHashAcc = api.MulAcc(c.OriginalPublicInputs[i].Limb, blockStateHashAcc, two_to_63)
	}
	for i := 7; i >= 4; i-- {
		sighashAcc = api.MulAcc(c.OriginalPublicInputs[i].Limb, sighashAcc, two_to_63)
	}

	api.AssertIsEqual(c.PublicInputs[0], blockStateHashAcc)
	api.AssertIsEqual(c.PublicInputs[1], sighashAcc)

	verifierChip.Verify(c.Proof, c.OriginalPublicInputs, c.VerifierOnlyCircuitData)

	return nil
}

func NewCRVerifierCircuitFromFile(path string) (*CRVerifierCircuit, error) {

	if err := CheckPlonky2Path(path); err != nil {
		return nil, fmt.Errorf("plonky2 proof files not exist: %v", err)
	}

	commonCircuitData := types.ReadCommonCircuitData(path + COMMON_CIRCUIT_DATA_FILE)

	rawProofWithPis := types.ReadProofWithPublicInputs(path + PROOF_WITH_PUBLIC_INPUTS_FILE)
	proofWithPis := variables.DeserializeProofWithPublicInputs(rawProofWithPis)
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData(path + VERIFIER_ONLY_CIRCUIT_DATA_FILE))

	two_to_63 := new(big.Int).SetUint64(1 << 63)

	blockStateHashAcc := big.NewInt(0)
	sighashAcc := big.NewInt(0)
	for i := 3; i >= 0; i-- {
		blockStateHashAcc = new(big.Int).Mul(blockStateHashAcc, two_to_63)
		blockStateHashAcc = new(big.Int).Add(blockStateHashAcc, new(big.Int).SetUint64(rawProofWithPis.PublicInputs[i]))
	}
	for i := 7; i >= 4; i-- {
		sighashAcc = new(big.Int).Mul(sighashAcc, two_to_63)
		sighashAcc = new(big.Int).Add(sighashAcc, new(big.Int).SetUint64(rawProofWithPis.PublicInputs[i]))
	}
	blockStateHash := frontend.Variable(blockStateHashAcc)
	sighash := frontend.Variable(sighashAcc)

	circuit := CRVerifierCircuit{
		PublicInputs:            []frontend.Variable{blockStateHash, sighash},
		Proof:                   proofWithPis.Proof,
		OriginalPublicInputs:    proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	return &circuit, nil
}
