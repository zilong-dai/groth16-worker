package worker

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

type Groth16Prover struct {
	Path    string
	curveId ecc.ID
	pk      groth16.ProvingKey
	vk      groth16.VerifyingKey
	Proof   groth16.Proof
	Witness witness.Witness
	r1cs    constraint.ConstraintSystem
}

type Groth16Verifier struct {
	Path          string
	Vk            groth16.VerifyingKey
	Proof         groth16.Proof
	PublicWitness witness.Witness
}

type Groth16Worker struct {
	Path    string
	curveId ecc.ID
	Pk      groth16.ProvingKey
	Vk      groth16.VerifyingKey
	r1cs    constraint.ConstraintSystem
}
