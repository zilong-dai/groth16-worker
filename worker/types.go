package worker

import (
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

type Groth16Prover struct {
	Path          string
	pk            groth16.ProvingKey
	Proof         groth16.Proof
	PublicWitness witness.Witness
	r1cs          constraint.ConstraintSystem
}

type Groth16Verifier struct {
	Path          string
	Vk            groth16.VerifyingKey
	Proof         groth16.Proof
	PublicWitness witness.Witness
}
