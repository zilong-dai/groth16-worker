package cmd

import (
	"path/filepath"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/spf13/cobra"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
	"github.com/zilong-dai/gorth16-worker/utils"
)

var proveCmdDataDir string

func init() {
	proveCmd.Flags().StringVar(&proveCmdDataDir, "data", "", "")
}

var proveCmd = &cobra.Command{
	Use: "prove",
	Run: func(cmd *cobra.Command, args []string) {
		// Sanity check the required arguments have been provided.
		if proveCmdDataDir == "" {
			panic("--data is required")
		}

		// Read the R1CS.
		r1cs, err := utils.ReadCircuit(CURVE_ID, proveCmdDataDir+"/"+CIRCUIT_PATH)
		if err != nil {
			panic(err)
		}

		// Read the proving key.
		pk, err := utils.ReadProvingKey(CURVE_ID, proveCmdDataDir+"/"+PK_PATH)
		if err != nil {
			panic(err)
		}

		// Read the verifier key.
		vk, err := utils.ReadVerifyingKey(CURVE_ID, proveCmdDataDir+"/"+VK_PATH)
		if err != nil {
			panic(err)
		}

		// Read the file.
		if err := utils.CheckPlonky2Path(proveCmdDataDir); err != nil {
			panic("plonky2 data is missing")
		}
		// commonCircuitData := types.ReadCommonCircuitData(filepath.Join(proveCmdDataDir, COMMON_CIRCUIT_DATA_FILE))
		proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs(filepath.Join(proveCmdDataDir, PROOF_WITH_PUBLIC_INPUTS_FILE)))
		verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData(filepath.Join(proveCmdDataDir, VERIFIER_ONLY_CIRCUIT_DATA_FILE)))

		assignment := verifier.ExampleVerifierCircuit{
			Proof:                   proofWithPis.Proof,
			PublicInputs:            proofWithPis.PublicInputs,
			VerifierOnlyCircuitData: verifierOnlyCircuitData,
		}
		witness, err := frontend.NewWitness(&assignment, CURVE_ID.ScalarField())
		if err != nil {
			panic(err)
		}
		publicWitness, err := witness.Public()
		if err != nil {
			panic(err)
		}

		// Generate the proof.
		proof, err := groth16.Prove(r1cs, pk, witness)
		if err != nil {
			panic(err)
		}

		// Verify proof.
		err = groth16.Verify(proof, vk, publicWitness)
		if err != nil {
			panic(err)
		}

		// Serialize the proof to a file.
		if err := utils.WriteProof(proof, proveCmdDataDir+"/"+PROOF_PATH); err != nil {
			panic(err)
		}

		if err := utils.WritePublicInputs(publicWitness, proveCmdDataDir+"/"+WITNESS_PATH); err != nil {
			panic(err)
		}
	},
}
